"""Headless agent isolation, identity and endpoint ownership boundaries."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from agenticvm.cli import parser
from agenticvm.errors import AgenticVMError
from agenticvm.qemu import QemuBackend, _cleanup_socket_directory, _prepare_socket_directory, prepare_pair_directory, cleanup_pair_directory
from agenticvm.state import StateStore, qemu_socket_directory, validate_isolated_link, validate_serial_link


class AgentProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.temp_patch = patch("agenticvm.state.tempfile.gettempdir", return_value=str(self.root))
        self.temp_patch.start()
        self.addCleanup(self.temp_patch.stop)
        self.store = StateStore(self.root / "owned")
        self.identifier = str(uuid4())
        self.pair = str(uuid4())
        directory = qemu_socket_directory(self.identifier)
        name = "AgenticVM-" + self.identifier
        self.state = {"schema": 1, "backend": "qemu", "session": "default", "workspace": str(self.store.root),
                      "uuid": self.identifier, "name": name, "profile": "agent", "memory_mib": 256,
                      "network": "isolated", "isolated_link": {"pair_uuid": self.pair, "role": "listen", "capture": True},
                      "root_disk": str(self.root / "root.ext2"), "display_width": 1024, "display_height": 768,
                      "run_dir": str(self.store.root / "vms" / name), "iso": str(self.root / "peer.iso"),
                      "packet_capture": str(self.store.root / "vms" / name / "peer.pcap"),
                      "host_control_transport": "unix", "socket_dir": str(directory),
                      "serial_socket": str(directory / "s"), "qmp_socket": str(directory / "q"),
                      "peer_channel": True, "peer_socket": str(directory / "c"),
                      "pid": 42, "process_created": "123", "executable": str(self.root / "qemu.exe"),
                      "backend_sha256": "a" * 64, "registered": True, "status": "running"}

    def test_agent_metadata_rejects_nat_unowned_channels_capture_and_browser_state(self):
        self.store.validate(self.state)
        for changes in ({"network": "nat"}, {"peer_socket": str(self.root / "other")},
                        {"peer_channel": 1}, {"packet_capture": str(self.root / "unrelated.pcap")},
                        {"browser_job_id": "4"}, {"isolated_link": {"pair_uuid": self.pair, "role": "bridge"}},
                        {"isolated_link": {"pair_uuid": self.pair, "role": "listen", "host": "127.0.0.1"}}):
            with self.subTest(changes=changes), self.assertRaises(AgenticVMError) as caught:
                self.store.validate({**self.state, **changes})
            self.assertEqual(caught.exception.code, "invalid_state")

    def test_serial_peer_cleanup_never_removes_shared_fabric(self):
        directory = _prepare_socket_directory(self.identifier)
        pair_directory = prepare_pair_directory(self.pair)
        for name in ("s", "q", "c"):
            (directory / name).write_bytes(b"owned")
        (pair_directory / "n").write_bytes(b"shared")
        (pair_directory / "b").write_bytes(b"serial shared")
        self.assertTrue(_cleanup_socket_directory(self.state))
        self.assertEqual((pair_directory / "n").read_bytes(), b"shared")
        self.assertEqual((pair_directory / "b").read_bytes(), b"serial shared")
        (pair_directory / "keep").write_bytes(b"retain")
        self.assertFalse(cleanup_pair_directory(self.pair))
        self.assertEqual((pair_directory / "keep").read_bytes(), b"retain")
        (pair_directory / "keep").unlink()
        self.assertTrue(cleanup_pair_directory(self.pair))

    def test_failed_spawn_records_only_private_pair_stream_without_nat_host_tcp_or_usb(self):
        executable, iso, root_disk = self.root / "qemu.exe", self.root / "peer.iso", self.root / "root.ext2"
        for file in (executable, iso, root_disk):
            file.write_bytes(b"fixture")
        pair_dir = prepare_pair_directory(self.pair)
        backend = QemuBackend(self.store, executable)
        with patch.object(backend, "doctor", return_value={"whpx": {"available": True}, "sha256": "a" * 64, "version": "fixture"}), \
             patch("agenticvm.qemu.check_memory_budget", return_value={}), \
             patch("agenticvm.qemu.uuid4", return_value=self.identifier), \
             patch("agenticvm.qemu.subprocess.Popen", side_effect=OSError("injected failure")) as spawn:
            with self.assertRaises(OSError):
                backend.start(iso, 256, profile="agent", root_disk=root_disk, peer_channel=True,
                              isolated_link={"pair_uuid": self.pair, "role": "listen", "capture": True})
        command = spawn.call_args.args[0]
        self.assertIn("stream,id=peernet,addr.type=unix,addr.path=" + str(pair_dir / "n") + ",server=on", command)
        self.assertIn("name=opt/agenticvm/peer-role,string=listen", command)
        self.assertIn("virtserialport,bus=agentbus.0,nr=2,chardev=peer,name=org.agenticvm.peer", command)
        self.assertFalse(any("hostfwd" in item or "user,id=" in item or "usb-" in item or "tcp:" in item for item in command))
        self.assertTrue(pair_dir.is_dir())
        self.assertFalse(qemu_socket_directory(self.identifier).exists())
        saved = self.store.load()
        self.assertEqual(saved["profile"], "agent")
        self.assertFalse(saved["registered"])
        self.assertTrue(saved["socket_cleanup"])
        self.assertTrue(cleanup_pair_directory(self.pair))

    def test_agent_cli_has_explicit_peer_settings(self):
        args = parser().parse_args(["start", "--profile", "agent", "--peer-channel", "--pair", self.pair,
                                    "--peer-role", "connect", "--peer-capture"])
        self.assertEqual(args.profile, "agent")
        self.assertTrue(args.peer_channel)
        self.assertTrue(args.peer_capture)
        self.assertEqual(args.peer_role, "connect")

    def test_serial_pair_metadata_cannot_enable_network_or_host_peer_port(self):
        state = copy.deepcopy(self.state)
        for key in ("isolated_link", "packet_capture", "peer_channel", "peer_socket"):
            state.pop(key)
        state.update(network="none", serial_link={"pair_uuid": self.pair, "role": "listen"})
        self.store.validate(state)
        for changes in ({"network": "nat"}, {"peer_channel": True},
                        {"serial_link": {"pair_uuid": self.pair, "role": "listen", "capture": True}},
                        {"serial_link": {"pair_uuid": self.pair, "role": "listen", "path": "arbitrary"}}):
            with self.subTest(changes=changes), self.assertRaises(AgenticVMError):
                self.store.validate({**state, **changes})

    def test_serial_pair_launch_has_no_ethernet_or_ip_stack_connection(self):
        executable, iso, root_disk = self.root / "qemu.exe", self.root / "peer.iso", self.root / "root.ext2"
        for file in (executable, iso, root_disk):
            file.write_bytes(b"fixture")
        pair_dir = prepare_pair_directory(self.pair)
        backend = QemuBackend(self.store, executable)
        with patch.object(backend, "doctor", return_value={"whpx": {"available": True}, "sha256": "a" * 64, "version": "fixture"}), \
             patch("agenticvm.qemu.check_memory_budget", return_value={}), \
             patch("agenticvm.qemu.uuid4", return_value=self.identifier), \
             patch("agenticvm.qemu.subprocess.Popen", side_effect=OSError("injected failure")) as spawn:
            with self.assertRaises(OSError):
                backend.start(iso, 256, profile="agent", root_disk=root_disk,
                              serial_link={"pair_uuid": self.pair, "role": "listen"})
        command = spawn.call_args.args[0]
        self.assertIn("socket,id=peer,path=" + str(pair_dir / "b") + ",server=on,wait=off", command)
        self.assertIn("-nic", command)
        self.assertEqual(command[command.index("-nic") + 1], "none")
        self.assertFalse(any("netdev" in item or "e1000" in item or "peer-role" in item for item in command))
        self.assertNotIn("peer_socket", self.store.load())
        self.assertTrue(cleanup_pair_directory(self.pair))

    def test_pair_configuration_is_strict_and_never_accepts_arbitrary_endpoints(self):
        self.assertEqual(validate_isolated_link({"pair_uuid": self.pair, "role": "connect"}),
                         {"pair_uuid": self.pair, "role": "connect"})
        for link in ({"pair_uuid": self.pair.upper(), "role": "listen"},
                     {"pair_uuid": self.pair, "role": []},
                     {"pair_uuid": self.pair, "role": "connect", "capture": 1},
                     {"pair_uuid": self.pair, "role": "listen", "path": str(self.root / "other")}):
            with self.subTest(link=link), self.assertRaises(AgenticVMError):
                validate_isolated_link(link)


if __name__ == "__main__":
    unittest.main()
