"""Private QEMU socket ownership, failure cleanup and transport boundaries."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from agenticvm.errors import AgenticVMError
from agenticvm.qemu import QemuBackend, _cleanup_socket_directory, _prepare_socket_directory, qmp_endpoint, qmp_sequence
from agenticvm.state import StateStore, qemu_socket_directory


class PrivateQemuSocketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        temporary = patch("agenticvm.state.tempfile.gettempdir", return_value=str(self.root))
        temporary.start()
        self.addCleanup(temporary.stop)
        self.identifier = str(uuid4())

    def state(self):
        directory = _prepare_socket_directory(self.identifier)
        return {"uuid": self.identifier, "host_control_transport": "unix", "socket_dir": str(directory),
                "serial_socket": str(directory / "s"), "qmp_socket": str(directory / "q")}

    def test_cleanup_removes_only_exited_sessions_exact_leaves_and_keeps_unknown_files(self):
        state = self.state()
        directory = Path(state["socket_dir"])
        for name in ("s", "q", "keep"):
            (directory / name).write_text(name)
        self.assertFalse(_cleanup_socket_directory(state))
        self.assertEqual(list(directory.iterdir()), [directory / "keep"])
        self.assertEqual((directory / "keep").read_text(), "keep")
        (directory / "keep").unlink()
        self.assertTrue(_cleanup_socket_directory(state))
        self.assertFalse(directory.exists())

    def test_cleanup_refuses_forged_directory_and_never_recurses_into_a_leaf(self):
        state = self.state()
        directory = Path(state["socket_dir"])
        (directory / "s").mkdir()
        (directory / "s/important").write_text("retained")
        self.assertFalse(_cleanup_socket_directory(state))
        self.assertEqual((directory / "s/important").read_text(), "retained")
        state["qmp_socket"] = str(self.root / "unrelated")
        with self.assertRaises(AgenticVMError) as caught:
            _cleanup_socket_directory(state)
        self.assertEqual(caught.exception.code, "invalid_state")

    def test_overlong_paths_fail_before_creating_directory_or_tcp_fallback(self):
        long_temp = self.root / ("x" * 108)
        with patch("agenticvm.state.tempfile.gettempdir", return_value=str(long_temp)):
            with self.assertRaises(AgenticVMError) as caught:
                _prepare_socket_directory(self.identifier)
        self.assertEqual(caught.exception.code, "invalid_endpoint")
        self.assertFalse(long_temp.exists())
        with patch("agenticvm.qemu.SocketTransport") as local, patch("agenticvm.qemu.TcpTransport") as tcp:
            for endpoint in (False, "relative", self.root / ("x" * 108)):
                with self.assertRaises(AgenticVMError):
                    qmp_sequence(endpoint, [("query-status", {})])
        local.assert_not_called()
        tcp.assert_not_called()

    def test_legacy_networked_state_cannot_select_tcp_monitor(self):
        self.assertEqual(qmp_endpoint({"network": "none", "qmp_port": 41002}), 41002)
        with self.assertRaises(AgenticVMError) as caught:
            qmp_endpoint({"network": "nat", "qmp_port": 41002})
        self.assertEqual(caught.exception.code, "invalid_state")

    def test_failed_spawn_reaps_only_its_new_socket_directory_and_records_failure(self):
        store = StateStore(self.root / "owned", "failed")
        executable, iso = self.root / "qemu.exe", self.root / "agent.iso"
        executable.write_bytes(b"fixture")
        iso.write_bytes(b"fixture")
        backend = QemuBackend(store, executable)
        with patch.object(backend, "doctor", return_value={"whpx": {"available": True}, "sha256": "a" * 64, "version": "fixture"}), \
             patch("agenticvm.qemu.check_memory_budget", return_value={}), \
             patch("agenticvm.qemu.uuid4", return_value=self.identifier), \
             patch("agenticvm.qemu.subprocess.Popen", side_effect=OSError("injected spawn failure")):
            with self.assertRaises(OSError):
                backend.start(iso)
        self.assertFalse(qemu_socket_directory(self.identifier).exists())
        saved = store.load()
        self.assertEqual(saved["status"], "failed")
        self.assertFalse(saved["registered"])
        self.assertTrue(saved["socket_cleanup"])


if __name__ == "__main__":
    unittest.main()
