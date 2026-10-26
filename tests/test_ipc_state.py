"""The guest network must never expose the QEMU host control endpoints."""
import copy
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from agenticvm.errors import AgenticVMError
from agenticvm.state import StateStore, qemu_socket_directory


class HostIpcStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = StateStore(Path(self.temporary.name))
        identifier = str(uuid4())
        name = "AgenticVM-" + identifier
        directory = qemu_socket_directory(identifier)
        self.state = {"schema": 1, "backend": "qemu", "uuid": identifier, "name": name,
                      "session": "default", "workspace": str(self.store.root), "profile": "desktop",
                      "run_dir": str(self.store.root / "vms" / name), "memory_mib": 768,
                      "network": "nat", "root_disk": str(self.store.root / "root.ext2"),
                      "display_width": 1024, "display_height": 768,
                      "pid": 42, "process_created": "123", "executable": str(self.store.root / "qemu.exe"),
                      "backend_sha256": "a" * 64, "iso": str(self.store.root / "boot.iso"),
                      "registered": True, "status": "running", "host_control_transport": "unix",
                      "socket_dir": str(directory), "serial_socket": str(directory / "s"), "qmp_socket": str(directory / "q")}

    def test_networked_guest_uses_only_owned_filesystem_endpoints(self):
        self.store.validate(self.state)
        for key, value in (("serial_socket", str(self.store.root / "other.sock")),
                           ("qmp_socket", self.state["serial_socket"]),
                           ("socket_dir", str(qemu_socket_directory(str(uuid4())))),
                           ("host_control_transport", "unknown"), ("serial_port", 43000)):
            state = {**self.state, key: value}
            with self.subTest(key=key), self.assertRaises(AgenticVMError) as caught:
                self.store.validate(state)
            self.assertEqual(caught.exception.code, "invalid_state")

    def legacy(self):
        state = copy.deepcopy(self.state)
        for key in ("host_control_transport", "socket_dir", "serial_socket", "qmp_socket"):
            state.pop(key)
        return {**state, "serial_host": "127.0.0.1", "serial_port": 43000, "qmp_port": 43001}

    def test_active_networked_legacy_tcp_is_refused(self):
        with self.assertRaises(AgenticVMError):
            self.store.validate(self.legacy())

    def test_offline_legacy_and_stopped_history_remain_readable(self):
        self.store.validate({**self.legacy(), "network": "none"})
        self.store.validate({**self.legacy(), "status": "stopped", "registered": False})


if __name__ == "__main__":
    unittest.main()
