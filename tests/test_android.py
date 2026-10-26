"""Host-side Android security and resource regression checks (no VM launched)."""
import contextlib
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from agenticvm import android
from agenticvm.errors import AgenticVMError


class AndroidTests(unittest.TestCase):
    def test_root_transport_restart_is_retried_but_uid_is_required(self):
        backend = android.AndroidBackend(None)
        closed = subprocess.CompletedProcess([], 1, b"", b"closed")
        root = subprocess.CompletedProcess([], 0, b"0\n", b"")
        with patch.object(backend, "adb", return_value=closed), patch.object(backend, "shell", side_effect=[closed, root]), patch.object(android.time, "sleep"):
            backend.set_shell_identity({"adb_serial": "127.0.0.1:5555"}, root=True)

    def test_root_readiness_never_accepts_shell_uid(self):
        backend = android.AndroidBackend(None)
        shell = subprocess.CompletedProcess([], 0, b"2000\n", b"")
        with patch.object(backend, "adb", return_value=shell), patch.object(backend, "shell", return_value=shell), patch.object(android.time, "monotonic", side_effect=[0, 0, 31]), patch.object(android.time, "sleep"), self.assertRaises(AgenticVMError) as error:
            backend.set_shell_identity({"adb_serial": "127.0.0.1:5555"}, root=True)
        self.assertEqual(error.exception.code, "android_network_guard")

    def test_guest_path_boundary(self):
        self.assertEqual(android.guest_path("/workspace/a.bin"), "/data/local/tmp/agenticvm/a.bin")
        self.assertEqual(android.guest_path("a.bin"), "/data/local/tmp/agenticvm/a.bin")
        for bad in ("../x", "/workspace/../x", "/workspace-other/x", "/etc/passwd", "a\\b", "a\x00b"):
            with self.subTest(bad=bad), self.assertRaises(AgenticVMError):
                android.guest_path(bad)

    def test_literal_shell_argv_is_quoted(self):
        backend = android.AndroidBackend(None)
        values = ["printf", "%s", "$(touch /tmp/x); ' $` \n next"]
        with patch.object(backend, "adb", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as adb:
            backend.shell({}, values)
        arguments = adb.call_args.args
        self.assertEqual(arguments[1:3], ("shell", "-T"))
        self.assertEqual(shlex.split(arguments[3]), values)

    def test_shell_rejects_nul_and_empty_command(self):
        backend = android.AndroidBackend(None)
        for argv in ([], ["x\x00y"], ["a"] * 65):
            with self.assertRaises(AgenticVMError):
                backend.shell({}, argv)

    def test_capture_is_bounded_while_both_streams_are_drained(self):
        result = android.run([sys.executable, "-I", "-B", "-c", "import sys;sys.stdout.write('x'*1000000);sys.stderr.write('y'*1000000)"], output_limit=5000)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout), 5001)
        self.assertEqual(len(result.stderr), 5001)

    def test_deadline_kills_only_spawned_client(self):
        with self.assertRaises(AgenticVMError) as error:
            android.run([sys.executable, "-I", "-B", "-c", "import time;time.sleep(10)"], timeout=0.1)
        self.assertEqual(error.exception.code, "android_timeout")

    def test_unread_stdin_cannot_defeat_client_deadline(self):
        with self.assertRaises(AgenticVMError) as error:
            android.run([sys.executable, "-I", "-B", "-c", "import time;time.sleep(10)"], input=b"x" * 1024 * 1024, timeout=0.1)
        self.assertEqual(error.exception.code, "android_timeout")

    def test_invalid_guest_memory_is_rejected_before_any_campaign_or_process(self):
        with patch.object(android, "campaign_idle", side_effect=AssertionError("must not acquire campaign")):
            for value in (0, 1024, 1536, True, 8193):
                with self.subTest(value=value), self.assertRaises(AgenticVMError) as error:
                    android.AndroidBackend(None).start(memory=value)
                self.assertEqual(error.exception.code, "invalid_limits")

    def test_modified_control_apk_is_denied_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            control = folder / "control"
            control.mkdir()
            (control / "control.apk").write_bytes(b"modified")
            (control / "receipt.json").write_text(json.dumps({"apk_sha256": hashlib.sha256(b"original").hexdigest(), "sources": {}}))
            with patch.object(android, "SDK", folder / "sdk"), self.assertRaises(AgenticVMError) as error:
                android.verify_helper()
            self.assertEqual(error.exception.code, "android_integrity")

    def test_mismatched_creation_time_never_yields_process(self):
        class Process:
            created = "different"
            executable = Path("C:/expected.exe").resolve()
            def __init__(self, *args, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def alive(self): return True
        with patch.object(android, "WindowsProcess", Process), self.assertRaises(AgenticVMError) as error:
            with android.owned_process({"pid": 999, "created": "recorded", "executable": "C:/expected.exe"}, terminate=True):
                self.fail("Ownership mismatch must not yield a control handle")
        self.assertEqual(error.exception.code, "ownership_mismatch")

    def test_manifest_rejects_escape_and_foreign_process(self):
        with tempfile.TemporaryDirectory() as folder:
            store = android.AndroidStore(Path(folder))
            identifier = str(uuid4())
            run_dir = store.root / "vms" / ("AgenticVM-" + identifier)
            state = dict(schema=1, backend="android", profile="android", session="default", uuid=identifier,
                         name="AgenticVM-" + identifier, workspace=str(store.root), run_dir=str(run_dir),
                         registered=False, status="creating", memory_mib=2560, network="none", persistent=False,
                         avd_name="AgenticVM_" + identifier.replace("-", ""), data_dir=str(run_dir / "data"),
                         avd_home=str(run_dir / "avd"), adb_serial="127.0.0.1:5555", console_port=5554,
                         adb_server_port=30000, processes=[])
            store.validate(state)
            for key, value in (("data_dir", str(store.root.parent)), ("console_port", 5555), ("memory_mib", True),
                               ("launcher", dict(pid=1, created="123", executable="C:/Windows/notepad.exe")),
                               ("processes", [dict(pid=1, created="123", executable="C:/Windows/notepad.exe")])):
                with self.subTest(key=key), self.assertRaises(AgenticVMError):
                    store.validate({**state, key: value})

    def test_linux_state_keeps_original_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(AgenticVMError):
                android.AndroidStore(Path(folder)).validate({"backend": "qemu"})


if __name__ == "__main__":
    unittest.main()
