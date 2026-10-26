"""Meaningful host-side protocol, ownership and lifecycle regression checks."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agenticvm.backend import VERIFIED_VERSION, VirtualBoxBackend, parse_machine_info
from agenticvm.cli import _save_download, _snapshot, main
from agenticvm.errors import AgenticVMError, GuestError
from agenticvm.protocol import GuestClient, decode_data
from agenticvm.qemu import QemuBackend, WindowsProcess, qmp_call
from agenticvm.state import StateStore
from agenticvm.transport import FramedTransport


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.vm = {}
        self.failure = None
        self.unowned = False

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        op, args = command[1], command[2:]
        if self.failure == op:
            return subprocess.CompletedProcess(command, 1, "", "injected failure")
        text = ""
        if op == "--version":
            text = VERIFIED_VERSION + "\n"
        elif op == "createvm":
            values = {args[index]: args[index + 1] for index in range(0, len(args) - 1, 2)}
            name = values["--name"]
            self.vm = {"UUID": values["--uuid"], "name": name, "VMState": "poweroff",
                       "CfgFile": str(Path(values["--basefolder"]) / name / f"{name}.vbox")}
        elif op == "showvminfo":
            values = {**self.vm, "name": "Unrelated VM"} if self.unowned else self.vm
            text = "\n".join(f'{key}="{value}"' for key, value in values.items())
        elif op == "startvm":
            self.vm["VMState"] = "running"
        elif op == "controlvm":
            self.vm["VMState"] = "poweroff"
        elif op == "unregistervm":
            self.vm = {}
        return subprocess.CompletedProcess(command, 0, text, "")


class ReplyTransport:
    def __init__(self, response):
        self.response = response
        self.frames = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def write(self, data, timeout):
        request = json.loads(data)
        self.frames = self.response(request)

    def readline(self, timeout, limit):
        if not self.frames:
            raise AgenticVMError("timeout", "guest_timeout")
        return self.frames.pop(0)


class ChunkTransport(FramedTransport):
    def __init__(self, chunks):
        super().__init__()
        self.chunks = iter(chunks)

    def read(self, size, timeout):
        return next(self.chunks, b"")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "private", "test")
        self.iso = self.root / "guest.iso"
        self.iso.write_bytes(b"fixture")
        self.exe = self.root / "VBoxManage.exe"
        self.exe.write_bytes(b"binary fixture")
        digest = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.patch = patch("agenticvm.backend.VERIFIED_VBOXMANAGE_SHA256", digest)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        memory_patch = patch("agenticvm.backend.check_memory_budget", return_value={"available_physical_mib": 2048})
        memory_patch.start()
        self.addCleanup(memory_patch.stop)
        self.runner = FakeRunner()
        self.backend = VirtualBoxBackend(self.store, self.exe, runner=self.runner, process_probe=lambda: [])

    def test_start_stop_controls_only_owned_uuid_and_keeps_files(self):
        state = self.backend.start(self.iso)
        self.assertEqual(self.backend.status()["vm_state"], "running")
        self.assertEqual(state["memory_mib"], 512)
        calls = [item[0] for item in self.runner.calls]
        modify = next(command for command in calls if command[1] == "modifyvm")
        self.assertEqual(modify[modify.index("--uart-mode1") + 1], "server")
        self.assertEqual(modify[modify.index("--uart2") + 1:modify.index("--uart2") + 3], ["0x2f8", "3"])
        self.assertEqual(modify[modify.index("--uart-mode2") + 1:modify.index("--uart-mode2") + 3], ["file", state["boot_log"]])
        self.assertEqual(modify[modify.index("--nic1") + 1], "none")
        self.assertEqual(modify[modify.index("--usb-ohci") + 1], "off")
        for command, options in self.runner.calls:
            self.assertIs(options["shell"], False)
            self.assertEqual(options["env"]["VBOX_USER_HOME"], str(self.store.root / "vbox-user"))
        stopped = self.backend.stop()
        self.assertTrue(stopped["vm_files_retained"])
        self.assertEqual(self.store.load()["registered"], False)
        self.assertEqual(self.backend.status()["status"], "stopped")
        self.assertFalse(any("--delete" in command for command, _ in self.runner.calls))
        mutations = [command for command, _ in self.runner.calls if command[1] in {"controlvm", "unregistervm"}]
        self.assertTrue(all(command[2] == state["uuid"] for command in mutations))

    def test_unrelated_vm_cannot_be_stopped(self):
        self.backend.start(self.iso)
        self.runner.unowned = True
        before = len(self.runner.calls)
        with self.assertRaises(AgenticVMError) as caught:
            self.backend.stop()
        self.assertEqual(caught.exception.code, "ownership_mismatch")
        self.assertFalse(any(command[1] in {"controlvm", "unregistervm"} for command, _ in self.runner.calls[before:]))

    def test_metadata_path_escape_is_rejected_before_control(self):
        self.backend.start(self.iso)
        data = self.store.load()
        data["config_file"] = str(self.root / "unrelated.vbox")
        self.store.path.write_text(json.dumps(data))
        before = len(self.runner.calls)
        with self.assertRaises(AgenticVMError) as caught:
            self.backend.stop()
        self.assertEqual(caught.exception.code, "invalid_state")
        self.assertEqual(len(self.runner.calls), before)

    def test_existing_vbox_process_blocks_initial_creation(self):
        self.backend.process_probe = lambda: [{"name": "VBoxSVC.exe", "pid": "23"}]
        with self.assertRaises(AgenticVMError) as caught:
            self.backend.start(self.iso)
        self.assertEqual(caught.exception.code, "virtualbox_busy")
        self.assertEqual(self.runner.calls, [])

    def test_failed_configuration_rolls_back_only_owned_registration(self):
        self.runner.failure = "modifyvm"
        with self.assertRaises(AgenticVMError):
            self.backend.start(self.iso)
        data = self.store.load()
        self.assertEqual(data["status"], "failed")
        self.assertFalse(data["registered"])
        self.assertTrue(any(command[1] == "unregistervm" for command, _ in self.runner.calls))

    def test_overlapping_lifecycle_operations_are_refused(self):
        another = StateStore(self.store.root, "other")
        with self.store.lock():
            with self.assertRaises(AgenticVMError) as caught:
                with another.lock():
                    pass
        self.assertEqual(caught.exception.code, "session_busy")

    def test_new_session_after_stop_gets_fresh_uuid(self):
        first = self.backend.start(self.iso)["uuid"]
        self.backend.stop()
        second = self.backend.start(self.iso)["uuid"]
        self.assertNotEqual(first, second)


class ProtocolTests(unittest.TestCase):
    def test_fragmented_lines_preserve_the_next_frame(self):
        transport = ChunkTransport([b'{"a":', b'1}\n{"b":2}\n'])
        self.assertEqual(transport.readline(1, 32), b'{"a":1}')
        self.assertEqual(transport.readline(1, 32), b'{"b":2}')

    def test_oversized_unterminated_frame_is_rejected(self):
        transport = ChunkTransport([b"x" * 32])
        with self.assertRaises(AgenticVMError) as caught:
            transport.readline(1, 32)
        self.assertEqual(caught.exception.code, "protocol_error")

    def test_request_correlation_ignores_startup_and_stale_frames(self):
        def response(request):
            return [b"boot line", b'{"v":1,"id":"old","ok":true,"result":{}}',
                    json.dumps({"v": 1, "id": request["id"], "ok": True, "result": {"protocol": 1}}).encode()]
        transport = ReplyTransport(response)
        self.assertEqual(GuestClient(lambda _: transport).call("ping"), {"protocol": 1})
        self.assertTrue(transport.closed)

    def test_guest_failure_keeps_error_code(self):
        transport = ReplyTransport(lambda request: [json.dumps({"v": 1, "id": request["id"], "ok": False,
                                                               "error": {"code": "outside_workspace", "message": "denied"}}).encode()])
        with self.assertRaises(GuestError) as caught:
            GuestClient(lambda _: transport).call("read_file", path="../../etc/passwd")
        self.assertEqual(caught.exception.code, "outside_workspace")

    def test_readiness_fails_immediately_when_vm_has_exited(self):
        from unittest.mock import Mock
        factory = Mock()
        with self.assertRaises(AgenticVMError) as caught:
            GuestClient(factory).ready(90, is_running=lambda: False)
        self.assertEqual(caught.exception.code, "guest_boot_failed")
        factory.assert_not_called()

    def test_malformed_matching_envelope_is_rejected(self):
        transport = ReplyTransport(lambda request: [json.dumps({"v": 1, "id": request["id"], "ok": "yes", "result": {}}).encode()])
        with self.assertRaises(AgenticVMError) as caught:
            GuestClient(lambda _: transport).call("ping")
        self.assertEqual(caught.exception.code, "protocol_error")

    def test_base64_is_strict_and_bounded(self):
        self.assertEqual(decode_data("AAH/", 3), b"\0\1\xff")
        for value in ("!", "YWJjZA==", None):
            with self.assertRaises(AgenticVMError):
                decode_data(value, 3)

    def test_snapshot_keeps_binary_and_adds_readable_text(self):
        encoded = base64.b64encode(b"hello\xff").decode()
        snapshot = _snapshot({"stdout_b64": encoded, "stderr_b64": "", "state": "exited"})
        self.assertEqual(snapshot["stdout_b64"], encoded)
        self.assertEqual(snapshot["stdout"], "hello\ufffd")

    def test_download_refuses_accidental_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "result"
            _save_download(target, b"first", False)
            with self.assertRaises(AgenticVMError):
                _save_download(target, b"second", False)
            self.assertEqual(target.read_bytes(), b"first")
            _save_download(target, b"second", True)
            self.assertEqual(target.read_bytes(), b"second")

    def test_cli_error_is_one_json_envelope(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(["--workspace", temp, "exec", "--", "uname"])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "no_session")

    def test_completed_exec_keeps_nonzero_guest_exit_status_and_releases_job(self):
        import contextlib
        import io
        from unittest.mock import Mock
        client = Mock()
        client.call.side_effect = [{"job_id": "test-job"}, {"state": "exited", "exit_code": 200,
                                  "signal": 0, "stdout_b64": "", "stderr_b64": ""}, {}]
        with tempfile.TemporaryDirectory() as temp, patch("agenticvm.cli._client", return_value=client), contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(["--workspace", temp, "exec", "--", "sh", "-c", "exit 200"])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 200)
        self.assertTrue(result["ok"])
        self.assertFalse(result["result"]["retained"])
        self.assertEqual(client.call.call_args.args, ("forget",))
        self.assertEqual(client.call.call_args.kwargs["job_id"], "test-job")

    def test_start_readiness_failure_stops_the_new_session_and_preserves_error(self):
        import contextlib
        import io
        from unittest.mock import Mock
        backend = Mock()
        backend.start.return_value = {"uuid": "new-uuid", "memory_mib": 512}
        backend.stop.return_value = {"status": "stopped"}
        client = Mock()
        client.ready.side_effect = AgenticVMError("guest timed out", "guest_not_ready")
        with tempfile.TemporaryDirectory() as temp, \
             patch("agenticvm.cli.QemuBackend", return_value=backend), \
             patch("agenticvm.cli.find_qemu", return_value=Path(temp) / "qemu.exe"), \
             patch("agenticvm.cli._client", return_value=client), \
             patch.object(StateStore, "load", return_value={"uuid": "new-uuid"}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(["--workspace", temp, "start"])
        response = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(response["error"]["code"], "guest_not_ready")
        self.assertTrue(response["error"]["details"]["startup_cleanup"]["ok"])
        backend.stop.assert_called_once()

    def test_stale_start_does_not_stop_a_replacement_session(self):
        from agenticvm.cli import _startup_cleanup
        from unittest.mock import Mock
        backend = Mock()
        with tempfile.TemporaryDirectory() as temp:
            store = StateStore(Path(temp))
            with patch.object(store, "load", return_value={"uuid": "replacement-uuid"}):
                result = _startup_cleanup(store, backend, "original-uuid")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "ownership_mismatch")
        backend.stop.assert_not_called()


class QemuTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        ipc_temp = patch("agenticvm.state.tempfile.gettempdir", return_value=str(self.root))
        ipc_temp.start()
        self.addCleanup(ipc_temp.stop)
        self.store = StateStore(self.root / "private", "qemu-test")
        self.exe = self.root / "qemu-system-x86_64.exe"
        self.exe.write_bytes(b"fixture")
        self.iso = self.root / "linux.iso"
        self.iso.write_bytes(b"fixture")
        self.backend = QemuBackend(self.store, self.exe)

    def _start(self):
        executable = self.exe

        class Process:
            def __init__(self, pid, **kwargs):
                self.handle, self.created, self.executable = 1, "123456789", executable
            def __enter__(self): return self
            def __exit__(self, *_): self.close()
            def alive(self): return True
            def wait(self, seconds): return True
            def close(self): self.handle = None
            def terminate(self): raise AssertionError("unexpected termination")

        class Child:
            pid = 4321
            def poll(self): return None

        from types import SimpleNamespace
        with patch.object(self.backend, "doctor", return_value={"version": "QEMU fixture", "sha256": "a" * 64, "whpx": {"available": True}}), \
             patch("agenticvm.qemu.os", SimpleNamespace(name="nt")), \
             patch("agenticvm.qemu.check_memory_budget", return_value={"available_physical_mib": 2048}), \
             patch("agenticvm.qemu.WindowsProcess", Process), \
             patch("agenticvm.qemu.qmp_call", return_value={"status": "running"}), \
             patch("agenticvm.qemu.subprocess.CREATE_NO_WINDOW", 0, create=True), \
             patch("agenticvm.qemu.subprocess.CREATE_NEW_PROCESS_GROUP", 0, create=True), \
             patch("agenticvm.qemu.subprocess.Popen", return_value=Child()) as launch:
            state = self.backend.start(self.iso)
        return state, launch.call_args.args[0], Process

    def test_unavailable_or_missing_hypervisor_capability_refuses_launch(self):
        for capabilities in ({"available": False}, {}):
            with self.subTest(capabilities=capabilities), \
                 patch.object(self.backend, "doctor", return_value={"whpx": capabilities}), \
                 patch("agenticvm.qemu.check_memory_budget", return_value={}), \
                 patch("agenticvm.qemu.subprocess.Popen") as launch:
                with self.assertRaises(AgenticVMError) as caught:
                    self.backend.start(self.iso)
                self.assertEqual(caught.exception.code, "whpx_unavailable")
                launch.assert_not_called()

    def test_qemu_profile_is_whpx_only_and_uses_no_guest_network_or_disk(self):
        state, command, _ = self._start()
        self.assertEqual(command[command.index("-accel") + 1], "whpx")
        self.assertEqual(command[command.index("-nic") + 1], "none")
        self.assertEqual(command[command.index("-smp") + 1], "1")
        self.assertIn("-nodefaults", command)
        self.assertIn("virtio-serial-pci,id=agentbus", command)
        self.assertIn("virtserialport,bus=agentbus.0,nr=1,chardev=agent,name=org.agenticvm.agent", command)
        self.assertIn("isa-serial,index=1,chardev=boot", command)
        self.assertEqual(Path(state["boot_log"]), Path(state["run_dir"]) / "boot.log")
        self.assertNotIn("-serial", command)
        self.assertNotIn("-drive", command)
        self.assertFalse(any("tcg" in item.lower() for item in command))
        self.assertEqual(state["pid"], 4321)
        self.assertEqual(state["process_created"], "123456789")
        self.assertEqual(state["control_transport"], "virtio-serial")
        self.assertEqual(self.store.load()["backend"], "qemu")

    def test_qemu_stop_requires_saved_process_creation_time(self):
        state, _, Process = self._start()
        state["process_created"] = "987654321"
        self.store.save(state)
        with patch("agenticvm.qemu.WindowsProcess", Process), patch("agenticvm.qemu.qmp_call") as monitor:
            with self.assertRaises(AgenticVMError) as caught:
                self.backend.stop()
        self.assertEqual(caught.exception.code, "ownership_mismatch")
        monitor.assert_not_called()

    def test_qemu_stop_uses_qmp_quit_and_retains_its_logs(self):
        state, _, Process = self._start()
        with patch("agenticvm.qemu.WindowsProcess", Process), patch("agenticvm.qemu.qmp_call", return_value={}) as monitor:
            result = self.backend.stop()
        monitor.assert_called_once_with(Path(state["qmp_socket"]), "quit")
        self.assertTrue(result["socket_cleanup"])
        self.assertFalse(Path(state["socket_dir"]).exists())
        self.assertTrue(result["vm_files_retained"])
        self.assertFalse(self.store.load()["registered"])
        self.assertTrue((Path(state["run_dir"]) / "launch.json").is_file())

    def test_qmp_negotiates_and_ignores_events(self):
        import socket
        import threading
        failures = []
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            try:
                with server, server.accept()[0] as connection:
                    connection.settimeout(3)
                    stream = connection.makefile("rwb", buffering=0)
                    stream.write(b'{"QMP":{"version":{}}}\r\n')
                    for expected in ("qmp_capabilities", "query-status"):
                        request = json.loads(stream.readline())
                        if request["execute"] != expected:
                            raise AssertionError(request)
                        stream.write(b'{"event":"RESUME"}\r\n')
                        result = {"status": "running"} if expected == "query-status" else {}
                        stream.write(json.dumps({"id": request["id"], "return": result}).encode() + b"\r\n")
                    stream.close()
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertEqual(qmp_call(port, "query-status"), {"status": "running"})
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])

    @unittest.skipUnless(__import__("os").name == "nt", "Windows process API")
    def test_process_exit_during_image_query_is_treated_as_exited(self):
        from unittest.mock import Mock
        api = Mock()
        api.OpenProcess.return_value = 7
        # Alive after OpenProcess, then exited when the image query fails.
        api.WaitForSingleObject.side_effect = [258, 0, 0]

        def times(handle, created, exited, kernel, user):
            created._obj.dwLowDateTime = 123
            return True

        api.GetProcessTimes.side_effect = times
        api.QueryFullProcessImageNameW.return_value = False
        with patch("ctypes.WinDLL", return_value=api):
            with WindowsProcess(4321, terminate=True) as process:
                self.assertFalse(process.alive())
                self.assertIsNone(process.executable)
        api.TerminateProcess.assert_not_called()
        api.CloseHandle.assert_called_once_with(7)


if __name__ == "__main__":
    unittest.main()
