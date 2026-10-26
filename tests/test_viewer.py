"""Real loopback HTTP checks with mocked VM/controller operations; no VM launch."""
from __future__ import annotations

import base64
import http.client
import json
from pathlib import Path
import subprocess
import sys
import shutil
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from agenticvm.viewer import MAX_BODY, MAX_FILE, ViewerController, ViewerError, ViewerServer
from agenticvm.state import qemu_socket_directory
from agenticvm.errors import AgenticVMError


class ViewerHttpTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agenticvm-viewer-test-")
        self.controller = ViewerController(Path(self.temporary.name))
        self.controller.cli = Mock(return_value={"ok": True, "result": {"status": "running"}})
        self.controller.screen = Mock(return_value=b"test-png-only")
        self.server = ViewerServer(self.controller, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def call(self, method, path, body=None, *, authenticated=True, origin=True, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        request_headers = {"Content-Type": "application/json"}
        if authenticated:
            request_headers["X-AgenticVM-Token"] = self.server.token
        if origin:
            request_headers["Origin"] = self.server.origin
        request_headers.update(headers or {})
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        data, response_headers = response.read(), dict(response.getheaders())
        result = json.loads(data) if "application/json" in response_headers.get("Content-Type", "") else data
        status = response.status
        connection.close()
        return status, result, response_headers

    def test_static_page_and_assets_have_browser_guards(self):
        status, body, headers = self.call("GET", "/", authenticated=False)
        self.assertEqual(status, 200)
        self.assertIn(b"AgenticVM", body)
        self.assertIn(b"Debian 13", body)
        self.assertNotIn(b'<option value="512">', body)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(self.call("GET", "/../viewer.py")[0], 404)
        self.assertEqual(self.call("GET", "/app.js")[0], 200)
        self.assertEqual(self.call("GET", "/style.css")[0], 200)
        for asset in ("/glass-ui.js", "/brand.png", "/icons/monitor.svg"):
            self.assertEqual(self.call("GET", asset, authenticated=False)[0], 200)
        for path in ("/icons/../viewer.py", "/icons/unknown.svg", "/icon-package.json"):
            self.assertEqual(self.call("GET", path)[0], 404)

    def test_api_and_screenshots_require_the_fragment_token(self):
        for path in ("/api/info", "/api/status", "/api/screen"):
            self.assertEqual(self.call("GET", path, authenticated=False)[0], 401)
        self.controller.cli.assert_not_called()
        self.controller.screen.assert_not_called()
        status, result, _ = self.call("GET", "/api/info")
        self.assertEqual(status, 200)
        self.assertEqual(result["result"]["workspace"], str(self.controller.workspace))
        self.assertEqual(result["result"]["os"], "Debian 13 · Xfce")
        self.assertEqual(result["result"]["browser"], "Firefox ESR")
        status, result, _ = self.call("GET", "/api/screen")
        self.assertEqual((status, result), (200, b"test-png-only"))

    def test_recovery_guard_checks_the_newly_selected_profile(self):
        self.controller.store.load=Mock(return_value=None)
        with patch('agenticvm.control_checkpoints.pending',side_effect=lambda controller:controller.profile=='android'):
            with self.assertRaises(ViewerError) as error:
                self.controller.action({'action':'start','profile':'android'})
        self.assertEqual(error.exception.code,'recovery_required')
        self.controller.cli.assert_not_called()

    def test_agent_target_mismatch_is_rejected_before_any_guest_operation(self):
        for headers in ({'X-AgenticVM-Profile':'windows'}, {'X-AgenticVM-Guest':str(uuid4())}):
            status, result, _ = self.call('POST', '/api/action', {'action':'key','keys':'enter'}, headers=headers)
            self.assertEqual(status, 409)
            self.assertEqual(result['error']['code'], 'target_changed')
            self.assertEqual(self.call('GET','/api/screen',headers=headers)[0], 409)
        self.controller.cli.assert_not_called()
        self.controller.screen.assert_not_called()

    def test_other_origins_and_rebound_hosts_cannot_control_the_vm(self):
        for headers, origin in (({"Origin": "https://example.com"}, True), ({}, False), ({"Host": "evil.example"}, True)):
            status, result, _ = self.call("POST", "/api/action", {"action": "stop"}, headers=headers, origin=origin)
            self.assertEqual(status, 403, result)
        self.controller.cli.assert_not_called()
        self.assertEqual(self.call("OPTIONS", "/api/action")[0], 405)

    def test_start_is_one_explicit_bounded_qemu_desktop_command(self):
        status, _, _ = self.call("POST", "/api/action", {"action": "start", "memory": 768, "network": True, "persistent": True})
        self.assertEqual(status, 200)
        self.controller.cli.assert_called_once_with(["start", "--profile", "desktop", "--memory", "768", "--network", "--persistent"])
        self.assertEqual(self.call("POST", "/api/action", {"action": "start", "memory": 16385})[0], 400)
        self.assertEqual(self.call("POST", "/api/action", {"action": "start", "memory": 512})[0], 400)
        self.assertEqual(self.call("POST", "/api/action", {"action": "start", "network": "true"})[0], 400)

    def test_terminal_text_only_reaches_the_linux_shell_argv(self):
        command = 'printf "$HOME"; echo host-string-does-not-run'
        self.assertEqual(self.call("POST", "/api/action", {"action": "exec", "command": command})[0], 200)
        self.controller.cli.assert_called_once_with(["exec", "--timeout-ms", "30000", "--", "/bin/sh", "-c", command])
        self.assertEqual(self.call("POST", "/api/action", {"action": "powershell", "command": "whoami"})[0], 400)

    def test_coordinates_url_text_and_envelope_limits_are_checked(self):
        for request in ({"action": "click", "x": -1, "y": 0}, {"action": "move", "x": True, "y": 1},
                        {"action": "scroll", "steps": 0}, {"action": "type", "text": "x" * 4097},
                        {"action": "open-url", "url": "file:///etc/passwd"},
                        {"action": "open-url", "url": "https://user:password@example.org"}):
            self.assertEqual(self.call("POST", "/api/action", request)[0], 400)
        status, _, _ = self.call("POST", "/api/action", b"{}", headers={"Content-Length": str(MAX_BODY + 1)})
        self.assertEqual(status, 413)
        self.assertEqual(self.call("POST", "/api/action", b"[]")[0], 400)
        self.assertEqual(self.call("POST", "/api/action", b"not json")[0], 400)
        self.controller.cli.assert_not_called()

    def test_busy_control_does_not_overlap_screenshots_or_mutations(self):
        with self.controller.lock:
            self.assertEqual(self.call("GET", "/api/screen")[0], 409)
            self.assertEqual(self.call("POST", "/api/action", {"action": "stop"})[0], 409)
            self.assertEqual(self.call("GET", "/api/info")[0], 200)
        self.controller.cli.assert_not_called()
        self.controller.screen.assert_not_called()

    def test_lifecycle_busy_is_a_conflict_and_not_a_bad_request(self):
        self.controller.status = Mock(side_effect=AgenticVMError('Lifecycle busy', 'session_busy'))
        status, response, _ = self.call('GET', '/api/status')
        self.assertEqual(status,409)
        self.assertEqual(response['error']['code'],'session_busy')

    def test_new_control_route_retains_authentication_and_typed_dispatch(self):
        status,_,_=self.call('POST','/api/control',{'operation':'capabilities'},authenticated=False)
        self.assertEqual(status,401)
        status,response,_=self.call('POST','/api/control',{'operation':'capabilities','vm':'linux'})
        self.assertEqual(status,200)
        self.assertEqual(response['result']['command_shell'],'sh')
        self.assertEqual(self.call('POST','/api/control',{'operation':'host-exec'})[0],400)
        self.controller.cli.assert_not_called()

    def test_windows_metadata_names_the_correct_guest(self):
        self.controller.select_profile('windows')
        self.assertIn('Windows',self.controller.info()['os'])

    def test_startup_failure_is_visible_after_background_start(self):
        self.controller.cli.return_value = {"ok": False, "error": {"code": "insufficient_host_memory", "message": "Free more memory before starting Linux."}}
        self.call("POST", "/api/action", {"action": "start"})
        self.controller.cli.return_value = {"ok": True, "result": {"status": "stopped"}}
        status, response, _ = self.call("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(response["result"]["startup_error"]["code"], "insufficient_host_memory")

    def test_upload_is_limited_and_uses_a_temporary_host_source(self):
        observed = []
        def copy_check(args):
            self.assertEqual(args[:2], ["put", "--"])
            source = Path(args[2])
            self.assertEqual(source.read_bytes(), b"\x00\xfftest")
            self.assertEqual(args[3], "/workspace/test.bin")
            observed.append(source)
            return {"ok": True, "result": {"bytes": 6}}
        self.controller.cli.side_effect = copy_check
        payload = base64.b64encode(b"\x00\xfftest").decode()
        self.assertEqual(self.call("POST", "/api/action", {"action": "upload", "path": "/workspace/test.bin", "data_b64": payload})[0], 200)
        self.assertFalse(observed[0].exists())
        self.assertEqual(self.call("POST", "/api/action", {"action": "upload", "path": "test", "data_b64": "???"})[0], 400)
        too_large = base64.b64encode(b"x" * (MAX_FILE + 1)).decode()
        self.assertEqual(self.call("POST", "/api/action", {"action": "upload", "path": "test", "data_b64": too_large})[0], 413)

    def test_download_never_interprets_a_guest_path_as_a_host_path(self):
        observed = []
        def copy_check(args):
            self.assertEqual(args[:3], ["get", "--", "/workspace/report.txt"])
            destination = Path(args[3])
            self.assertEqual(destination.name, "download.bin")
            destination.write_bytes(b"guest file")
            observed.append(destination)
            return {"ok": True, "result": {}}
        self.controller.cli.side_effect = copy_check
        status, body, headers = self.call("GET", "/api/download?path=%2Fworkspace%2Freport.txt")
        self.assertEqual((status, body), (200, b"guest file"))
        self.assertIn("report.txt", headers["Content-Disposition"])
        self.assertFalse(observed[0].exists())


class ViewerInvocationTests(unittest.TestCase):
    def test_controller_never_uses_a_host_shell_and_pins_the_workspace(self):
        with tempfile.TemporaryDirectory() as folder:
            controller = ViewerController(Path(folder), "demo")
            result = subprocess.CompletedProcess([], 0, stdout=b'{"ok":true,"result":{}}', stderr=b"")
            with patch("agenticvm.viewer.subprocess.run", return_value=result) as run:
                controller.action({"action": "exec", "command": "$(host-command); $HOME"})
            args, kwargs = run.call_args
            self.assertEqual(args[0][:3], [sys.executable, "-m", "agenticvm"])
            self.assertEqual(args[0][3:9], ["--workspace", str(Path(folder).resolve()), "--session", "demo", "--backend", "qemu"])
            self.assertEqual(args[0][-3:], ["/bin/sh", "-c", "$(host-command); $HOME"])
            self.assertIs(kwargs["shell"], False)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 180)

    def test_typed_text_beginning_with_a_flag_is_literal(self):
        with tempfile.TemporaryDirectory() as folder:
            controller = ViewerController(Path(folder))
            controller.cli = Mock(return_value={"ok": True, "result": {}})
            controller.action({"action": "type", "text": "--help"})
            controller.cli.assert_called_once_with(["type", "--", "--help"])


class ViewerSavedSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.controller = ViewerController(self.root)
        self.controller.cli = Mock(return_value={"ok": True, "result": {"status": "stopped"}})

    def save_session(self, *, memory=1024, network=False, persistent=False):
        identifier = str(uuid4())
        name = "AgenticVM-" + identifier
        sockets = qemu_socket_directory(identifier)
        saved = {"schema": 1, "backend": "qemu", "profile": "desktop", "session": "default",
                 "workspace": str(self.root.resolve()), "uuid": identifier, "name": name,
                 "run_dir": str(self.root / "vms" / name), "memory_mib": memory,
                 "root_disk": str(self.root / "rootfs.ext2"),
                 "workspace_disk": str(self.root / "data/default.ext2") if persistent else None,
                 "iso": str(self.root / "desktop.iso"), "display_width": 1024, "display_height": 768,
                 "network": "nat" if network else "none", "pid": 0, "process_created": "0",
                 "executable": str(self.root / "qemu.exe"), "backend_sha256": "f" * 64,
                 "host_control_transport": "unix", "socket_dir": str(sockets),
                 "serial_socket": str(sockets / "s"), "qmp_socket": str(sockets / "q"),
                 "registered": False, "status": "stopped"}
        self.controller.store.save(saved)
        return saved

    def test_stopped_autostart_preserves_offline_memory_and_ephemeral_choices_without_rewriting_state(self):
        self.save_session()
        before = self.controller.store.path.read_bytes()
        self.controller.start_if_needed()
        self.assertEqual(self.controller.cli.call_args_list,
                         [unittest.mock.call(["status"]), unittest.mock.call(["start", "--profile", "desktop", "--memory", "1024"])])
        self.assertEqual(self.controller.store.path.read_bytes(), before)
        self.assertFalse((self.root / "data").exists())

    def test_new_tab_status_exposes_saved_choices(self):
        self.save_session(memory=768, network=False, persistent=False)
        self.assertEqual(self.controller.status()["result"]["settings"], {"memory": 768, "cpus": 1, "width": 1024, "height": 768, "network": False, "persistent": False})

    def test_explicit_start_changes_override_saved_defaults_and_keep_omitted_choices(self):
        self.save_session(memory=1024, network=False, persistent=True)
        self.controller.action({"action": "start", "memory": 768})
        self.controller.cli.assert_called_once_with(["start", "--profile", "desktop", "--memory", "768", "--persistent"])

    def test_fresh_session_uses_initial_recommended_defaults(self):
        self.controller.cli.side_effect = [{"ok": False, "error": {"code": "no_session"}}, {"ok": True, "result": {}}]
        self.controller.start_if_needed()
        self.assertEqual(self.controller.cli.call_args_list[-1],
                         unittest.mock.call(["start", "--profile", "desktop", "--memory", "768", "--network", "--persistent"]))

    def test_experimental_cli_memory_resumes_at_the_next_supported_viewer_size(self):
        for memory, expected in ((512, 768), (900, 1024)):
            with self.subTest(memory=memory):
                self.save_session(memory=memory)
                self.controller.cli.reset_mock()
                self.controller.action({"action": "start"})
                self.controller.cli.assert_called_once_with(["start", "--profile", "desktop", "--memory", str(expected)])
        self.controller.cli.reset_mock()
        with self.assertRaises(ViewerError):
            self.controller.action({"action": "start", "memory": 512})
        self.controller.cli.assert_not_called()

    def test_invalid_saved_metadata_is_not_replaced_with_fresh_defaults(self):
        saved = self.save_session()
        saved["workspace"] = str(self.root / "unrelated")
        self.controller.store.path.write_text(json.dumps(saved))
        before = self.controller.store.path.read_bytes()
        self.controller.cli.return_value = {"ok": False, "error": {"code": "invalid_state"}}
        self.controller.start_if_needed()
        self.controller.cli.assert_called_once_with(["status"])
        self.assertEqual(self.controller.start_error["code"], "invalid_state")
        self.assertEqual(self.controller.store.path.read_bytes(), before)

    def test_running_desktop_is_reused_without_starting_another_session(self):
        self.controller.cli.return_value = {"ok": True, "result": {"status": "running"}}
        self.controller.start_if_needed()
        self.controller.cli.assert_called_once_with(["status"])


class ViewerFrontendSettingsTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node is used only for frontend development checks")
    def test_initial_settings_and_pending_user_edits_in_the_actual_frontend(self):
        script = Path(__file__).with_name("viewer-settings.mjs")
        result = subprocess.run([shutil.which("node"), str(script)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("settings checks passed", result.stdout)

    @unittest.skipUnless(shutil.which("node"), "Node is used only for frontend development checks")
    def test_download_waits_for_frames_and_actions_and_never_reports_a_failed_transfer_as_success(self):
        script = Path(__file__).with_name("viewer-download.mjs")
        result = subprocess.run([shutil.which("node"), str(script)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("download queue checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
