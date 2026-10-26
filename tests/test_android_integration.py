"""Android routing and viewer boundaries alongside the existing Linux surface."""
from argparse import Namespace
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from agenticvm.cli import parser, execute
from agenticvm.errors import AgenticVMError
from agenticvm.mcp import Bridge, TOOLS
from agenticvm.viewer import ViewerController, ViewerServer


class RecordingBridge(Bridge):
    def __init__(self):
        super().__init__(Namespace(workspace=Path("unused"), session="default", backend="qemu", image=None, profile="android"))
        self.commands = []
    def cli(self, *argv):
        self.commands.append(argv)
        return {"ok": True, "result": {}}, 0


class AndroidIntegrationTests(unittest.TestCase):
    def test_parser_routes_android_without_changing_linux_defaults(self):
        self.assertEqual(parser().parse_args(["start"]).profile, "command")
        self.assertEqual(parser().parse_args(["start", "--profile", "android"]).profile, "android")
        self.assertEqual(parser().parse_args(["install-apk", "x.apk"]).apk, Path("x.apk"))
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(AgenticVMError) as error:
                execute(parser().parse_args(["--workspace", folder, "install-apk", "x.apk"]))
            self.assertEqual(error.exception.code, "android_required")

    def test_android_mcp_defaults_and_touch_bounds(self):
        bridge = RecordingBridge()
        bridge.call("vm_start", {})
        self.assertIn("android", bridge.commands[0])
        self.assertIn(2560, bridge.commands[0])
        self.assertIn(240, bridge.commands[0])
        bridge.call("vm_click", {"x": 719, "y": 1279})
        bridge.call("vm_install_apk", {"path": "owned.apk"})
        bridge.call("vm_launch_app", {"component": "org.example/.Main"})
        bridge.call("vm_swipe", {"x1": 50, "y1": 1000, "x2": 50, "y2": 100})
        self.assertEqual(bridge.commands[2], ("install-apk", "--", "owned.apk"))
        with self.assertRaises(ValueError):
            bridge.call("vm_swipe", {"x1": 720, "y1": 1000, "x2": 50, "y2": 100})
        self.assertTrue({"vm_install_apk", "vm_launch_app", "vm_swipe"} <= {t["name"] for t in TOOLS})

    def test_viewer_profiles_keep_separate_session_and_workspace_data(self):
        with tempfile.TemporaryDirectory() as folder:
            viewer = ViewerController(Path(folder))
            linux_path = viewer.store.path
            viewer.cli = Mock(return_value={"ok": True, "result": {"status": "ready"}})
            result = viewer.action({"action": "start", "profile": "android", "memory": 2560})
            self.assertTrue(result["ok"])
            self.assertNotEqual(linux_path, viewer.store.path)
            self.assertEqual(viewer.session, "default-android")
            self.assertIn("240", viewer.cli.call_args.args[0])
            self.assertEqual(viewer.cli.call_args.kwargs["timeout"], 330)
            self.assertEqual(ViewerController(Path(folder)).profile, "android")
            viewer.select_profile("desktop")
            self.assertEqual(viewer.store.path, linux_path)

    def test_apk_upload_requires_token_origin_content_type_and_bounded_length(self):
        with tempfile.TemporaryDirectory() as folder:
            viewer = ViewerController(Path(folder))
            viewer.install_apk = Mock(return_value={"ok": True, "result": {"installed": True}})
            server = ViewerServer(viewer, 0)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            def request(headers, body=b"fixture"):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request("POST", "/api/apk", body=body, headers=headers)
                response = connection.getresponse()
                status = response.status
                response.read()
                connection.close()
                return status
            try:
                good = {"X-AgenticVM-Token": server.token, "Origin": server.origin, "Content-Type": "application/vnd.android.package-archive"}
                self.assertEqual(request({}), 401)
                self.assertEqual(request({**good, "Origin": "https://example.com"}), 403)
                self.assertEqual(request({**good, "Content-Type": "text/plain"}), 415)
                self.assertEqual(request({**good, "Content-Length": str(512 * 1024 * 1024 + 1)}), 413)
                self.assertEqual(request(good), 200)
                viewer.install_apk.assert_called_once()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)


if __name__ == "__main__":
    unittest.main()
