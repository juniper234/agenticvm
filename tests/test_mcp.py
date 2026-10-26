from argparse import Namespace
import base64
import json
from pathlib import Path
import unittest

from agenticvm.mcp import Bridge


class RecordingBridge(Bridge):
    def __init__(self):
        super().__init__(Namespace(workspace=Path("unused"), session="default", backend="qemu", image=Path("guest.iso")))
        self.commands = []

    def cli(self, *argv):
        self.commands.append(argv)
        if argv[0] == "screenshot":
            Path(argv[1]).write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="))
        return {"ok": True, "result": {"job_id": "1"}}, 0


class MCPTests(unittest.TestCase):
    def test_handshake_and_tools_are_mcp_messages(self):
        bridge = RecordingBridge()
        response = bridge.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")
        self.assertIsNone(bridge.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        tools = bridge.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        self.assertEqual(len(tools), 21)
        self.assertTrue({"vm_screenshot", "vm_click", "vm_type", "vm_key", "vm_open_url"} <= {tool["name"] for tool in tools})
        self.assertTrue(all(tool["inputSchema"]["additionalProperties"] is False for tool in tools))

    def test_argv_and_background_are_preserved_without_shell_interpretation(self):
        bridge = RecordingBridge()
        argv = ["/bin/printf", "%s", "a;$(echo unsafe)\n"]
        result = bridge.call("vm_exec", {"argv": argv, "background": True})
        self.assertFalse(result["isError"])
        self.assertEqual(bridge.commands[0][-4:], ("--", *argv))
        self.assertIn("--async", bridge.commands[0])

    def test_type_bounds_and_unknown_fields_rejected_before_dispatch(self):
        bridge = RecordingBridge()
        for values in ({"argv": ["true"], "timeout_ms": True}, {"argv": ["true"], "timeout_ms": 300001},
                       {"argv": []}, {"argv": ["true"], "host_command": "bad"}):
            with self.assertRaises(ValueError):
                bridge.call("vm_exec", values)
        self.assertEqual(bridge.commands, [])

    def test_large_text_rejected_and_unknown_tool_has_tool_error(self):
        bridge = RecordingBridge()
        with self.assertRaises(ValueError):
            bridge.call("vm_write_file", {"path": "x", "text": "x" * 65537})
        response = bridge.handle({"jsonrpc": "2.0", "id": "bad", "method": "tools/call", "params": {"name": "host_shell"}})
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(bridge.commands, [])

    def test_invalid_params_and_unknown_method_are_jsonrpc_errors(self):
        bridge = RecordingBridge()
        for method, params, code in (("initialize", [], -32602), ("missing", {}, -32601)):
            response = bridge.handle({"jsonrpc": "2.0", "id": 3, "method": method, "params": params})
            self.assertEqual(response["error"]["code"], code)
        self.assertEqual(bridge.handle([])["error"]["code"], -32600)

    def test_screenshot_is_an_mcp_image_instead_of_a_host_path(self):
        result = RecordingBridge().call("vm_screenshot", {})
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["type"], "image")
        self.assertEqual(result["content"][0]["mimeType"], "image/png")
        self.assertTrue(base64.b64decode(result["content"][0]["data"]).startswith(b"\x89PNG"))

    def test_desktop_options_and_literal_text_are_forwarded_as_argv(self):
        bridge = RecordingBridge()
        bridge.call("vm_start", {"profile": "desktop", "network": True, "persistent": True})
        self.assertIn("desktop", bridge.commands[0])
        self.assertIn("--network", bridge.commands[0])
        self.assertIn("--persistent", bridge.commands[0])
        text = "hello;$(not-a-host-command)\n\u2713"
        bridge.call("vm_type", {"text": text})
        self.assertEqual(bridge.commands[-1], ("type", "--", text))
        with self.assertRaises(ValueError):
            bridge.call("vm_type", {"text": "\u2713" * 6000})


if __name__ == "__main__":
    unittest.main()
