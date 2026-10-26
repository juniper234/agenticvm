"""Malformed Unicode and URL ports must fail before any guest dispatch."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from agenticvm.cli import _desktop_guest_action, _type_guest_text
from agenticvm.errors import AgenticVMError
from agenticvm.input_validation import validate_http_url
from agenticvm.mcp import Bridge
from agenticvm.viewer import ViewerController, ViewerError


class InvalidDesktopInputTests(unittest.TestCase):
    def test_cli_surrogate_text_has_invalid_text_error_without_guest_rpc(self):
        client = Mock()
        with patch("agenticvm.cli._run_guest") as run:
            for value in ("\ud800", "\udfff", "valid then \ud800"):
                with self.subTest(value=repr(value)), self.assertRaises(AgenticVMError) as caught:
                    _type_guest_text(client, value)
                self.assertEqual(caught.exception.code, "invalid_text")
            run.assert_not_called()
        client.call.assert_not_called()

    def test_cli_bad_port_and_surrogate_url_fail_before_session_or_rpc(self):
        store, client = Mock(), Mock()
        for value in ("https://example.test:65536/", "https://example.test:-1/", "https://example.test:abc/", "https://example.test:0/", "https://example.test/\ud800"):
            with self.subTest(value=repr(value)), self.assertRaises(AgenticVMError) as caught:
                _desktop_guest_action(SimpleNamespace(command="open-url", url=value), store, {}, Mock())
            self.assertEqual(caught.exception.code, "invalid_url")
        store.lock.assert_not_called()
        client.call.assert_not_called()

    def test_mcp_surrogates_are_clean_tool_errors_before_cli_dispatch(self):
        bridge = Bridge(SimpleNamespace(workspace=Path("unused"), session="default", backend="qemu", image=None))
        bridge.cli = Mock()
        for name, arguments in (("vm_type", {"text": "\ud800"}), ("vm_write_file", {"path": "test.txt", "text": "\udfff"})):
            response = bridge.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
            self.assertTrue(response["result"]["isError"])
            self.assertIn("valid UTF-8", response["result"]["content"][0]["text"])
        bridge.cli.assert_not_called()

    def test_mcp_bad_ports_are_rejected_before_cli_dispatch(self):
        bridge = Bridge(SimpleNamespace(workspace=Path("unused"), session="default", backend="qemu", image=None))
        bridge.cli = Mock()
        for value in ("https://example.test:70000/", "https://example.test:port/"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "valid port"):
                bridge.call("vm_open_url", {"url": value})
        bridge.cli.assert_not_called()

    def test_viewer_surrogates_and_bad_ports_are_client_errors_before_dispatch(self):
        controller = ViewerController(Path("unused"))
        controller.cli = Mock()
        for request in ({"action": "type", "text": "\ud800"}, {"action": "open-url", "url": "https://example.test/\udfff"},
                        {"action": "open-url", "url": "https://example.test:65536/"}, {"action": "open-url", "url": "https://example.test:bad/"}):
            with self.subTest(request=repr(request)), self.assertRaises(ViewerError) as caught:
                controller.action(request)
            self.assertEqual(caught.exception.status, 400)
        controller.cli.assert_not_called()

    def test_valid_nondefault_port_and_unicode_url_stays_literal(self):
        value = "https://example.test:4443/café?literal=$(id);&x=1#part"
        self.assertEqual(validate_http_url(value), value)


if __name__ == "__main__":
    unittest.main()
