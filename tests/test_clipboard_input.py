"""Literal guest-only Unicode clipboard input and temporary-file lifecycle."""
import base64
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from agenticvm.cli import _type_guest_text
from agenticvm.errors import AgenticVMError


class ClipboardInputTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.events = []
        self.text = "Clipboard café λ 中文 🚀\n--window $(whoami); 'quoted'\t"
        self.client.call.side_effect = self.write

    def write(self, operation, **fields):
        self.assertEqual(operation, "write_file")
        self.events.append((operation, fields["path"]))
        self.assertRegex(fields["path"], r"^\.agenticvm-input-[0-9a-f]{32}$")
        self.assertEqual(base64.b64decode(fields["data_b64"], validate=True), self.text.encode("utf-8"))
        self.assertEqual(fields["timeout"], 30)
        return {"size": len(self.text.encode("utf-8"))}

    def run_guest(self, client, argv, **options):
        self.assertIs(client, self.client)
        self.events.append((argv[0], argv))
        self.assertLessEqual(options["timeout_ms"], 5000)
        self.assertLessEqual(options["output_limit"], 16384)
        if argv[0] == "/usr/bin/xclip":
            return {"stdout": self.text, "stdout_truncated": False}, 0
        return {}, 0

    def test_unicode_shell_metacharacters_and_newlines_are_verified_before_one_paste(self):
        identifier = UUID("01234567-89ab-4def-8123-456789abcdef")
        with patch("agenticvm.cli.uuid4", return_value=identifier), patch("agenticvm.cli._run_guest", side_effect=self.run_guest) as run:
            self.assertEqual(_type_guest_text(self.client, self.text), {"typed_characters": len(self.text)})
        filename = "/workspace/.agenticvm-input-" + identifier.hex
        calls = [item.args[1] for item in run.call_args_list]
        self.assertEqual([event[0] for event in self.events],
                         ["write_file", "/bin/sh", "/usr/bin/xclip", "/usr/bin/xclip", "/usr/bin/xdotool", "/bin/rm"])
        self.assertEqual(calls[0][-2:], ["agenticvm-input", filename])
        script = calls[0][2]
        self.assertIn('for selection in clipboard primary', script)
        self.assertIn('/usr/bin/setsid --fork --wait /usr/bin/xclip -silent', script)
        self.assertIn('"$1"', script)
        self.assertNotIn(self.text, script)
        self.assertEqual(calls[1], ["/usr/bin/xclip", "-out", "-selection", "clipboard", "-target", "UTF8_STRING"])
        self.assertEqual(calls[2], ["/usr/bin/xclip", "-out", "-selection", "primary", "-target", "UTF8_STRING"])
        self.assertEqual(calls[3], ["/usr/bin/xdotool", "key", "--clearmodifiers", "shift+Insert"])
        self.assertEqual(calls[4], ["/bin/rm", "-f", "--", filename])
        self.assertTrue(all(self.text not in argv for argv in calls))

    def test_exact_16_kib_payload_needs_no_per_character_keyboard_job(self):
        self.text = "a" * 16382 + "é"
        with patch("agenticvm.cli._run_guest", side_effect=self.run_guest) as run:
            self.assertEqual(_type_guest_text(self.client, self.text), {"typed_characters": len(self.text)})
        self.assertEqual(run.call_count, 5)
        self.assertFalse(any("type" in item.args[1] for item in run.call_args_list))

    def test_empty_text_is_a_no_op_and_invalid_text_dispatches_nothing(self):
        with patch("agenticvm.cli._run_guest") as run:
            self.assertEqual(_type_guest_text(self.client, ""), {"typed_characters": 0})
            for value in ("\0", "\ud800", "é" * 8193):
                with self.subTest(value=repr(value)[:30]), self.assertRaises(AgenticVMError) as caught:
                    _type_guest_text(self.client, value)
                self.assertEqual(caught.exception.code, "invalid_text")
        self.client.call.assert_not_called()
        run.assert_not_called()

    def test_wrong_truncated_or_unavailable_clipboard_never_pastes_and_always_removes_file(self):
        for result, code in (({"stdout": self.text + "wrong"}, 0),
                             ({"stdout": self.text, "stdout_truncated": True}, 0),
                             ({"stdout": self.text}, 1)):
            self.events = []

            def fail_readback(client, argv, **options):
                self.run_guest(client, argv, **options)
                return (result, code) if argv[0] == "/usr/bin/xclip" else ({}, 0)

            with self.subTest(result=result, code=code), patch("agenticvm.cli._run_guest", side_effect=fail_readback) as run:
                with self.assertRaises(AgenticVMError) as caught:
                    _type_guest_text(self.client, self.text)
            self.assertEqual(caught.exception.code, "desktop_input_failed")
            self.assertNotIn(self.text, str(caught.exception))
            self.assertEqual(run.call_args.args[1][:3], ["/bin/rm", "-f", "--"])
            self.assertFalse(any(item.args[1][0] == "/usr/bin/xdotool" for item in run.call_args_list))

    def test_setup_or_paste_exit_failure_still_cleans_the_generated_file(self):
        for failing_binary in ("/bin/sh", "/usr/bin/xdotool"):
            def fail(client, argv, **options):
                result, code = self.run_guest(client, argv, **options)
                return (result, 7) if argv[0] == failing_binary else (result, code)

            with self.subTest(binary=failing_binary), patch("agenticvm.cli._run_guest", side_effect=fail) as run:
                with self.assertRaises(AgenticVMError) as caught:
                    _type_guest_text(self.client, self.text)
            self.assertEqual(caught.exception.code, "desktop_input_failed")
            self.assertEqual(run.call_args.args[1][0], "/bin/rm")
            if failing_binary == "/bin/sh":
                self.assertEqual(run.call_count, 2)

    def test_cleanup_failure_preserves_original_transport_exception(self):
        original = AgenticVMError("original write failure", "guest_timeout")
        self.client.call.side_effect = original
        with patch("agenticvm.cli._run_guest", side_effect=AgenticVMError("cleanup failure", "guest_disconnected")) as run:
            with self.assertRaises(AgenticVMError) as caught:
                _type_guest_text(self.client, self.text)
        self.assertIs(caught.exception, original)
        self.assertEqual(run.call_args.args[1][:3], ["/bin/rm", "-f", "--"])

    def test_cleanup_failure_after_paste_is_reported(self):
        def fail_cleanup(client, argv, **options):
            result, code = self.run_guest(client, argv, **options)
            return (result, 1) if argv[0] == "/bin/rm" else (result, code)

        with patch("agenticvm.cli._run_guest", side_effect=fail_cleanup):
            with self.assertRaisesRegex(AgenticVMError, "cleanup failed"):
                _type_guest_text(self.client, self.text)


if __name__ == "__main__":
    unittest.main()
