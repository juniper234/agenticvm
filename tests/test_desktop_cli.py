"""Browser recovery and stale-session protections without launching a VM."""
from __future__ import annotations

import base64
from contextlib import nullcontext, redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch
from uuid import uuid4

from agenticvm.cli import (_clear_browser_job, _desktop_guest_action, _desktop_probe, _ensure_browser,
                           _type_guest_text, execute, main, parser)
from agenticvm.errors import AgenticVMError
from agenticvm.state import StateStore, qemu_socket_directory


NOT_READY = {"ready": False, "browser_window_ids": []}
READY = {"ready": True, "browser_window_ids": ["12345"]}


class DesktopCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = StateStore(self.root / "private")
        self.state = self.make_state()
        self.store.save(self.state)
        self.client = Mock()
        self.client.call.side_effect = self.respond
        self.cancelled = set()
        self.backend = Mock()
        self.backend._process.side_effect = lambda state: nullcontext(SimpleNamespace(alive=lambda: True))
        self.backend_patch = patch("agenticvm.cli.QemuBackend", return_value=self.backend)
        self.backend_patch.start()
        self.addCleanup(self.backend_patch.stop)

    def make_state(self):
        identifier = str(uuid4())
        name = "AgenticVM-" + identifier
        sockets = qemu_socket_directory(identifier)
        return {"schema": 1, "backend": "qemu", "profile": "desktop", "session": "default",
                "workspace": str(self.store.root), "uuid": identifier, "name": name,
                "run_dir": str(self.store.root / "vms" / name), "memory_mib": 768,
                "root_disk": str(self.root / "rootfs.ext2"), "workspace_disk": None,
                "iso": str(self.root / "desktop.iso"), "display_width": 1024, "display_height": 768,
                "network": "nat", "pid": 4321, "process_created": "123456",
                "executable": str(self.root / "qemu.exe"), "backend_sha256": "f" * 64,
                "host_control_transport": "unix", "socket_dir": str(sockets),
                "serial_socket": str(sockets / "s"), "qmp_socket": str(sockets / "q"),
                "registered": True, "status": "running", "created_at": time.time()}

    def respond(self, operation, **fields):
        if operation == "cancel":
            self.cancelled.add(fields["job_id"])
            return {"cancelled": True}
        if operation == "poll":
            return {"state": "exited", "exit_code": 0, "stdout_b64": "", "stderr_b64": ""}
        if operation == "forget":
            return {"forgotten": True}
        raise AssertionError((operation, fields))

    def prior_job(self, *, age=30):
        self.state["browser_job_id"] = "1"
        self.state["browser_started_at"] = time.time() - age
        self.store.save(self.state)

    def ensure(self, url="https://example.test/"):
        return _ensure_browser(self.client, self.store, url, expected_uuid=self.state["uuid"])

    def test_closed_browser_reaps_finished_job_and_starts_literal_url(self):
        self.prior_job()
        url = "https://example.test/path?q=$(whoami)&value=one;two#fragment"
        with patch("agenticvm.cli._desktop_probe", side_effect=[NOT_READY, READY]), \
             patch("agenticvm.cli._run_guest", return_value=({"job_id": "7"}, 0)) as run:
            self.assertEqual(self.ensure(url), ("12345", "7"))
        run.assert_called_once_with(self.client, ["/usr/local/bin/agenticvm-browser", url], timeout_ms=0, background=True)
        self.assertIn(call("forget", job_id="1", timeout=2), self.client.call.call_args_list)
        self.assertEqual(self.store.load()["browser_job_id"], "7")

    def test_missing_prior_job_recovers_but_transport_errors_do_not_launch_duplicates(self):
        for error_code, should_recover in (("unknown_job", True), ("guest_timeout", False), ("protocol_error", False)):
            with self.subTest(error_code=error_code):
                self.prior_job()
                self.client.call.side_effect = AgenticVMError("injected prior poll failure", error_code)
                with patch("agenticvm.cli._desktop_probe", side_effect=[NOT_READY, READY]), \
                     patch("agenticvm.cli._run_guest", return_value=({"job_id": "7"}, 0)) as run:
                    if should_recover:
                        self.assertEqual(self.ensure(), ("12345", "7"))
                    else:
                        with self.assertRaises(AgenticVMError) as caught:
                            self.ensure()
                        self.assertEqual(caught.exception.code, error_code)
                        run.assert_not_called()
                        self.assertEqual(self.store.load()["browser_job_id"], "1")

    def test_minimized_existing_window_is_reused_without_new_browser_job(self):
        with patch("agenticvm.cli._desktop_probe", return_value=READY) as probe, patch("agenticvm.cli._run_guest") as run:
            self.assertEqual(self.ensure(), ("12345", None))
        probe.assert_called_once_with(self.client, only_visible=False)
        run.assert_not_called()
        self.client.call.assert_not_called()

    def test_hidden_firefox_helper_is_not_selected_before_managed_minimized_browser(self):
        managed = "0x00e00015  -1 Navigator.firefox-esr  agenticvm AgenticVM Desktop Ready — Mozilla Firefox\n"

        def windows(client, argv, **fields):
            if argv == ["/usr/bin/wmctrl", "-lx"]:
                return {"stdout": managed}, 0
            if argv[0] == "/usr/bin/xdotool":
                # The old unfiltered search returned this non-managed helper
                # first; windowactivate fails for it in the real guest.
                return {"stdout": "131099\n14680085\n"}, 0
            raise AssertionError("A managed minimized browser must not be relaunched")

        with patch("agenticvm.cli._run_guest", side_effect=windows) as run:
            self.assertEqual(self.ensure(), ("14680085", None))
        run.assert_called_once_with(self.client, ["/usr/bin/wmctrl", "-lx"], timeout_ms=3000, output_limit=16384)
        self.client.call.assert_not_called()

    def test_managed_browser_probe_filters_bad_ids_and_does_not_match_titles(self):
        rows = ("0x00000001  0 Editor.text-editor  guest Firefox ESR document\n"
                "not-hex  0 Navigator.firefox-esr  guest Invalid\n"
                "0x100000000  0 Navigator.firefox-esr  guest Too large\n"
                "0x00000000  0 Navigator.firefox-esr  guest Zero\n"
                "0x00e00015  0 Navigator.firefox-esr  guest Valid\n")
        with patch("agenticvm.cli._run_guest", return_value=({"stdout": rows}, 0)):
            self.assertEqual(_desktop_probe(self.client, only_visible=False), {"ready": True, "browser_window_ids": ["14680085"]})

    def test_recent_start_is_not_duplicated_but_stuck_job_can_be_replaced(self):
        self.prior_job(age=1)
        self.client.call.return_value = {"state": "running"}
        self.client.call.side_effect = None
        with patch("agenticvm.cli._desktop_probe", return_value=NOT_READY), patch("agenticvm.cli._run_guest") as run:
            with self.assertRaises(AgenticVMError) as caught:
                self.ensure()
            self.assertEqual(caught.exception.code, "browser_starting")
            run.assert_not_called()
        self.prior_job(age=30)

        def poll_until_cancel(operation, **fields):
            if operation == "poll" and fields["job_id"] not in self.cancelled:
                return {"state": "running"}
            return self.respond(operation, **fields)

        self.client.call.side_effect = poll_until_cancel
        with patch("agenticvm.cli._desktop_probe", side_effect=[NOT_READY, READY]), \
             patch("agenticvm.cli._run_guest", return_value=({"job_id": "7"}, 0)):
            self.assertEqual(self.ensure(), ("12345", "7"))
        self.assertIn("1", self.cancelled)

    def test_failed_start_preserves_stderr_and_cleans_new_job_metadata(self):
        failure = "Firefox profile could not be opened"

        def fail(operation, **fields):
            if operation == "poll":
                return {"state": "exited", "exit_code": 17, "stdout_b64": "", "stderr_b64": base64.b64encode(failure.encode()).decode()}
            return self.respond(operation, **fields)

        self.client.call.side_effect = fail
        with patch("agenticvm.cli._desktop_probe", return_value=NOT_READY), \
             patch("agenticvm.cli._run_guest", return_value=({"job_id": "7"}, 0)):
            with self.assertRaises(AgenticVMError) as caught:
                self.ensure()
        self.assertEqual(caught.exception.code, "browser_unavailable")
        self.assertIn(failure, str(caught.exception))
        self.assertTrue(caught.exception.details["browser_cleanup"]["forgotten"])
        self.assertNotIn("browser_job_id", self.store.load())
        self.assertNotIn("browser_started_at", self.store.load())

    def test_start_timeout_cancels_and_releases_job_instead_of_permanent_starting_state(self):
        with patch("agenticvm.cli._desktop_probe", return_value=NOT_READY), \
             patch("agenticvm.cli._run_guest", return_value=({"job_id": "7"}, 0)), \
             patch("agenticvm.cli.time.monotonic", side_effect=[0, 21]):
            with self.assertRaises(AgenticVMError) as caught:
                self.ensure()
        self.assertEqual(caught.exception.code, "browser_unavailable")
        self.assertIn("7", self.cancelled)
        self.assertNotIn("browser_job_id", self.store.load())

    def test_cleanup_transport_failure_keeps_job_tracked_and_original_error(self):
        def fail(operation, **fields):
            if operation == "cancel":
                raise AgenticVMError("cannot reach guest", "guest_timeout")
            return self.respond(operation, **fields)

        self.client.call.side_effect = fail
        with patch("agenticvm.cli._desktop_probe", return_value=NOT_READY), \
             patch("agenticvm.cli._run_guest", return_value=({"job_id": "7"}, 0)), \
             patch("agenticvm.cli.time.monotonic", side_effect=[0, 21]):
            with self.assertRaises(AgenticVMError) as caught:
                self.ensure()
        self.assertEqual(caught.exception.code, "browser_unavailable")
        self.assertEqual(caught.exception.details["browser_cleanup"]["error"]["code"], "guest_timeout")
        self.assertEqual(self.store.load()["browser_job_id"], "7")

    def test_stale_uuid_is_rejected_before_any_guest_rpc_or_state_write(self):
        self.store.save(self.make_state())
        with patch("agenticvm.cli._desktop_probe") as probe, patch("agenticvm.cli._run_guest") as run:
            with self.assertRaises(AgenticVMError) as caught:
                self.ensure()
        self.assertEqual(caught.exception.code, "ownership_mismatch")
        probe.assert_not_called()
        run.assert_not_called()
        self.client.call.assert_not_called()

    def test_uuid_change_during_launch_never_writes_or_cancels_through_replacement(self):
        replacement = self.make_state()

        def replace(*args, **kwargs):
            self.store.save(replacement)
            return {"job_id": "7"}, 0

        with patch("agenticvm.cli._desktop_probe", return_value=NOT_READY), patch("agenticvm.cli._run_guest", side_effect=replace):
            with self.assertRaises(AgenticVMError) as caught:
                self.ensure()
        self.assertEqual(caught.exception.code, "ownership_mismatch")
        self.assertEqual(self.store.load()["uuid"], replacement["uuid"])
        self.assertNotIn("browser_job_id", self.store.load())
        self.client.call.assert_not_called()

    def test_cleanup_cannot_clear_a_different_browser_job(self):
        self.prior_job()
        self.assertFalse(_clear_browser_job(self.store, self.state["uuid"], "99"))
        self.assertEqual(self.store.load()["browser_job_id"], "1")

    def test_open_url_passes_the_literal_url_after_window_focus_and_address_bar_selection(self):
        url = "https://example.test/?literal=$(id);&unicode=caf%C3%A9#part"
        args = parser().parse_args(["--workspace", str(self.store.root), "open-url", url])
        desktop = Mock()
        actions = []
        desktop.key.side_effect = lambda keys: actions.append(keys)
        with patch("agenticvm.cli._client", return_value=self.client), \
             patch("agenticvm.cli._ensure_browser", return_value=("12345", None)) as ensure, \
             patch("agenticvm.cli._run_guest", side_effect=lambda *args, **kwargs: (actions.append("focus") or {}, 0)) as run, \
             patch("agenticvm.cli._type_guest_text", side_effect=lambda client, text: actions.append(("type", text))) as typing:
            result = _desktop_guest_action(args, self.store, self.state, desktop)
        self.assertEqual(result["url"], url)
        ensure.assert_called_once_with(self.client, self.store, url, expected_uuid=self.state["uuid"])
        run.assert_called_once_with(self.client, ["/usr/bin/xdotool", "windowactivate", "--sync", "12345"], timeout_ms=3000)
        typing.assert_called_once_with(self.client, url)
        self.assertEqual(desktop.key.call_args_list, [call("ctrl+l"), call("enter")])
        self.assertEqual(actions, ["focus", "ctrl+l", ("type", url), "enter"])

    def test_invalid_urls_fail_before_guest_connection(self):
        for url in ("file:///etc/passwd", "https://user:secret@example.test", "https://example.test/\nvalue", "http://[invalid", "https://example.test/\x7f"):
            args = parser().parse_args(["--workspace", str(self.store.root), "open-url", url])
            with self.subTest(url=url), patch("agenticvm.cli._client") as connect:
                with self.assertRaises(AgenticVMError) as caught:
                    _desktop_guest_action(args, self.store, self.state, Mock())
                self.assertEqual(caught.exception.code, "invalid_url")
                connect.assert_not_called()

    def test_failed_desktop_readiness_stops_only_its_new_session(self):
        self.store.path.unlink()
        self.backend.start.side_effect = lambda *args, **kwargs: (self.store.save(self.state), self.state)[1]
        self.backend.stop.return_value = {"status": "stopped"}
        self.client.ready.return_value = {"protocol": 1}
        args = parser().parse_args(["--workspace", str(self.store.root), "start", "--profile", "desktop", "--ready-timeout", "0.001"])
        with patch("agenticvm.cli.find_qemu", return_value=Path(self.state["executable"])), \
             patch("agenticvm.cli._client", return_value=self.client), \
             patch("agenticvm.cli._desktop_probe", return_value=NOT_READY), \
             patch("agenticvm.cli.time.monotonic", side_effect=[0, 1]):
            with self.assertRaises(AgenticVMError) as caught:
                execute(args)
        self.assertEqual(caught.exception.code, "desktop_not_ready")
        self.assertTrue(caught.exception.details["startup_cleanup"]["ok"])
        self.backend.stop.assert_called_once()

    def test_browser_metadata_and_malformed_identity_fail_as_invalid_state(self):
        for key, value in (("browser_job_id", 7), ("browser_job_id", "not-a-job"), ("browser_job_id", "0"),
                           ("browser_job_id", "18446744073709551616"), ("browser_started_at", float("inf")),
                           ("browser_started_at", 10**400), ("pid", True), ("schema", True), ("uuid", 7)):
            state = copy.deepcopy(self.state)
            if key == "browser_started_at":
                state["browser_job_id"] = "1"
            state[key] = value
            with self.subTest(key=key, value=str(value)[:30]), self.assertRaises(AgenticVMError) as caught:
                self.store.validate(state)
            self.assertEqual(caught.exception.code, "invalid_state")


class CliBusyRetryTests(unittest.TestCase):
    def test_brief_viewer_lock_retries_once_and_returns_one_success(self):
        output = io.StringIO()
        with patch("agenticvm.cli.execute", side_effect=[AgenticVMError("capture lock", "session_busy"), ({"status": "running"}, 0)]) as execute_call, \
             patch("agenticvm.cli.time.monotonic", side_effect=[10, 10.05]), \
             patch("agenticvm.cli.time.sleep") as pause, redirect_stdout(output):
            self.assertEqual(main(["status"]), 0)
        self.assertEqual(execute_call.call_count, 2)
        self.assertIs(execute_call.call_args_list[0].args[0], execute_call.call_args_list[1].args[0])
        pause.assert_called_once_with(0.025)
        self.assertEqual(json.loads(output.getvalue()), {"ok": True, "command": "status", "result": {"status": "running"}})

    def test_other_errors_are_reported_without_replaying_the_action(self):
        for error, code in ((AgenticVMError("input failure", "desktop_input_failed"), "desktop_input_failed"),
                            (OSError("injected host failure"), "host_error")):
            output = io.StringIO()
            with self.subTest(code=code), patch("agenticvm.cli.execute", side_effect=error) as execute_call, \
                 patch("agenticvm.cli.time.sleep") as pause, redirect_stdout(output):
                self.assertEqual(main(["status"]), 1)
            execute_call.assert_called_once()
            pause.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["error"]["code"], code)

    def test_persistent_contention_stops_at_the_two_second_deadline(self):
        output = io.StringIO()
        with patch("agenticvm.cli.execute", side_effect=AgenticVMError("still locked", "session_busy")) as execute_call, \
             patch("agenticvm.cli.time.monotonic", side_effect=[10, 11.99, 12.01]), \
             patch("agenticvm.cli.time.sleep") as pause, redirect_stdout(output):
            self.assertEqual(main(["status"]), 1)
        self.assertEqual(execute_call.call_count, 2)
        pause.assert_called_once_with(0.025)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], "session_busy")


if __name__ == "__main__":
    unittest.main()
