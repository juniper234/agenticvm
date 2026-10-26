"""Machine-readable CLI: every command emits one JSON envelope to stdout."""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from . import __version__
from .backend import VirtualBoxBackend, find_vboxmanage
from .errors import AgenticVMError
from .input_validation import validate_http_url
from .protocol import GuestClient, MAX_FILE, decode_data
from .qemu import QemuBackend, find_qemu
from .state import StateStore
from .transport import SocketTransport, TcpTransport, WindowsPipeTransport


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agenticvm", description="Control a small, offline Linux agent VM. Output is JSON.")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--workspace", type=Path, default=Path.cwd() / "runtime" / "agenticvm", help="Private VM state directory")
    result.add_argument("--garden-dir", type=Path, help="Garden state directory (default: WORKSPACE/garden)")
    result.add_argument("--session", default="default", help="Named disposable session (default: default)")
    result.add_argument("--backend", choices=("qemu", "virtualbox", "android"), help="Backend for a new session (default: qemu); existing sessions retain theirs")
    result.add_argument("--qemu", help="Path to portable qemu-system-x86_64.exe")
    result.add_argument("--vboxmanage", help="Path to the verified Oracle 7.2.20 VBoxManage.exe")
    result.add_argument("--serial-socket", help=argparse.SUPPRESS)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check the selected hypervisor binary without starting a VM")
    start = commands.add_parser("start", help="Boot a Linux command guest or graphical desktop")
    start.add_argument("--profile", choices=("command", "desktop", "agent", "android"), default="command")
    start.add_argument("--image", type=Path)
    start.add_argument("--root-disk", type=Path, help="Read-only desktop root image")
    start.add_argument("--persistent", action="store_true", help="Retain the desktop workspace across stop/reset")
    start.add_argument("--network", action="store_true", help="Enable desktop outbound NAT; no port forwards")
    start.add_argument("--peer-channel", action="store_true", help="Add a dedicated agent TLS byte channel; no guest NIC")
    start.add_argument("--pair", help="Owned isolated pair UUID (requires --peer-role)")
    start.add_argument("--peer-role", choices=("listen", "connect"), help="Role on a prepared isolated pair Ethernet link")
    start.add_argument("--peer-capture", action="store_true", help="Capture isolated Ethernet packets in this owned VM run folder")
    start.add_argument("--peer-link", choices=("ethernet", "serial"), default="ethernet", help="Medium for --pair; serial needs no NIC or IP")
    start.add_argument("--memory", type=int, metavar="MiB")
    start.add_argument("--cpus", type=int, default=1)
    start.add_argument("--width", type=int, default=1024)
    start.add_argument("--height", type=int, default=768)
    start.add_argument("--ready-timeout", type=float, default=90)
    commands.add_parser("status", help="Report saved session and observed VM/guest status")
    execute = commands.add_parser("exec", help="Run a guest command as an argv array; use -- before argv")
    execute.add_argument("--cwd", default="/workspace")
    execute.add_argument("--timeout-ms", type=int, default=30000)
    execute.add_argument("--output-limit", type=int, default=65536)
    execute.add_argument("--async", dest="asynchronous", action="store_true")
    execute.add_argument("argv", nargs=argparse.REMAINDER)
    poll = commands.add_parser("poll", help="Read a cumulative bounded job snapshot")
    poll.add_argument("job_id")
    poll.add_argument("--wait-ms", type=int, default=0)
    cancel = commands.add_parser("cancel", help="Cancel a guest job and its process group")
    cancel.add_argument("job_id")
    forget = commands.add_parser("forget", help="Release a completed job's retained output")
    forget.add_argument("job_id")
    put = commands.add_parser("put", help="Copy a host file (at most 1 MiB) into /workspace")
    put.add_argument("source", type=Path)
    put.add_argument("path", help="Guest workspace path")
    put.add_argument("--rpc-timeout", type=float, default=240)
    get = commands.add_parser("get", help="Copy a guest workspace file (at most 1 MiB) to the host")
    get.add_argument("path")
    get.add_argument("destination", type=Path)
    get.add_argument("--overwrite", action="store_true")
    get.add_argument("--rpc-timeout", type=float, default=240)
    commands.add_parser("stop", help="Stop and unregister this session; retain its VM files")
    reset = commands.add_parser("reset", help="Stop this session and create a fresh diskless VM")
    reset.add_argument("--ready-timeout", type=float, default=90)
    capture = commands.add_parser("screenshot", help="Capture the guest desktop as a PNG")
    capture.add_argument("destination", type=Path, nargs="?")
    capture.add_argument("--overwrite", action="store_true")
    for name in ("click", "move"):
        point = commands.add_parser(name, help="Send a desktop pointer action at guest pixel coordinates")
        point.add_argument("x", type=int)
        point.add_argument("y", type=int)
        if name == "click":
            point.add_argument("--button", choices=("left", "right", "middle"), default="left")
            point.add_argument("--count", type=int, choices=(1, 2), default=1)
    keys = commands.add_parser("key", help="Send a key or chord, for example ctrl+l or enter")
    keys.add_argument("keys")
    typing = commands.add_parser("type", help="Type literal UTF-8 text into the focused guest window")
    typing.add_argument("text")
    wheel = commands.add_parser("scroll", help="Scroll the guest desktop")
    wheel.add_argument("steps", type=int)
    browser = commands.add_parser("open-url", help="Open the guest browser and navigate to an HTTP(S) URL")
    browser.add_argument("url")
    commands.add_parser("desktop-ready", help="Check that the guest desktop and browser are visible")
    install = commands.add_parser("install-apk", help="Install an APK in the owned Android guest")
    install.add_argument("apk", type=Path)
    launch = commands.add_parser("launch-app", help="Launch an Android package/activity component")
    launch.add_argument("component")
    swipe = commands.add_parser("swipe", help="Send an Android touch gesture")
    for point in ("x1", "y1", "x2", "y2"):
        swipe.add_argument(point, type=int)
    swipe.add_argument("--duration-ms", type=int, default=300)
    garden = commands.add_parser("garden", help="Host-only garden membership and policy state")
    garden_commands = garden.add_subparsers(dest="garden_command", required=True)
    garden_init = garden_commands.add_parser("init", help="Create the local garden state")
    garden_init.add_argument("--name", default="lab")
    garden_init.add_argument("--scope", action="append")
    garden_init.add_argument("--methods", action="append", choices=("inventory", "icmp", "tcp", "ssh", "agent"))
    garden_init.add_argument("--max-total", type=int, default=8)
    garden_init.add_argument("--max-depth", type=int, default=3)
    garden_init.add_argument("--max-active", type=int, default=2)
    garden_init.add_argument("--force", action="store_true")
    garden_init.add_argument("--json", action="store_true")
    garden_status = garden_commands.add_parser("status", help="Show garden state")
    garden_status.add_argument("--json", action="store_true")
    garden_member = garden_commands.add_parser("member", help="Inspect or change membership")
    member_commands = garden_member.add_subparsers(dest="member_command", required=True)
    member_list = member_commands.add_parser("list", help="List members")
    member_list.add_argument("--json", action="store_true")
    member_add = member_commands.add_parser("add", help="Add a member")
    member_add.add_argument("--role", choices=("offshoot", "mother"), default="offshoot")
    member_add.add_argument("--generation", type=int, default=1)
    member_add.add_argument("--address")
    member_add.add_argument("--parent")
    member_add.add_argument("--public-key-sha256")
    member_add.add_argument("--label")
    member_add.add_argument("--json", action="store_true")
    for name in ("activate", "revoke"):
        command = member_commands.add_parser(name, help=name.title() + " a member")
        command.add_argument("member_id")
        command.add_argument("--json", action="store_true")
    garden_policy = garden_commands.add_parser("policy", help="Show or change policy")
    policy_commands = garden_policy.add_subparsers(dest="policy_command", required=True)
    policy_show = policy_commands.add_parser("show", help="Show the policy")
    policy_show.add_argument("--json", action="store_true")
    policy_set = policy_commands.add_parser("set", help="Change policy limits or scope")
    policy_set.add_argument("--scope", action="append")
    policy_set.add_argument("--methods", action="append", choices=("inventory", "icmp", "tcp", "ssh", "agent"))
    policy_set.add_argument("--max-total", type=int)
    policy_set.add_argument("--max-depth", type=int)
    policy_set.add_argument("--max-active", type=int)
    policy_set.add_argument("--json", action="store_true")
    receipts = garden_commands.add_parser("receipts", help="Show hash-chained receipts")
    receipts.add_argument("--limit", type=int, default=20)
    receipts.add_argument("--json", action="store_true")
    garden_search = garden_commands.add_parser("search", help="Bounded read-only TCP inventory")
    garden_search.add_argument("--scope")
    garden_search.add_argument("--port", type=int, action="append")
    garden_search.add_argument("--max-hosts", type=int, default=256)
    garden_search.add_argument("--timeout-ms", type=int, default=300)
    garden_search.add_argument("--json", action="store_true")
    garden_ping = garden_commands.add_parser("ping", help="Authenticated member liveness")
    garden_ping.add_argument("address", nargs="?")
    garden_ping.add_argument("--port", type=int, default=7443)
    garden_ping.add_argument("--member")
    garden_ping.add_argument("--listen", action="store_true")
    garden_ping.add_argument("--host", default="127.0.0.1")
    garden_ping.add_argument("--duration", type=int, default=30)
    garden_ping.add_argument("--timeout-ms", type=int, default=2000)
    garden_ping.add_argument("--json", action="store_true")
    return result


def _client(args, store: StateStore) -> GuestClient:
    if args.serial_socket:
        return GuestClient(lambda timeout: SocketTransport(args.serial_socket, timeout))
    state = store.load()
    if state["status"] != "running" or not state.get("registered", True):
        raise AgenticVMError("This session is not running. Run start first.", "session_not_running")
    if state.get("backend") == "qemu":
        backend = QemuBackend(store, Path(state["executable"]))
        with backend._process(state) as process:
            if not process.alive():
                raise AgenticVMError("The owned VM process has exited.", "session_not_running")
        if state.get("host_control_transport") == "unix":
            return GuestClient(lambda timeout: SocketTransport(state["serial_socket"], timeout))
        return GuestClient(lambda timeout: TcpTransport(state["serial_host"], state["serial_port"], timeout))
    return GuestClient(lambda timeout: WindowsPipeTransport(state["pipe"], timeout))


def _snapshot(result: dict) -> dict:
    result = dict(result)
    for stream in ("stdout", "stderr"):
        field = stream + "_b64"
        if field in result:
            data = decode_data(result[field], 65536)
            result[stream] = data.decode("utf-8", errors="replace")
    return result


def _bounded_timeout(value: float, maximum: float = 300) -> float:
    if not 0 < value <= maximum:
        raise AgenticVMError(f"Timeout must be above zero and at most {maximum:g} seconds.", "invalid_timeout")
    return value


def _run_guest(client, argv, *, cwd="/workspace", timeout_ms=30000, output_limit=65536, background=False):
    started = client.call("exec", argv=argv, cwd=cwd, timeout_ms=timeout_ms, output_limit=output_limit, timeout=30)
    job = started.get("job_id")
    if not isinstance(job, str) or not job:
        raise AgenticVMError("Guest did not return a job ID.", "protocol_error")
    if background:
        return started, 0
    deadline = time.monotonic() + timeout_ms / 1000 + 15
    while time.monotonic() < deadline:
        snapshot = client.call("poll", job_id=job, wait_ms=200, timeout=30)
        if snapshot.get("state") == "exited":
            snapshot = _snapshot(snapshot)
            snapshot["job_id"] = job
            try:
                client.call("forget", job_id=job)
                snapshot["retained"] = False
            except AgenticVMError:
                snapshot["retained"] = True
            code = snapshot.get("exit_code")
            return snapshot, code if type(code) is int and 0 <= code <= 255 else 1
        if snapshot.get("state") != "running":
            raise AgenticVMError("Guest returned an invalid job state.", "protocol_error")
        time.sleep(0.02)
    try:
        client.call("cancel", job_id=job)
    except AgenticVMError:
        pass
    raise AgenticVMError(f"Host wait deadline exceeded for job {job}; cancellation was requested.", "guest_timeout")


def _desktop_probe(client, *, only_visible=True):
    if only_visible:
        result, code = _run_guest(client, ["/usr/bin/xdotool", "search", "--onlyvisible", "--class", "chromium|firefox"],
                                  timeout_ms=3000, output_limit=1024)
        identities = [value for value in result.get("stdout", "").split()
                      if re.fullmatch(r"[0-9]{1,10}", value) and 0 < int(value) <= 0xffffffff]
    else:
        # Searching every X window by class includes Firefox helper windows.
        # The window manager's client list contains actual managed windows,
        # including minimized ones that windowactivate can restore.
        result, code = _run_guest(client, ["/usr/bin/wmctrl", "-lx"], timeout_ms=3000, output_limit=16384)
        identities = []
        for row in result.get("stdout", "").splitlines():
            fields = row.split(None, 4)
            if len(fields) < 4 or not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", fields[0]):
                continue
            browser_classes = {"firefox", "firefox-esr", "chromium", "chromium-browser"}
            if not browser_classes.intersection(fields[2].casefold().split(".")):
                continue
            identity = int(fields[0], 16)
            if identity:
                identities.append(str(identity))
    identities = list(dict.fromkeys(identities)) if code == 0 else []
    return {"ready": bool(identities), "browser_window_ids": identities}


def _clear_browser_job(store, expected_uuid, job):
    """Do not let an old browser cleanup overwrite replacement VM metadata."""
    with store.lock():
        latest = store.load()
        if latest["uuid"] != expected_uuid or latest.get("browser_job_id") != job:
            return False
        latest.pop("browser_job_id", None)
        latest.pop("browser_started_at", None)
        store.save(latest)
        return True


def _cleanup_browser_job(client, store, expected_uuid, job, *, cancel=False):
    """Best-effort cleanup preserves the original startup error and tracked job."""
    result = {"job_id": job, "cancel_requested": False, "forgotten": False}
    try:
        with store.lock():
            if store.load()["uuid"] != expected_uuid:
                result["error"] = {"code": "ownership_mismatch", "message": "Session changed; refusing cleanup through a stale browser client."}
                return result
        if cancel:
            client.call("cancel", job_id=job, timeout=2)
            result["cancel_requested"] = True
        snapshot = client.call("poll", job_id=job, wait_ms=100 if cancel else 0, timeout=2)
        if snapshot.get("state") == "exited":
            client.call("forget", job_id=job, timeout=2)
            result["forgotten"] = True
        elif snapshot.get("state") != "running":
            raise AgenticVMError("Guest returned an invalid browser job state.", "protocol_error")
    except (AgenticVMError, OSError) as error:
        if getattr(error, "code", None) == "unknown_job":
            result["forgotten"] = True
        else:
            result["error"] = {"code": getattr(error, "code", "host_error"), "message": str(error)}
    if result["forgotten"]:
        try:
            result["metadata_cleared"] = _clear_browser_job(store, expected_uuid, job)
        except (AgenticVMError, OSError) as error:
            result["error"] = {"code": getattr(error, "code", "host_error"), "message": str(error)}
    return result


def _ensure_browser(client, store, url, *, expected_uuid=None):
    # The same Store object supports nested locks, so open-url can retain this
    # guard through focus/type/Enter as well as the browser startup itself.
    with store.lock():
        current = store.load()
        if expected_uuid is not None and current["uuid"] != expected_uuid:
            raise AgenticVMError("The VM changed while opening the browser.", "ownership_mismatch")
        if current.get("backend") != "qemu" or current.get("profile") != "desktop":
            raise AgenticVMError("Browser control requires the QEMU desktop profile.", "desktop_unavailable")
        if not current.get("registered") or current["status"] != "running":
            raise AgenticVMError("This desktop session is not running.", "session_not_running")
        expected_uuid = current["uuid"]
        backend = QemuBackend(store, Path(current["executable"]))
        with backend._process(current) as process:
            if not process.alive():
                raise AgenticVMError("The owned VM process has exited.", "session_not_running")
            # A minimized browser is still reusable: open-url activates it after
            # this lookup. Boot readiness separately requires a visible window.
            probe = _desktop_probe(client, only_visible=False)
            if probe["ready"]:
                return probe["browser_window_ids"][0], current.get("browser_job_id")
            prior_job = current.get("browser_job_id")
            if prior_job:
                try:
                    snapshot = client.call("poll", job_id=prior_job, wait_ms=0, timeout=3)
                except AgenticVMError as error:
                    if error.code != "unknown_job":
                        raise
                    _clear_browser_job(store, expected_uuid, prior_job)
                else:
                    state = snapshot.get("state")
                    if state not in {"running", "exited"}:
                        raise AgenticVMError("Guest returned an invalid browser job state.", "protocol_error")
                    age = max(0, time.time() - current["browser_started_at"]) if "browser_started_at" in current else 20
                    if state == "running" and age < 20:
                        raise AgenticVMError("The browser is still starting. Retry in a moment.", "browser_starting")
                    cleaned = _cleanup_browser_job(client, store, expected_uuid, prior_job, cancel=state == "running")
                    if not cleaned["forgotten"]:
                        raise AgenticVMError("The previous browser job could not be released; retry after checking the desktop.",
                                             "browser_unavailable", {"browser_cleanup": cleaned})
            # A stale client cannot launch a job or write into a new UUID.
            latest = store.load()
            if latest["uuid"] != expected_uuid:
                raise AgenticVMError("The VM changed while opening the browser.", "ownership_mismatch")
            launched, _ = _run_guest(client, ["/usr/local/bin/agenticvm-browser", url], timeout_ms=0, background=True)
            job = launched["job_id"]
            try:
                latest = store.load()
                if latest["uuid"] != expected_uuid:
                    raise AgenticVMError("The VM changed while opening the browser.", "ownership_mismatch")
                latest["browser_job_id"] = job
                latest["browser_started_at"] = time.time()
                store.save(latest)
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if not process.alive():
                        raise AgenticVMError("The VM exited while starting the browser.", "session_not_running")
                    probe = _desktop_probe(client)
                    if probe["ready"]:
                        return probe["browser_window_ids"][0], job
                    snapshot = client.call("poll", job_id=job, wait_ms=100, timeout=3)
                    if snapshot.get("state") == "exited":
                        snapshot = _snapshot(snapshot)
                        raise AgenticVMError("The browser could not start: " + snapshot.get("stderr", "")[-1024:], "browser_unavailable")
                    if snapshot.get("state") != "running":
                        raise AgenticVMError("Guest returned an invalid browser job state.", "protocol_error")
                    time.sleep(0.1)
                raise AgenticVMError("The browser did not open in time; its startup job will be stopped.", "browser_unavailable")
            except (AgenticVMError, OSError, KeyboardInterrupt) as error:
                cleanup = _cleanup_browser_job(client, store, expected_uuid, job, cancel=True)
                if isinstance(error, KeyboardInterrupt):
                    raise
                details = {**(getattr(error, "details", None) or {}), "browser_job_id": job, "browser_cleanup": cleanup}
                raise AgenticVMError(str(error), getattr(error, "code", "host_error"), details) from error


_CLIPBOARD_OWNER_SCRIPT = """set -eu
for selection in clipboard primary; do
    /usr/bin/setsid --fork --wait /usr/bin/xclip -silent -selection "$selection" -in "$1" >/dev/null 2>&1 &
done
for selection in clipboard primary; do
    ready=0
    attempt=0
    while [ "$attempt" -lt 40 ]; do
        if /usr/bin/xclip -out -selection "$selection" -target UTF8_STRING 2>/dev/null | /usr/bin/cmp -s -- "$1" -; then
            ready=1
            break
        fi
        attempt=$((attempt + 1))
        /bin/sleep 0.025
    done
    [ "$ready" -eq 1 ] || exit 1
done
"""


def _type_guest_text(client, text):
    try:
        valid = isinstance(text, str) and "\0" not in text and len(text.encode("utf-8")) <= 16384
    except UnicodeError:
        valid = False
    if not valid:
        raise AgenticVMError("Text must contain at most 16 KiB UTF-8, without NUL.", "invalid_text")
    if not text:
        return {"typed_characters": 0}
    data = text.encode("utf-8")
    relative = ".agenticvm-input-" + uuid4().hex
    filename = "/workspace/" + relative
    failed = False
    try:
        client.call("write_file", path=relative, data_b64=base64.b64encode(data).decode("ascii"), timeout=30)
        # Owners must have acquired both X selections before the setup job
        # exits: normal job cleanup kills its original process group. setsid
        # gives each owner a separate session; a replacement selection owner
        # makes the previous xclip exit without retaining an agent job slot.
        _, code = _run_guest(client, ["/bin/sh", "-c", _CLIPBOARD_OWNER_SCRIPT, "agenticvm-input", filename],
                             timeout_ms=5000, output_limit=1024)
        if code:
            raise AgenticVMError("Guest clipboard setup failed.", "desktop_input_failed")
        for selection in ("clipboard", "primary"):
            result, code = _run_guest(client, ["/usr/bin/xclip", "-out", "-selection", selection, "-target", "UTF8_STRING"],
                                      timeout_ms=3000, output_limit=16384)
            if code or result.get("stdout_truncated") or result.get("stdout") != text:
                raise AgenticVMError("Guest clipboard verification failed; text was not pasted.", "desktop_input_failed")
        _, code = _run_guest(client, ["/usr/bin/xdotool", "key", "--clearmodifiers", "shift+Insert"],
                             timeout_ms=3000, output_limit=1024)
        if code:
            raise AgenticVMError("Guest clipboard paste failed.", "desktop_input_failed")
    except BaseException:
        failed = True
        raise
    finally:
        try:
            _, code = _run_guest(client, ["/bin/rm", "-f", "--", filename], timeout_ms=3000, output_limit=1024)
            if code:
                raise AgenticVMError("Guest text input temporary-file cleanup failed.", "desktop_input_failed")
        except BaseException:
            if not failed:
                raise
    return {"typed_characters": len(text)}


def _desktop_guest_action(args, store, saved, desktop):
    url = None
    if args.command == "open-url":
        try:
            url = validate_http_url(args.url)
        except ValueError as error:
            raise AgenticVMError(str(error), "invalid_url") from error
    # A reset must not replace the endpoint between _client's process proof and
    # subsequent guest RPCs, or between focusing a window and typing its URL.
    with store.lock():
        if store.load()["uuid"] != saved["uuid"]:
            raise AgenticVMError("The VM changed before the desktop action began.", "ownership_mismatch")
        client = _client(args, store)
        if args.command == "desktop-ready":
            return _desktop_probe(client)
        if args.command == "type":
            return _type_guest_text(client, args.text)
        window_id, browser_job = _ensure_browser(client, store, url, expected_uuid=saved["uuid"])
        if not window_id.isascii() or not window_id.isdecimal():
            raise AgenticVMError("Browser returned an invalid window identity.", "browser_unavailable")
        focused, code = _run_guest(client, ["/usr/bin/xdotool", "windowactivate", "--sync", window_id], timeout_ms=3000)
        if code:
            raise AgenticVMError("Cannot focus the browser: " + focused.get("stderr", "")[-512:], "desktop_input_failed")
        desktop.key("ctrl+l")
        _type_guest_text(client, url)
        desktop.key("enter")
        return {"url": url, "navigation_requested": True, "browser_job_id": browser_job}


def _save_download(destination: Path, data: bytes, overwrite: bool) -> Path:
    destination = destination.resolve()
    if not destination.parent.is_dir():
        raise AgenticVMError("Download destination directory does not exist.", "invalid_destination")
    if destination.exists() and not overwrite:
        raise AgenticVMError("Download destination exists; use --overwrite to replace it.", "destination_exists")
    descriptor, temporary = tempfile.mkstemp(prefix=".agenticvm-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            # Link creation atomically refuses a concurrently created destination.
            os.link(temporary, destination)
            os.unlink(temporary)
        return destination
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def execute(args) -> tuple[dict, int]:
    if args.command == "garden":
        from .garden_cli import execute as garden_execute
        return garden_execute(args), 0
    from .android import execute_android
    android_result = execute_android(args)
    if android_result is not None:
        return android_result
    if args.command in {"install-apk", "launch-app", "swipe"}:
        raise AgenticVMError("This command requires an Android profile.", "android_required")
    store = StateStore(args.workspace, args.session)
    if args.command in {"exec", "poll", "cancel", "forget", "put", "get"}:
        client = _client(args, store)
        if args.command == "exec":
            argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
            if not argv or len(argv) > 64 or not all(isinstance(item, str) and "\x00" not in item for item in argv):
                raise AgenticVMError("Supply a guest command after --, for example: exec -- uname -a.", "invalid_argv")
            persistent_job = args.timeout_ms == 0 and args.asynchronous and store.load().get("profile") in {"desktop", "agent"}
            if (not 1 <= args.timeout_ms <= 300000 and not persistent_job) or not 1 <= args.output_limit <= 65536:
                raise AgenticVMError("Timeout must be 1–300000 ms; desktop/agent background jobs may use 0. Output limit is 1–65536 bytes.", "invalid_limits")
            encoded_arguments = [len(json.dumps(item, ensure_ascii=True)) - 1 for item in argv]
            if any(size > 16385 for size in encoded_arguments) or sum(encoded_arguments) > 65536:
                raise AgenticVMError("Guest argv is limited to 16 KiB per argument and 64 KiB in total.", "invalid_argv")
            return _run_guest(client, argv, cwd=args.cwd, timeout_ms=args.timeout_ms,
                              output_limit=args.output_limit, background=args.asynchronous)
        if args.command == "poll":
            if not 0 <= args.wait_ms <= 1000:
                raise AgenticVMError("Poll wait must be 0–1000 ms.", "invalid_limits")
            return _snapshot(client.call("poll", job_id=args.job_id, wait_ms=args.wait_ms, timeout=30)), 0
        if args.command in {"cancel", "forget"}:
            return client.call(args.command, job_id=args.job_id), 0
        if args.command == "put":
            _bounded_timeout(args.rpc_timeout)
            if args.source.stat().st_size > MAX_FILE:
                raise AgenticVMError("File exceeds the 1 MiB guest transfer limit.", "file_too_large")
            with args.source.open("rb") as stream:
                data = stream.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise AgenticVMError("File exceeds the 1 MiB guest transfer limit.", "file_too_large")
            result = client.call("write_file", path=args.path, data_b64=base64.b64encode(data).decode("ascii"), timeout=args.rpc_timeout)
            return result, 0
        _bounded_timeout(args.rpc_timeout)
        result = client.call("read_file", path=args.path, timeout=args.rpc_timeout)
        data = decode_data(result.get("data_b64"))
        if result.get("size") != len(data):
            raise AgenticVMError("Guest file size does not match the transferred bytes.", "protocol_error")
        saved = _save_download(args.destination, data, args.overwrite)
        return {"path": args.path, "destination": str(saved), "size": len(data)}, 0

    desktop_commands = {"screenshot", "click", "move", "key", "type", "scroll", "open-url", "desktop-ready"}
    saved = store.load(required=False) if args.command in {"status", "stop", "reset"} | desktop_commands else None
    selected = args.backend or (saved.get("backend", "virtualbox") if saved else "qemu")
    if saved and selected != saved.get("backend", "virtualbox"):
        raise AgenticVMError("The selected backend does not own this saved session.", "backend_mismatch")
    if selected == "qemu":
        executable = (Path(saved["executable"]) if saved and not args.qemu else find_qemu(args.qemu))
        backend = QemuBackend(store, executable)
    else:
        backend = VirtualBoxBackend(store, find_vboxmanage(args.vboxmanage))
    if args.command == "doctor":
        return {**backend.doctor(), "workspace": str(store.root)}, 0
    if args.command in desktop_commands:
        if not saved or selected != "qemu" or saved.get("profile") != "desktop":
            raise AgenticVMError("Start the QEMU desktop profile to use desktop controls.", "desktop_unavailable")
        from .desktop import DesktopController
        desktop = DesktopController(backend)
        if args.command == "screenshot":
            return desktop.screenshot(args.destination, overwrite=args.overwrite), 0
        if args.command == "click":
            return desktop.click(args.x, args.y, args.button, count=args.count), 0
        if args.command == "move":
            return desktop.mouse_move(args.x, args.y), 0
        if args.command == "key":
            return desktop.key(args.keys), 0
        if args.command == "scroll":
            return desktop.scroll(args.steps), 0
        return _desktop_guest_action(args, store, saved, desktop), 0
    if args.command in {"start", "reset"}:
        _bounded_timeout(args.ready_timeout)
        if args.command == "reset":
            with store.lock():
                prior = store.load()
                image, memory = Path(prior["iso"]), prior["memory_mib"]
                _stop(args, store, backend)
                if prior.get("profile") in {"desktop", "agent"}:
                    options = {"peer_channel": prior.get("peer_channel", False), "isolated_link": prior.get("isolated_link"), "serial_link": prior.get("serial_link")} if prior["profile"] == "agent" else {}
                    state = backend.start(image, memory, profile=prior["profile"], root_disk=Path(prior["root_disk"]),
                                          workspace_disk=Path(prior["workspace_disk"]) if prior.get("workspace_disk") else None,
                                          network=prior.get("network") == "nat", width=prior["display_width"], height=prior["display_height"], cpus=prior.get("cpus", 1),
                                          **options)
                else:
                    state = backend.start(image, memory)
        else:
            if bool(args.pair) != bool(args.peer_role):
                raise AgenticVMError("Supply both --pair and --peer-role.", "invalid_network")
            if (args.peer_channel or args.pair or args.peer_capture) and args.profile != "agent":
                raise AgenticVMError("Peer channels and isolated pairs require --profile agent.", "invalid_profile")
            if args.peer_capture and not args.pair:
                raise AgenticVMError("--peer-capture requires --pair and --peer-role.", "invalid_network")
            if args.peer_link == "serial" and (not args.pair or args.peer_capture or args.peer_channel):
                raise AgenticVMError("Serial pairs require --pair and an exclusive peer port; Ethernet capture is unavailable.", "invalid_network")
            if args.profile in {"desktop", "agent"}:
                if selected != "qemu":
                    raise AgenticVMError("The graphical desktop currently uses QEMU/WHPX.", "unsupported_profile")
                image = args.image or Path.cwd() / ("runtime/linux-peer/agenticvm-linux-peer.iso" if args.profile == "agent" else "runtime/linux-desktop/agenticvm-linux-desktop.iso")
                root_disk = args.root_disk or Path.cwd() / "runtime/linux-desktop/rootfs.ext2"
                memory = args.memory if args.memory is not None else (256 if args.profile == "agent" else 768)
                from .storage import ensure_workspace_disk
                with store.lock():
                    current = store.load(required=False)
                    if current and current.get("registered"):
                        raise AgenticVMError("A session is already registered. Stop it before starting another.", "session_exists")
                    workspace_disk = ensure_workspace_disk(store) if args.persistent else None
                    options = {"peer_channel": args.peer_channel, ("serial_link" if args.peer_link == "serial" else "isolated_link"): {"pair_uuid": args.pair, "role": args.peer_role, **({"capture": True} if args.peer_capture else {})} if args.pair else None} if args.profile == "agent" else {}
                    state = backend.start(image, memory, profile=args.profile, root_disk=root_disk,
                                          workspace_disk=workspace_disk, network=args.network, cpus=args.cpus, width=args.width, height=args.height, **options)
            else:
                if args.root_disk or args.persistent or args.network:
                    raise AgenticVMError("Disks, persistence and networking require --profile desktop.", "invalid_profile")
                image = args.image or Path.cwd() / "runtime/linux-agent/agenticvm-linux-agent.iso"
                memory = args.memory if args.memory is not None else 512
                state = backend.start(image, memory)
        try:
            ready_deadline = time.monotonic() + args.ready_timeout
            ready = _client(args, store).ready(args.ready_timeout,
                                              is_running=lambda: backend.status().get("status") == "running")
            if state.get("profile") == "desktop":
                while True:
                    gui = _desktop_probe(_client(args, store))
                    if gui["ready"]:
                        ready["desktop"] = gui
                        break
                    if time.monotonic() >= ready_deadline:
                        raise AgenticVMError("Linux started, but the desktop/browser did not become ready; inspect boot.log.", "desktop_not_ready")
                    time.sleep(0.25)
        except BaseException as error:
            cleanup = _startup_cleanup(store, backend, state["uuid"])
            if isinstance(error, KeyboardInterrupt):
                raise
            code = error.code if isinstance(error, AgenticVMError) else "host_error"
            details = {"startup_cleanup": cleanup, "session": store.session, "uuid": state["uuid"]}
            suffix = " The new session was stopped." if cleanup["ok"] else " Startup cleanup failed; inspect status before retrying."
            raise AgenticVMError(str(error) + suffix, code, details) from error
        return {"session": store.session, "uuid": state["uuid"], "status": "ready", "guest": ready,
                "memory_mib": state["memory_mib"], "cpus": state.get("cpus", 1), "network": state.get("network", "none"), "disk": state.get("disk", "none"),
                "profile": state.get("profile", "command"), "persistent_workspace": bool(state.get("workspace_disk")),
                "workspace": str(store.root)}, 0
    if args.command == "status":
        result = backend.status()
        if result["status"] == "running":
            try:
                result["guest"] = _client(args, store).call("ping", timeout=3)
                result["guest_ready"] = True
            except AgenticVMError as error:
                result["guest_ready"] = False
                result["guest_error"] = {"code": error.code, "message": str(error)}
        return result, 0
    return _stop(args, store, backend), 0


def _startup_cleanup(store: StateStore, backend, expected_uuid: str) -> dict:
    """Never let an older failed start stop a newer concurrent session."""
    try:
        with store.lock():
            if store.load()["uuid"] != expected_uuid:
                raise AgenticVMError("Session changed during startup; refusing to stop its replacement.", "ownership_mismatch")
            return {"ok": True, "result": backend.stop()}
    except Exception as error:
        return {"ok": False, "error": {"code": getattr(error, "code", "host_error"), "message": str(error)}}


def _stop(args, store: StateStore, backend: VirtualBoxBackend) -> dict:
    state = store.load()
    if state.get("registered", True) and state["status"] == "running":
        try:
            _client(args, store).call("shutdown", timeout=3)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if backend.status().get("vm_state") in {"poweroff", "aborted"}:
                    break
                time.sleep(0.1)
        except AgenticVMError:
            pass
    return backend.stop()


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        # The live viewer takes short capture locks. A concurrent agent action
        # waits briefly for those locks instead of failing randomly at 1 FPS.
        deadline = time.monotonic() + 2
        while True:
            try:
                result, code = execute(args)
                break
            except AgenticVMError as error:
                if error.code != "session_busy" or time.monotonic() >= deadline:
                    raise
                time.sleep(0.025)
        output = {"ok": True, "command": args.command, "result": result}
    except AgenticVMError as error:
        output, code = {"ok": False, "command": args.command, "error": {"code": error.code, "message": str(error)}}, 1
        if error.details is not None:
            output["error"]["details"] = error.details
    except (OSError, ValueError) as error:
        output, code = {"ok": False, "command": args.command, "error": {"code": "host_error", "message": str(error)}}, 1
    except KeyboardInterrupt:
        output, code = {"ok": False, "command": args.command, "error": {"code": "interrupted", "message": "Interrupted. Use status to inspect this session."}}, 130
    print(json.dumps(output, ensure_ascii=True, separators=(",", ":")))
    return code
