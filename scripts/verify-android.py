"""Sequential Android acceptance with durable receipts, checkpoints and exact cleanup."""
from __future__ import annotations
import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from uuid import uuid4
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import AndroidBackend, AndroidStore, campaign_idle, owned_process, process_pin, sha256
from agenticvm.resources import memory_status

PIN_PATHS = ["src/agenticvm/" + name for name in ("android.py", "cli.py", "mcp.py", "viewer.py", "state.py", "qemu.py", "resources.py", "web/app.js", "web/index.html")]
PIN_PATHS += ["tools/android-lock.json", "scripts/prepare-android.py", "scripts/build-android-control.py", "scripts/verify-android.py"]
PIN_PATHS += ["scripts/android-development-reservation.py", "scripts/promote-android-integration.py", "desktop/AgenticVM.Desktop/Controls.cs", "desktop/AgenticVM.Desktop/MainForm.cs"]
PIN_PATHS += ["src/agenticvm/png_evidence.py"]


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def worker(workspace, ready):
    backend = AndroidBackend(AndroidStore(workspace))
    result = backend.start(memory=2560, persistent=True, network=False, timeout=240, campaign_locked=True)
    save(ready, result)
    while True:
        time.sleep(10)


def main():
    global AndroidBackend, AndroidStore
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--promote", action="store_true")
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--worker-workspace", type=Path)
    parser.add_argument("--worker-ready", type=Path)
    parser.add_argument("--lease-file", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_workspace:
        worker(args.worker_workspace, args.worker_ready)
        return 0
    folder = ROOT / "runtime/android-validation" / str(uuid4())
    folder.mkdir(parents=True)
    report = {"schema": "agenticvm.android-acceptance.v1", "passed": False, "complete": False, "smoke_only": args.smoke,
              "run": str(folder), "started_at": time.time(), "checkpoint_schema": 2, "checks": [], "source_pins": {}, "artifacts": {}, "cleanup": []}
    previous = "0" * 64
    def checkpoint(event, **details):
        nonlocal previous
        row = {"event": event, "at": time.time(), "previous": previous, **details}
        raw = json.dumps(row, sort_keys=True, ensure_ascii=True).encode()
        previous = hashlib.sha256(raw).hexdigest()
        row["checkpoint_sha256"] = previous
        with (folder / "checkpoints.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=True) + "\n")
        save(folder / "report.json", report)
        print(json.dumps({"event": event, "report": str(folder / "report.json"), **details}, ensure_ascii=True), flush=True)
    def check(name, condition, **details):
        report["checks"].append({"name": name, "passed": bool(condition), **details})
        checkpoint(name, passed=bool(condition), **details)
        if not condition:
            raise AssertionError(name)
    def artifact(path):
        report["artifacts"][str(path.relative_to(folder)).replace("\\", "/")] = sha256(path)
    lock = None
    backend = AndroidBackend(AndroidStore(folder / "workspace"))
    worker_pin = None
    try:
        free_disk = shutil.disk_usage(ROOT).free
        checkpoint("created", host_memory=memory_status(), free_disk_bytes=free_disk)
        if not args.smoke and free_disk < 16 * 1024**3:
            raise RuntimeError("Full Android acceptance requires 16 GiB free disk, including retained interrupted userdata initialization")
        deadline = time.monotonic() + args.wait_seconds
        announced = False
        while True:
            if args.lease_file:
                lease_path = args.lease_file.resolve()
                if lease_path.name != "lease.json" or not lease_path.is_relative_to(ROOT / "runtime/android-development-reservations"):
                    raise RuntimeError("Reservation file is outside the development reservation directory")
                lease = json.loads(lease_path.read_text(encoding="utf-8"))
                expected_source = sha256(ROOT / "scripts/android-development-reservation.py")
                if not lease.get("held") or lease.get("phase") != "verify" or lease.get("source_sha256") != expected_source or lease["owner"]["pid"] != os.getppid():
                    raise RuntimeError("Android reservation does not belong to this test controller's parent")
                promotion_results = []
                for candidate in sorted(lease_path.parent.glob("command-*.result.json")):
                    value = json.loads(candidate.read_text(encoding="utf-8"))
                    if value.get("action") == "promote":
                        promotion_results.append(value)
                if not promotion_results or not promotion_results[-1].get("passed"):
                    raise RuntimeError("Latest source promotion was not successful; refusing native launch")
                with owned_process(lease["owner"]) as owner:
                    if not owner.alive():
                        raise RuntimeError("Android reservation owner exited")
                try:
                    reservation_context = __import__("runpy").run_path(str(ROOT / "scripts/android-development-reservation.py"))["reservation_context"]
                    with reservation_context(lease):
                        pass
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("Reservation does not hold the native campaign mutex")
                report["reservation"] = {"path": str(lease_path), "owner": lease["owner"], "source_sha256": expected_source,
                                         "lock_scope": lease.get("lock_scope", "native-host")}
                context = nullcontext()
            else:
                context = campaign_idle()
            try:
                context.__enter__()
                lock = context
                break
            except RuntimeError:
                if not announced:
                    checkpoint("waiting_for_native_campaign")
                    announced = True
                if time.monotonic() >= deadline:
                    raise RuntimeError("Native campaign remains active; no Android VM was launched")
                time.sleep(1)
        if args.promote:
            import runpy
            runpy.run_path(str(ROOT / "scripts/promote-android-integration.py"))["promote"]()
            import importlib
            import agenticvm.android as android_module
            importlib.reload(android_module)
            AndroidBackend, AndroidStore = android_module.AndroidBackend, android_module.AndroidStore
            backend = AndroidBackend(AndroidStore(folder / "workspace"))
            checkpoint("integration_promoted")
        paths = [ROOT / p for p in PIN_PATHS] + sorted((ROOT / "guest/android-control").rglob("*"))
        report["source_pins"] = {str(p.relative_to(ROOT)).replace("\\", "/"): sha256(p) for p in paths if p.is_file()}
        checkpoint("source_snapshot", files=len(report["source_pins"]))
        from agenticvm.cli import parser as cli_parser, execute
        def call(*argv, expect=0):
            parsed = cli_parser().parse_args(["--workspace", str(backend.store.root), "--session", backend.store.session, *map(str, argv)])
            result, code = execute(parsed)
            if code != expect:
                raise AssertionError(f"CLI {argv[0]} returned {code}: {result}")
            return result
        started = backend.start(memory=2560, persistent=True, network=False, timeout=240, campaign_locked=True)
        state = backend.store.load()
        check("native_boot", started["guest_ready"] and started["guest"]["ro.build.version.sdk"] == "35", identity=started["guest"], uuid=state["uuid"])
        check("shell_identity", backend.shell(state, ["id", "-u"]).stdout.strip() == b"2000")
        check("unsupported_bluetooth_disabled", b"package:com.android.bluetooth" in backend.shell(state, ["pm", "list", "packages", "-d", "com.android.bluetooth"]).stdout.splitlines())
        check("adb_identity_binding", state["guest_binding"]["avd_name"] == state["avd_name"] and state["guest_binding"]["observed_memory_kib"] <= state["memory_mib"] * 1024, binding=state["guest_binding"])
        check("effective_persistent_disk_binding", all(Path(value).parent == Path(state["data_dir"]) for value in state["guest_binding"]["disk_paths"].values()), disk_paths=state["guest_binding"]["disk_paths"])
        blocked_external = backend.shell(state, ["nc", "-w", "2", "1.1.1.1", "443"], timeout=5, check=False)
        check("offline_network_denied", "! -o lo -j REJECT" in state["network_guard"]["ipv4"] and "! -o lo -j REJECT" in state["network_guard"]["ipv6"] and blocked_external.returncode != 0,
              rules=state["network_guard"])
        boot_id = backend.shell(state, ["cat", "/proc/sys/kernel/random/boot_id"]).stdout.decode().strip()
        data, metadata = backend.screenshot_bytes()
        screenshot = folder / "boot.png"
        screenshot.write_bytes(data)
        artifact(screenshot)
        from agenticvm.png_evidence import png_signal
        signal = png_signal(data)
        check("native_screenshot", struct.unpack(">II", data[16:24]) == (720, 1280) and signal["nonblack_pixels"] >= 100, bytes=len(data), signal=signal)
        if args.smoke:
            report["complete"] = True
            report["passed"] = True
            return 0
        installed = call("install-apk", ROOT / "tools/android/control/control.apk")
        check("apk_install", installed["installed"], sha256=installed["sha256"])
        invalid_apk = folder / "invalid.apk"
        invalid_apk.write_bytes(b"AgenticVM deliberate invalid APK fixture")
        artifact(invalid_apk)
        try:
            call("install-apk", invalid_apk)
        except Exception as error:
            detail = str(error)
            native_parse_denial = (("java.lang.IllegalArgumentException: Error: Failed to parse APK file: /data/local/tmp/invalid.apk" in detail)
                                   and ("Caused by: java.io.IOException: Failed to load asset path /data/local/tmp/invalid.apk" in detail))
            existing = backend.shell(state, ["pm", "path", "org.agenticvm.control"]).stdout
            check("invalid_apk_denied", getattr(error, "code", None) == "android_command_failed" and native_parse_denial and b"package:" in existing,
                  error=detail, fixture_sha256=sha256(invalid_apk), installed_control_preserved=True)
        else:
            check("invalid_apk_denied", False)
        launched = call("launch-app", "org.agenticvm.control/.MainActivity")
        check("app_launch", "Status: ok" in launched["output"], output=launched["output"])
        def ui():
            result = backend.shell(backend.store.load(), ["uiautomator", "dump", "/data/local/tmp/agenticvm/ui.xml"], timeout=30)
            raw = backend.shell(backend.store.load(), ["cat", "/data/local/tmp/agenticvm/ui.xml"]).stdout
            (folder / "ui-latest.xml").write_bytes(raw)
            return ET.fromstring(raw)
        def widget(description):
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                tree = ui()
                node = next((x for x in tree.iter("node") if x.get("content-desc") == description), None)
                if node is not None:
                    return node
                time.sleep(0.5)
            raise AssertionError("Android widget was not visible: " + description)
        def tap(description):
            node = widget(description)
            x1, y1, x2, y2 = map(int, re.findall(r"\d+", node.attrib["bounds"]))
            call("click", (x1 + x2) // 2, (y1 + y2) // 2)
        marker = "Android 中文 ✓ 😀 ' $ ; %s " + folder.name[:8]
        marker_sha = hashlib.sha256(marker.encode()).hexdigest()
        tap("agenticvm-editor")
        call("type", "--", marker)
        tap("agenticvm-save")
        status = widget("agenticvm-status").get("text", "")
        check("unicode_touch_input", status == "SHA256 " + marker_sha, saved_text_sha256=marker_sha, observed=status)
        app_png = folder / "app.png"
        app_png.write_bytes(backend.screenshot_bytes()[0])
        artifact(app_png)
        literal = "a;$(echo unsafe)'\"$`%s"
        execution = call("exec", "--", "printf", "%s", literal)
        check("literal_argv", execution["stdout"] == literal)
        payload = bytes(range(256)) * 4096
        source, target = folder / "binary-source.bin", folder / "binary-roundtrip.bin"
        source.write_bytes(payload)
        call("put", source, "/workspace/binary.bin")
        call("get", "/workspace/binary.bin", target)
        check("binary_transfer_1mib", target.read_bytes() == payload, sha256=sha256(target))
        artifact(source)
        artifact(target)
        try:
            call("put", source, "/workspace/../escape.bin")
        except Exception as error:
            check("path_escape_denied", getattr(error, "code", None) == "invalid_path", error=str(error))
        else:
            check("path_escape_denied", False)
        bounded = call("exec", "--output-limit", 1024, "--", "head", "-c", "200000", "/dev/zero")
        check("bounded_output", len(bounded["stdout_b64"]) <= 1368 and bounded["output_truncated"])
        before = time.monotonic()
        timed = cli_parser().parse_args(["--workspace", str(backend.store.root), "exec", "--timeout-ms", "150", "--", "sleep", "2"])
        timed_result, timed_code = execute(timed)
        check("guest_deadline", timed_code in {124, 137} and 0.1 <= time.monotonic() - before < 6, exit_code=timed_code)
        sentinel = socket.socket()
        sentinel.bind(("127.0.0.1", 0))
        sentinel.listen()
        sentinel.settimeout(0.2)
        accepted = []
        finish = threading.Event()
        def serve_sentinel():
            while not finish.is_set():
                try:
                    conn, address = sentinel.accept()
                    accepted.append(address)
                    conn.close()
                except socket.timeout:
                    continue
                except OSError:
                    return
        thread = threading.Thread(target=serve_sentinel, daemon=True)
        thread.start()
        try:
            blocked = backend.shell(state, ["nc", "-w", "2", "10.0.2.2", str(sentinel.getsockname()[1])], timeout=5, check=False)
            check("host_alias_denied_offline", blocked.returncode != 0 and not accepted)
        finally:
            finish.set()
            sentinel.close()
            thread.join(2)
        call("key", "home")
        # input keyevent returns before the Home transition finishes. Wait for
        # the actual launcher hierarchy before sending the next gesture.
        home = ui()
        check("android_home", any(node.get("resource-id") == "com.android.launcher3:id/workspace" for node in home.iter("node")))
        call("swipe", "360", "1180", "360", "300", "--duration-ms", "350")
        navigation = ui()
        navigation_raw = (folder / "ui-latest.xml").read_bytes()
        (folder / "navigation.xml").write_bytes(navigation_raw)
        artifact(folder / "navigation.xml")
        drawer = any(node.get("resource-id", "").endswith(("/apps_view", "/apps_list_view", "/search_container_all_apps")) for node in navigation.iter("node"))
        check("android_navigation", drawer, observed_resources=[node.get("resource-id") for node in navigation.iter("node") if node.get("resource-id")][:25])
        stopped = backend.stop()
        report["cleanup"].append(stopped)
        check("clean_stop", stopped["owned_processes_stopped"] and stopped["clean_shutdown"], shutdown=stopped)
        rebooted = backend.start(memory=2560, persistent=True, network=True, timeout=240, campaign_locked=True)
        state = backend.store.load()
        new_boot_id = backend.shell(state, ["cat", "/proc/sys/kernel/random/boot_id"]).stdout.decode().strip()
        check("cold_boot", new_boot_id != boot_id, before=boot_id, after=new_boot_id)
        call("launch-app", "org.agenticvm.control/.MainActivity")
        check("persistent_app_data", widget("agenticvm-status").get("text") == "SHA256 " + marker_sha)
        (folder / "persistent-app.xml").write_bytes((folder / "ui-latest.xml").read_bytes())
        artifact(folder / "persistent-app.xml")
        got = call("exec", "--", "sha256sum", "/data/local/tmp/agenticvm/binary.bin")
        check("persistent_workspace", got["stdout"].split()[0] == hashlib.sha256(payload).hexdigest())
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            connectivity = backend.shell(state, ["dumpsys", "connectivity"], timeout=10).stdout
            if re.search(rb"Active default network: [0-9]+", connectivity) and re.search(rb"DnsAddresses: \[ /[0-9]", connectivity):
                break
            time.sleep(0.5)
        (folder / "nat-connectivity.txt").write_bytes(connectivity)
        artifact(folder / "nat-connectivity.txt")
        check("nat_default_network", re.search(rb"Active default network: [0-9]+", connectivity) is not None and re.search(rb"DnsAddresses: \[ /[0-9]", connectivity) is not None)
        request = 'printf "GET /generate_204 HTTP/1.1\\r\\nHost: connectivitycheck.gstatic.com\\r\\nConnection: close\\r\\n\\r\\n" | nc -4 -q 5 -w 5 -W 5 connectivitycheck.gstatic.com 80'
        deadline = time.monotonic() + 30
        attempts = []
        while time.monotonic() < deadline:
            network = backend.shell(state, ["sh", "-c", request], timeout=15, check=False)
            attempts.append({"code": network.returncode, "stdout": network.stdout.decode("utf-8", "replace"), "stderr": network.stderr.decode("utf-8", "replace")})
            if re.match(rb"HTTP/1\.[01] 204 ", network.stdout):
                break
            time.sleep(0.5)
        save(folder / "nat-http-attempts.json", attempts)
        artifact(folder / "nat-http-attempts.json")
        (folder / "nat-http.txt").write_bytes(network.stdout + network.stderr)
        artifact(folder / "nat-http.txt")
        check("nat_outbound", re.match(rb"HTTP/1\.[01] 204 ", network.stdout) is not None, response_prefix=network.stdout[:160].decode("utf-8", "replace"))
        protected = backend.shell(state, ["nc", "-4", "-w", "2", "10.0.2.2", str(state["adb_server_port"])], timeout=5, check=False)
        check("host_control_denied_nat", protected.returncode != 0)
        call("open-url", "https://example.com/")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            ui()
            if b"This domain is for use in documentation examples" in (folder / "ui-latest.xml").read_bytes():
                break
            time.sleep(1)
        browser_xml = folder / "browser.xml"
        browser_xml.write_bytes((folder / "ui-latest.xml").read_bytes())
        artifact(browser_xml)
        browser_png = folder / "browser.png"
        browser_png.write_bytes(backend.screenshot_bytes()[0])
        artifact(browser_png)
        check("https_browser", b"This domain is for use in documentation examples" in browser_xml.read_bytes() and b"https://example.com/" in browser_xml.read_bytes())
        from agenticvm.mcp import Bridge
        mcp = Bridge(argparse.Namespace(workspace=backend.store.root, session="default", backend="android", image=None, profile="android", root_disk=None, network=False, persistent=True))
        screen_result = mcp.call("vm_screenshot", {})
        check("mcp_screenshot", screen_result["isError"] is False and screen_result["content"][0]["type"] == "image")
        from agenticvm.viewer import ViewerController
        viewer = ViewerController(backend.store.root, application_root=ROOT)
        viewer.base_session = "default"
        viewer.profile = "android"
        viewer.session = "default"
        viewer.store = backend.store
        check("viewer_screen", viewer.screen().startswith(b"\x89PNG"))
        report["cleanup"].append(backend.stop())
        # Force a real boot timeout and retain its failed launch logs/manifest.
        previous_uuid = state["uuid"]
        try:
            backend.start(memory=2560, persistent=False, network=False, timeout=1, campaign_locked=True)
        except Exception as error:
            failed = backend.store.load()
            check("failed_boot_cleanup", getattr(error, "code", None) == "android_timeout" and failed["uuid"] != previous_uuid and len(failed["processes"]) >= 2 and not failed["registered"] and backend.status()["status"] == "stopped", error=str(error), run_dir=failed["run_dir"])
        else:
            report["cleanup"].append(backend.stop())
            check("failed_boot_cleanup", False)
        worker_ready = folder / "worker-ready.json"
        with (folder / "worker.log").open("wb") as log:
            process = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker-workspace", str(backend.store.root), "--worker-ready", str(worker_ready)],
                                       stdout=log, stderr=log, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        worker_pin = process_pin(process.pid)
        deadline = time.monotonic() + 300
        while not worker_ready.is_file() and time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Crash-test controller exited; inspect worker.log")
            time.sleep(0.5)
        if not worker_ready.is_file():
            raise RuntimeError("Crash-test worker never became ready")
        with owned_process(worker_pin, terminate=True) as handle:
            handle.terminate()
            if not handle.wait(10):
                raise AssertionError("Test controller did not exit")
        recovered = AndroidBackend(AndroidStore(backend.store.root)).stop()
        check("controller_crash_recovery", recovered["owned_processes_stopped"], controller=worker_pin, recovery=recovered)
        report["cleanup"].append(recovered)
        check("source_pins_unchanged", all(sha256(ROOT / p) == pin for p, pin in report["source_pins"].items()))
        report["complete"] = True
        report["passed"] = True
        return 0
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
        checkpoint("failed", error=report["error"])
        return 1
    finally:
        if worker_pin:
            try:
                with owned_process(worker_pin, terminate=True) as process:
                    if process.alive():
                        process.terminate()
                    report["test_controllers_stopped"] = process.wait(10)
            except Exception as error:
                report["test_controllers_stopped"] = False
                report["controller_cleanup_error"] = str(error)
                report["passed"] = False
        try:
            result = backend.stop()
            report["cleanup"].append(result)
            report["all_owned_processes_stopped"] = backend.status()["status"] == "stopped"
        except Exception as error:
            report["cleanup_error"] = str(error)
            report["all_owned_processes_stopped"] = False
            report["passed"] = False
        report["finished_at"] = time.time()
        checkpoint("finished", passed=report["passed"], complete=report["complete"], cleanup=report["all_owned_processes_stopped"])
        if lock:
            lock.__exit__(None, None, None)
        if not report["passed"]:
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
