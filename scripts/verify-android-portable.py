"""Boot the relocated portable Android runtime while the lab reservation is held."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import campaign_idle, owned_process, sha256


def lease_expiry(lease):
    # Reservation v1 has a fixed two-hour supervisor lifetime. Windows process
    # creation time is FILETIME (100 ns since 1601), not a Unix timestamp.
    if lease.get("schema") != "agenticvm.android-development-reservation.v1":
        raise RuntimeError("Unknown reservation lifetime contract")
    return int(lease["owner"]["created"]) / 10_000_000 - 11_644_473_600 + 7200


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--lease-file", type=Path, required=True)
    parser.add_argument("--hold-ui", action="store_true")
    args = parser.parse_args()
    package = args.package.resolve()
    lease_path = args.lease_file.resolve()
    lease = json.loads(lease_path.read_text(encoding="utf-8"))
    if not lease_path.is_relative_to(ROOT / "runtime/android-development-reservations") or not lease.get("held") or lease.get("phase") != "idle":
        raise RuntimeError("Portable verification requires an idle, held Android lab reservation")
    if lease["source_sha256"] != sha256(ROOT / "scripts/android-development-reservation.py"):
        raise RuntimeError("Reservation supervisor source changed")
    with owned_process(lease["owner"]) as owner:
        if not owner.alive():
            raise RuntimeError("Native reservation owner exited")
    expires = lease_expiry(lease)
    if expires - time.time() < 600:
        raise RuntimeError("Portable UI acceptance needs at least ten minutes remaining on the reservation; acquire a fresh reservation before launching")
    def ui_deadline():
        return time.monotonic() + min(900, max(0, expires - time.time() - 120))
    try:
        reservation_context = __import__("runpy").run_path(str(ROOT / "scripts/android-development-reservation.py"))["reservation_context"]
        with reservation_context(lease):
            pass
    except RuntimeError:
        pass
    else:
        raise RuntimeError("The selected Android campaign mutex is not reserved")
    folder = ROOT / "runtime/android-portable-validation" / str(uuid4())
    folder.mkdir(parents=True)
    data = folder / "app-data"
    workspace = data / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "viewer-profile-desktop-app.json").write_text(json.dumps({"profile": "android"}), encoding="utf-8")
    python = package / "bundle/python/python.exe"
    environment = os.environ.copy()
    environment.pop("AGENTICVM_HOME", None)
    environment.pop("AGENTICVM_PYTHON", None)
    report = {"schema": "agenticvm.android-portable-acceptance.v1", "passed": False, "complete": False,
              "package": str(package), "folder": str(folder), "checks": [], "phase": "created", "reservation": str(lease_path)}
    def save():
        (folder / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    def check(name, condition, **detail):
        report["checks"].append({"name": name, "passed": bool(condition), **detail})
        save()
        print(json.dumps({"check": name, "passed": bool(condition), "report": str(folder / "report.json")}), flush=True)
        if not condition:
            raise AssertionError(name)
    def cli(*arguments):
        result = subprocess.run([str(python), "-I", "-B", "-m", "agenticvm", "--workspace", str(workspace), "--session", "desktop-app-android", *map(str, arguments)],
                                cwd=package / "bundle", env=environment, capture_output=True, timeout=330,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        response = json.loads(result.stdout)
        with (folder / "cli.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"command": arguments[0], "response": response}) + "\n")
        if result.returncode or not response.get("ok"):
            raise RuntimeError(str(response))
        return response["result"]
    try:
        report["phase"] = "booting"
        save()
        if args.hold_ui:
            opener = subprocess.run([str(python), "-I", "-B", str(package / "scripts/open-android-app.py"), "--data-dir", str(data)],
                                    env=environment, capture_output=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if opener.returncode:
                raise RuntimeError(opener.stderr.decode("utf-8", "replace"))
            report["native_app"] = json.loads(opener.stdout)
            report["phase"] = "ui-start-required"
            save()
            print(json.dumps({"phase": report["phase"], "folder": str(folder)}), flush=True)
            deadline = ui_deadline()
            state_path = workspace / "sessions/desktop-app-android.json"
            while time.monotonic() < deadline:
                if state_path.is_file():
                    saved_state = json.loads(state_path.read_text(encoding="utf-8"))
                    if saved_state.get("registered") and saved_state.get("guest_ready"):
                        break
                time.sleep(0.5)
            else:
                raise RuntimeError("Native app Start did not produce a ready Android session")
            started = cli("status")
        else:
            started = cli("start", "--profile", "android", "--persistent", "--network", "--memory", "2560", "--ready-timeout", "240")
        check("relocated_native_boot", started["guest_ready"] and started["guest"]["ro.build.version.sdk"] == "35")
        state = json.loads((workspace / "sessions/desktop-app-android.json").read_text(encoding="utf-8"))
        check("native_start_configuration", state["profile"] == "android" and state["memory_mib"] == 2560 and state["network"] == "nat" and state["persistent"])
        check("relocated_backend_ownership", all(Path(pin["executable"]).is_relative_to(package / "bundle/tools/android/sdk") for pin in state["processes"]))
        identity = cli("exec", "--", "id", "-u")
        check("relocated_shell", identity["stdout"].strip() == "2000")
        request = 'printf "GET /generate_204 HTTP/1.1\\r\\nHost: connectivitycheck.gstatic.com\\r\\nConnection: close\\r\\n\\r\\n" | nc -4 -q 5 -w 5 -W 5 connectivitycheck.gstatic.com 80; exit 0'
        deadline = time.monotonic() + 60
        probes = []
        while time.monotonic() < deadline:
            response = cli("exec", "--timeout-ms", "15000", "--", "sh", "-c", request)
            probes.append(response)
            if response["stdout"].startswith(("HTTP/1.1 204 ", "HTTP/1.0 204 ")):
                break
            time.sleep(0.5)
        (folder / "nat-probes.json").write_text(json.dumps(probes, indent=2), encoding="utf-8")
        check("relocated_nat_http_204", response["stdout"].startswith(("HTTP/1.1 204 ", "HTTP/1.0 204 ")))
        # Repeat the denial only AFTER real outbound traffic has succeeded,
        # against the ADB port whose live listener just carried these calls.
        blocked = cli("exec", "--", "sh", "-c", f'nc -4 -w 2 10.0.2.2 {state["adb_server_port"]}; result=$?; printf "DENIED_EXIT %s" "$result"; test "$result" -ne 0')
        check("relocated_host_control_denied_nat", blocked["stdout"].startswith("DENIED_EXIT ") and int(blocked["stdout"].split()[-1]) != 0)
        cli("launch-app", "org.agenticvm.control/.MainActivity")
        capture = folder / "android.png"
        cli("screenshot", capture)
        png = capture.read_bytes()
        check("relocated_screenshot", png.startswith(b"\x89PNG\r\n\x1a\n") and struct.unpack(">II", png[16:24]) == (720, 1280), sha256=sha256(capture))
        if args.hold_ui:
            report["phase"] = "ui-ready"
            save()
            print(json.dumps({"phase": "ui-ready", "folder": str(folder), "report": str(folder / "report.json")}), flush=True)
            deadline = ui_deadline()
            while not (folder / "ui-verified.json").is_file() and time.monotonic() < deadline:
                time.sleep(0.5)
            proof = json.loads((folder / "ui-verified.json").read_text(encoding="utf-8"))
            check("native_app_ui", proof.get("verified") is True, observations=proof)
            final_png = folder / "native-app-guest.png"
            cli("screenshot", final_png)
            report["native_guest_screenshot"] = {"path": str(final_png), "sha256": sha256(final_png)}
            report["phase"] = "ui-stop-required"
            save()
            print(json.dumps({"phase": report["phase"], "folder": str(folder)}), flush=True)
            deadline = ui_deadline()
            while not (folder / "ui-stopped.json").is_file() and time.monotonic() < deadline:
                time.sleep(0.5)
            stopped = json.loads((workspace / "sessions/desktop-app-android.json").read_text(encoding="utf-8"))
            check("native_app_stop", not stopped["registered"] and stopped.get("last_stop_clean") is True)
        report.update(passed=True, complete=True)
    except Exception as error:
        report["error"] = str(error)
    finally:
        try:
            report["cleanup"] = cli("stop")
            status = cli("status")
            report["all_owned_vms_stopped"] = status["status"] == "stopped" and not status["registered"]
            if not report["all_owned_vms_stopped"]:
                report["passed"] = False
        except Exception as error:
            report["cleanup_error"] = str(error)
            report["passed"] = False
        report["phase"] = "finished"
        save()
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
