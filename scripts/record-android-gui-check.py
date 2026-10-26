"""Capture independent guest evidence; deliberately exposes no APK install API."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import owned_process, process_pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("phase")
    parser.add_argument("--closed", action="store_true")
    parser.add_argument("--stopped", action="store_true")
    args = parser.parse_args()
    folder = args.folder.resolve()
    report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    package = Path(report["package"])
    workspace = folder / "app-data/workspace"
    target = folder / "apk-gui" / args.phase
    target.mkdir(parents=True, exist_ok=False)
    lease = json.loads(Path(report["reservation"]).read_text(encoding="utf-8"))
    with owned_process(lease["owner"]) as owner:
        if not lease["held"] or not owner.alive():
            raise RuntimeError("Reservation no longer held by its owner")
    pin_path = folder / "native-app-process.json"
    if not pin_path.exists():
        rows = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                               "Get-CimInstance Win32_Process -Filter \"Name='AgenticVM.exe'\" | Select-Object ProcessId,ExecutablePath | ConvertTo-Json -Compress"],
                              capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        candidates = json.loads(rows.stdout)
        if isinstance(candidates, dict):
            candidates = [candidates]
        candidates = [r for r in candidates if Path(r["ExecutablePath"]).resolve() == package / "AgenticVM.exe"]
        if len(candidates) != 1:
            raise RuntimeError("Expected one exact packaged native app")
        pin_path.write_text(json.dumps(process_pin(candidates[0]["ProcessId"]), indent=2), encoding="utf-8")
    evidence = {"phase": args.phase, "at": time.time(), "reservation_held": True, "calls": []}
    environment = os.environ.copy()
    environment.pop("AGENTICVM_HOME", None)
    environment.pop("AGENTICVM_PYTHON", None)
    def cli(*arguments, allow_absent=False):
        result = subprocess.run([str(package / "bundle/python/python.exe"), "-I", "-B", "-m", "agenticvm", "--workspace", str(workspace), "--session", "desktop-app-android", *map(str, arguments)],
                                cwd=package / "bundle", env=environment, capture_output=True, timeout=65, creationflags=subprocess.CREATE_NO_WINDOW)
        response = json.loads(result.stdout)
        evidence["calls"].append({"argv": list(map(str, arguments)), "exit_code": result.returncode, "response": response})
        (target / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        absent = allow_absent and response.get("ok") and response["result"].get("exit_code") == 1 and not response["result"].get("stdout") and not response["result"].get("stderr")
        if (result.returncode and not absent) or not response.get("ok"):
            raise RuntimeError(str(response))
        return response["result"]
    evidence["status"] = cli("status")
    evidence["session_manifest"] = json.loads((workspace / "sessions/desktop-app-android.json").read_text(encoding="utf-8"))
    if args.stopped:
        state = evidence["session_manifest"]
        if state["registered"] or state.get("last_stop_clean") is not True:
            raise AssertionError("Intermediate GUI stop was not clean")
        (folder / "intermediate-gui-stop.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    elif args.closed:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
        with owned_process(pin) as app:
            closed = not app.alive()
        (folder / "native-app-closed.json").write_text(json.dumps({"process": pin, "closed": closed, "at": time.time()}, indent=2), encoding="utf-8")
        if not closed or evidence["status"]["registered"]:
            raise AssertionError("Owned app or VM still running")
    else:
        evidence["package_path"] = cli("exec", "--", "pm", "path", "org.agenticvm.guiprobe", allow_absent=True)
        installed = evidence["package_path"]["stdout"].strip()
        if installed:
            evidence["installed_apk_digest"] = cli("exec", "--", "sha256sum", installed.removeprefix("package:"))
            evidence["package_details"] = cli("exec", "--", "dumpsys", "package", "org.agenticvm.guiprobe")
        evidence["activity"] = cli("exec", "--", "dumpsys", "activity", "activities")
        cli("exec", "--timeout-ms", "35000", "--", "uiautomator", "dump", "/data/local/tmp/agenticvm/gui-probe-ui.xml")
        evidence["ui"] = cli("exec", "--", "cat", "/data/local/tmp/agenticvm/gui-probe-ui.xml")
        cli("screenshot", target / "guest.png")
    evidence["artifacts"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in target.iterdir() if p.is_file() and p.name != "evidence.json"}
    evidence["recorder_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (target / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": str(target / "evidence.json"), "phase": args.phase, "package_path": evidence.get("package_path", {}), "closed": args.closed}))


if __name__ == "__main__":
    main()
