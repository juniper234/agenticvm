"""Independently check GUI install provenance, guest state, persistence and exit."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys
import time
from uuid import uuid4
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import owned_process, sha256


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    args = parser.parse_args()
    folder, fixture_path = args.folder.resolve(), args.fixture.resolve()
    checks, artifacts = [], {}
    def check(name, passed, **detail):
        checks.append({"name": name, "passed": bool(passed), **detail})
    def evidence(name):
        path = folder / "apk-gui" / name / "evidence.json"
        data = read(path)
        artifacts[str(path)] = sha256(path)
        for name, pin in data["artifacts"].items():
            check("artifact_" + data["phase"] + "_" + name, sha256(path.parent / name) == pin)
        # This companion only inspects state; the UI owns install/launch/touch.
        def inspection_call(call):
            argv = call["argv"]
            if argv == ["status"]:
                return True
            if argv[0] == "screenshot":
                return len(argv) == 2 and Path(argv[1]).resolve() == path.parent / "guest.png"
            if argv[0] != "exec" or "--" not in argv:
                return False
            guest = argv[argv.index("--") + 1:]
            fixed = [["pm", "path", "org.agenticvm.guiprobe"], ["dumpsys", "package", "org.agenticvm.guiprobe"],
                     ["dumpsys", "activity", "activities"], ["uiautomator", "dump", "/data/local/tmp/agenticvm/gui-probe-ui.xml"],
                     ["cat", "/data/local/tmp/agenticvm/gui-probe-ui.xml"]]
            if guest in fixed:
                return True
            return len(guest) == 2 and guest[0] == "sha256sum" and guest[1].startswith("/data/app/") and guest[1].endswith("/base.apk")
        inspect_only = all(inspection_call(c) for c in data["calls"])
        check("inspection_only_" + data["phase"], inspect_only and data["reservation_held"] is True)
        check("recorder_source_" + data["phase"], data["recorder_sha256"] == sha256(ROOT / "scripts/record-android-gui-check.py"))
        return data
    fixture, portable, native = read(fixture_path), read(folder / "report.json"), read(args.native)
    check("fixture_apk_digest", sha256(Path(fixture["apk"])) == fixture["apk_sha256"])
    check("fixture_invalid_digest", sha256(Path(fixture["invalid_apk"])) == fixture["invalid_apk_sha256"])
    check("fixture_source_pins", all(sha256(ROOT / n) == h for n, h in fixture["sources"].items()))
    check("fixture_no_permissions", not ET.parse(ROOT / "guest/android-gui-probe/AndroidManifest.xml").getroot().findall("uses-permission"))
    check("current_native_acceptance", native["passed"] and native["complete"] and not native["smoke_only"] and all(sha256(ROOT / n) == h for n, h in native["source_pins"].items()))
    check("portable_native_complete", portable["passed"] and portable["complete"] and all(c["passed"] for c in portable["checks"]))
    check("portable_clean_stop", portable["all_owned_vms_stopped"] and portable["cleanup"]["clean_shutdown"])
    phases = {n: evidence(n) for n in ["before-verified", "invalid-refused", "installed", "tapped", "reinstalled", "coldboot", "closed"]}
    for name in ["before-verified", "invalid-refused"]:
        result = phases[name]["package_path"]
        check("absent_" + name, result["exit_code"] == 1 and not result["stdout"] and not result["stderr"])
    for name in ["installed", "tapped", "reinstalled", "coldboot"]:
        result = phases[name]
        check("installed_digest_" + name, result["installed_apk_digest"]["exit_code"] == 0 and result["installed_apk_digest"]["stdout"].split()[0] == fixture["apk_sha256"])
    for name in ["tapped", "reinstalled", "coldboot"]:
        result = phases[name]
        nodes = list(ET.fromstring(result["ui"]["stdout"]).iter("node"))
        check("app_running_with_saved_tap_" + name,
              any(n.get("text") == "GUI APK installation verified" and n.get("package") == fixture["package"] for n in nodes)
              and any(n.get("text") == "Verified taps: 1" and n.get("content-desc") == "gui-install-probe-status" for n in nodes)
              and "org.agenticvm.guiprobe/.MainActivity" in result["activity"]["stdout"])
    def install_time(phase, field):
        match = re.search(r"^\s*" + field + r"=(.+)$", phases[phase]["package_details"]["stdout"], re.MULTILINE)
        return match.group(1).strip() if match else None
    first = install_time("installed", "firstInstallTime")
    before_update, after_update = install_time("installed", "lastUpdateTime"), install_time("reinstalled", "lastUpdateTime")
    check("real_reinstall_preserved_app_identity", first is not None and first == install_time("reinstalled", "firstInstallTime")
          and before_update is not None and after_update is not None and after_update > before_update)
    check("coldboot_new_vm_same_persistent_data", phases["tapped"]["status"]["uuid"] != phases["coldboot"]["status"]["uuid"]
          and phases["coldboot"]["status"]["persistent"] is True
          and phases["tapped"]["session_manifest"]["data_dir"] == phases["coldboot"]["session_manifest"]["data_dir"])
    intermediate = read(folder / "intermediate-gui-stop.json")
    check("intermediate_clean_gui_poweroff", intermediate["registered"] is False and intermediate["last_stop_clean"] is True)
    observations = [json.loads(line) for line in (folder / "gui-observations.jsonl").read_text(encoding="utf-8").splitlines()]
    events = {o["event"]: o for o in observations}
    def text(name):
        return json.dumps(events.get(name, {}).get("accessibility") or {}, ensure_ascii=True)
    required = ["picker-cancelled-no-file", "invalid-apk-path-selected", "invalid-apk-submitted-keyboard-open", "invalid-apk-result", "valid-apk-path-selected", "valid-apk-submitted-through-open-dialog", "valid-apk-install-result", "installed-probe-launched-from-android-drawer", "probe-record-tap-clicked", "reinstall-apk-path-selected", "reinstall-apk-submitted-through-open-dialog", "reinstall-apk-install-result", "reinstalled-probe-launched-from-android-drawer", "intermediate-gui-stop-clicked", "intermediate-gui-stopped", "coldboot-start-clicked", "coldboot-probe-launched-from-android-drawer", "final-gui-stopped"]
    check("gui_action_checkpoints", all(n in events for n in required), missing=[n for n in required if n not in events])
    for name in ["valid-apk-path-selected", "reinstall-apk-path-selected"]:
        check("real_dialog_path_" + name, fixture["apk"].replace("\\", "\\\\") in text(name) and "File name:" in text(name))
    check("readable_invalid_error", "Android could not read this APK. Choose a valid, complete APK file." in text("invalid-apk-result") and "java.lang" not in text("invalid-apk-result"))
    check("gui_install_success", "Android app installed." in text("valid-apk-install-result") and "Android app installed." in text("reinstall-apk-install-result"))
    state = read(folder / "app-data/workspace/sessions/desktop-app-android.json")
    alive = []
    for pin in state["processes"] + [state["launcher"]]:
        with owned_process(pin) as process:
            if process.alive():
                alive.append(pin)
    check("independent_owned_vm_exit", not alive and state["registered"] is False and state["last_stop_clean"] is True)
    closed = read(folder / "native-app-closed.json")
    with owned_process(closed["process"]) as app:
        check("independent_native_app_exit", closed["closed"] and not app.alive())
    package = Path(portable["package"])
    check("packaged_frontend_current", sha256(package / "bundle/src/agenticvm/web/app.js") == sha256(ROOT / "src/agenticvm/web/app.js"))
    for path in [fixture_path, args.native.resolve(), folder / "report.json", folder / "gui-observations.jsonl", folder / "intermediate-gui-stop.json", folder / "native-app-closed.json", package / "bundle/src/agenticvm/web/app.js", package / "AgenticVM.exe", Path(__file__), ROOT / "scripts/record-android-gui-check.py"]:
        artifacts[str(path)] = sha256(path)
    output = ROOT / "runtime/android-gui-apk-audits" / str(uuid4())
    output.mkdir(parents=True)
    report = {"schema": "agenticvm.android-gui-apk-audit.v1", "passed": all(c["passed"] for c in checks), "at": time.time(),
              "checks": checks, "artifacts": artifacts, "folder": str(folder), "apk_sha256": fixture["apk_sha256"],
              "scope": "Actual native Windows app file chooser -> guest APK install -> drawer launch -> GUI tap -> GUI reinstall -> clean GUI stop/start -> saved app data; independent guest inspection and process exit probes"}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "checks": len(checks), "failed": [c["name"] for c in checks if not c["passed"]], "report": str(output / "report.json")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
