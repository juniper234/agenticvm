"""Audit Android delivery receipts, current pins, packaged JS and exact cleanup."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import owned_process, sha256
from agenticvm.png_evidence import png_signal


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("native", "host", "portable", "package"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    folder = ROOT / "runtime/android-delivery-audits" / str(uuid4())
    folder.mkdir(parents=True)
    checks = []
    def check(name, passed, **detail):
        checks.append({"name": name, "passed": bool(passed), **detail})
    paths = {name: getattr(args, name).resolve() for name in ("native", "host", "portable", "package")}
    native, host, portable = (read(paths[name]) for name in ("native", "host", "portable"))
    package = paths["package"]
    built = read(package / "android-package-receipt.json")
    audit = read(paths["native"].parent / "independent-audit.json")
    check("native_complete", native.get("passed") and native.get("complete") and not native.get("smoke_only"))
    check("independent_audit", audit.get("passed") and audit.get("receipt_sha256") == sha256(paths["native"]))
    changed_native = [name for name, pin in native["source_pins"].items() if sha256(ROOT / name) != pin]
    check("current_native_sources", not changed_native, changed=changed_native)
    changed_host = [name for name, pin in host["source_sha256"].items() if sha256(ROOT / name) != pin]
    check("current_full_host_gate", host.get("passed") and host.get("skipped") == 0 and not changed_host,
          tests=host.get("tests"), changed=changed_host)
    check("host_log_digest", sha256(paths["host"].parent / "tests.log") == host["log_sha256"])
    changed_package = [name for name, pin in built["pins"].items() if sha256(package / name) != pin]
    check("package_seal", built.get("passed") and not changed_package, changed=changed_package)
    check("delivered_guide", sha256(package / "ANDROID-README.md") == sha256(ROOT / "docs/android-support.md"))
    required_bundle = {name: pin for name, pin in native["source_pins"].items() if name.startswith(("src/", "guest/", "tools/"))}
    different = [name for name, pin in required_bundle.items() if not (package / "bundle" / name).is_file() or sha256(package / "bundle" / name) != pin]
    check("packaged_native_sources", not different, files=len(required_bundle), different=different)
    check("native_shell_sources", all(sha256(ROOT / "desktop/AgenticVM.Desktop" / name) == pin for name, pin in built["native_source_pins"].items()))
    check("relocated_native_and_ui", portable.get("passed") and portable.get("complete") and all(row.get("passed") for row in portable["checks"]))
    check("relocated_cleanup", portable.get("all_owned_vms_stopped") is True)
    capture = portable["native_guest_screenshot"]
    check("relocated_painted_display", sha256(Path(capture["path"])) == capture["sha256"] and png_signal(Path(capture["path"]).read_bytes())["nonblack_pixels"] >= 100)
    state = read(paths["portable"].parent / "app-data/workspace/sessions/desktop-app-android.json")
    live = []
    for pin in state["processes"] + [state["launcher"]]:
        with owned_process(pin) as process:
            if process.alive():
                live.append(pin)
    check("independent_relocated_process_probe", not state["registered"] and not live, live=live)
    closed = read(paths["portable"].parent / "native-app-closed.json")
    with owned_process(closed["process"]) as process:
        check("native_app_closed", closed.get("closed") is True and not process.alive())
    # Run the existing behavior tests against byte-identical packaged JS in an
    # owned scratch tree. No VM or product source is modified.
    script_names = ("viewer-settings.mjs", "viewer-download.mjs", "viewer-android.mjs")
    scratch = folder / "packaged-js"
    (scratch / "tests").mkdir(parents=True)
    (scratch / "src/agenticvm/web").mkdir(parents=True)
    shutil.copy2(package / "bundle/src/agenticvm/web/app.js", scratch / "src/agenticvm/web/app.js")
    for name in script_names:
        shutil.copy2(ROOT / "tests" / name, scratch / "tests" / name)
        result = subprocess.run([shutil.which("node"), str(scratch / "tests" / name)], capture_output=True, timeout=30,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        (folder / (name + ".log")).write_bytes(result.stdout + result.stderr)
        check("packaged_js_" + name, result.returncode == 0, source_sha256=sha256(ROOT / "tests" / name), log_sha256=sha256(folder / (name + ".log")))
    receipts = {name: {"path": str(paths[name]), "sha256": sha256(paths[name])} for name in ("native", "host", "portable")}
    receipts["package"] = {"path": str(package / "android-package-receipt.json"), "sha256": sha256(package / "android-package-receipt.json")}
    report = {"schema": "agenticvm.android-delivery-audit.v1", "passed": all(row["passed"] for row in checks), "at": time.time(),
              "checks": checks, "receipts": receipts, "audit_source_sha256": sha256(Path(__file__)), "run": str(folder),
              "profile": {"android": "15", "api": 35, "abi": "x86_64", "minimum_guest_memory_mib": 2560},
              "limits": ["Physical 4 GB host untested", "No Google Play services or ARM-only native translation", "No Android Garden enrollment", "Debug development guest; not a hardened malware detonation environment"]}
    (folder / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.output and report["passed"]:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "checks": len(checks), "failed": [row["name"] for row in checks if not row["passed"]], "report": str(folder / "report.json")}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
