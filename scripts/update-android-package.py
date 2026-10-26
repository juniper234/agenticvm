"""Apply a source-accepted Android backend to this task's unpublished bundle."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--package", type=Path, default=ROOT / "dist/AgenticVM-Android")
    args = parser.parse_args()
    package = args.package.resolve()
    if package != ROOT / "dist/AgenticVM-Android":
        raise RuntimeError("Only this task's unpublished candidate package may be updated")
    native = json.loads(args.native.read_text(encoding="utf-8"))
    if not native.get("passed") or not native.get("complete") or native.get("smoke_only"):
        raise RuntimeError("A complete successful native receipt is required")
    if any(sha256(ROOT / name) != pin for name, pin in native["source_pins"].items()):
        raise RuntimeError("Native receipt no longer matches the source")
    receipt_path = package / "android-package-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if any(sha256(package / name) != pin for name, pin in receipt["pins"].items()):
        raise RuntimeError("Existing package differs from its seal; preserved untouched")
    update = "src/agenticvm/android.py"
    for name, pin in native["source_pins"].items():
        if name.startswith(("src/", "guest/", "tools/")) and name != update:
            if sha256(package / "bundle" / name) != pin:
                raise RuntimeError("Another packaged source differs: " + name)
    backup = ROOT / "runtime/android-package-updates" / str(uuid4())
    backup.mkdir(parents=True)
    target = package / "bundle" / update
    shutil.copy2(target, backup / "android.py.before")
    shutil.copy2(receipt_path, backup / "package-receipt.before.json")
    restore = {"target": str(target), "old_sha256": sha256(target), "new_sha256": native["source_pins"][update],
               "original_receipt_sha256": sha256(receipt_path)}
    (backup / "restore.json").write_text(json.dumps(restore, indent=2), encoding="utf-8")
    temporary = target.with_name("android.py.candidate-" + uuid4().hex)
    shutil.copy2(ROOT / update, temporary)
    if sha256(temporary) != restore["new_sha256"]:
        raise RuntimeError("Candidate copy differs")
    os.replace(temporary, target)
    environment = os.environ.copy()
    environment.pop("AGENTICVM_HOME", None)
    probes = {}
    for backend in ("android", "qemu"):
        result = subprocess.run([str(package / "bundle/python/python.exe"), "-I", "-B", "-m", "agenticvm", "--workspace", str(package / "runtime/package-probe"), "--backend", backend, "doctor"],
                                cwd=package / "bundle", env=environment, capture_output=True, timeout=120,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        response = json.loads(result.stdout)
        if result.returncode or not response.get("ok"):
            raise RuntimeError("Relocated doctor failed: " + str(response))
        probes[backend] = response["result"]
    receipt["pins"]["bundle/" + update] = restore["new_sha256"]
    receipt["accepted_source_update"] = {"at": time.time(), "backup": str(backup), "native_report": str(args.native.resolve()),
                                         "native_report_sha256": sha256(args.native), "restore": restore, "doctor": probes}
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "package": str(package), "backup": str(backup), "source_sha256": restore["new_sha256"]}, indent=2))


if __name__ == "__main__":
    main()
