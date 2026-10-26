"""Apply only the accepted APK-message frontend change, with verified rollback."""
from pathlib import Path
import argparse
import json
import os
import shutil
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import owned_process, sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--previous-native", type=Path, required=True)
    parser.add_argument("--lease-file", type=Path, required=True)
    args = parser.parse_args()
    lease_path = args.lease_file.resolve()
    if not lease_path.is_relative_to(ROOT / "runtime/android-development-reservations"):
        raise RuntimeError("Reservation outside owned lab")
    lease = json.loads(lease_path.read_text(encoding="utf-8"))
    with owned_process(lease["owner"]) as owner:
        if not owner.alive() or not lease["held"] or lease["phase"] != "idle":
            raise RuntimeError("Idle live reservation required")
    package = ROOT / "dist/AgenticVM-Android"
    read = lambda p: json.loads(p.read_text(encoding="utf-8"))
    native, previous = read(args.native), read(args.previous_native)
    audit = read(args.native.parent / "independent-audit.json")
    if not native.get("passed") or not native.get("complete") or native.get("smoke_only"):
        raise RuntimeError("Complete native acceptance required")
    if not audit.get("passed") or audit["receipt_sha256"] != sha256(args.native):
        raise RuntimeError("Independent native audit required")
    for name, pin in native["source_pins"].items():
        if sha256(ROOT / name) != pin:
            raise RuntimeError("Native source drift: " + name)
    receipt_path = package / "android-package-receipt.json"
    receipt = read(receipt_path)
    if not receipt.get("passed") or any(sha256(package / name) != pin for name, pin in receipt["pins"].items()):
        raise RuntimeError("Original package seal differs")
    update = "src/agenticvm/web/app.js"
    for name, pin in native["source_pins"].items():
        if name.startswith(("src/", "guest/", "tools/")) and name != update and sha256(package / "bundle" / name) != pin:
            raise RuntimeError("Unexpected additional package change: " + name)
    target = package / "bundle" / update
    if sha256(target) != previous["source_pins"][update]:
        raise RuntimeError("Previous frontend source does not match the accepted baseline")
    backup = ROOT / "runtime/android-package-gui-updates" / str(uuid4())
    backup.mkdir(parents=True)
    for original, filename in [(target, "app.js.before"), (receipt_path, "package-receipt.before.json")]:
        shutil.copy2(original, backup / filename)
        if sha256(original) != sha256(backup / filename):
            raise RuntimeError("Backup differs")
    restore = {"target": str(target), "backup": str(backup / "app.js.before"), "old_sha256": sha256(target),
               "receipt_target": str(receipt_path), "receipt_backup": str(backup / "package-receipt.before.json"),
               "receipt_old_sha256": sha256(receipt_path),
               "procedure": "With all owned VMs/app stopped and the campaign lock held, copy both verified backups over their targets."}
    (backup / "restore.json").write_text(json.dumps(restore, indent=2) + "\n", encoding="utf-8")
    temporary = backup / "app.js.candidate"
    shutil.copy2(ROOT / update, temporary)
    if sha256(temporary) != native["source_pins"][update]:
        raise RuntimeError("Candidate differs")
    # Keep the candidate for review; atomic replace uses a second small copy.
    stage = target.with_suffix(".candidate-" + uuid4().hex)
    shutil.copy2(temporary, stage)
    os.replace(stage, target)
    receipt["pins"]["bundle/" + update] = sha256(target)
    receipt["accepted_gui_update"] = {"at": time.time(), "backup": str(backup), "native_report": str(args.native.resolve()),
                                      "native_report_sha256": sha256(args.native), "restore": restore}
    stage = receipt_path.with_suffix(".candidate-" + uuid4().hex)
    stage.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    os.replace(stage, receipt_path)
    print(json.dumps({"passed": True, "package": str(package), "backup": str(backup), "frontend_sha256": sha256(target)}))


if __name__ == "__main__":
    main()
