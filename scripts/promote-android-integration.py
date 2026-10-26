"""Apply staged integration only under the native campaign mutex and original pins."""
from pathlib import Path
import hashlib
import json
import shutil
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import campaign_idle


def promote():
    stage = ROOT / "runtime/android-integration-staging"
    pins = json.loads((stage / "original-pins.json").read_text(encoding="utf-8"))
    for relative, expected in pins.items():
        original, candidate = ROOT / relative, stage / relative
        if not original.resolve().is_relative_to(ROOT) or not candidate.resolve().is_relative_to(stage):
            raise RuntimeError("Integration path escapes its workspace")
        actual = hashlib.sha256(original.read_bytes()).hexdigest()
        new = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual not in {expected, new}:
            raise RuntimeError("Concurrent source change; preserve and reconcile: " + relative)
    changes = [relative for relative in pins if (ROOT / relative).read_bytes() != (stage / relative).read_bytes()]
    backup = ROOT / "runtime/android-integration-backups" / str(uuid4())
    if changes:
        backup.mkdir(parents=True)
        restoration = {}
        for relative in changes:
            target = backup / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
            original_hash = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            if hashlib.sha256(target.read_bytes()).hexdigest() != original_hash:
                raise RuntimeError("Integration backup differs: " + relative)
            restoration[relative] = {"backup": str(target), "sha256": original_hash,
                                     "restore": "Copy this exact backup over the original while holding the native campaign mutex"}
        (backup / "restore.json").write_text(json.dumps(restoration, indent=2), encoding="utf-8")
        for relative in changes:
            (ROOT / relative).write_bytes((stage / relative).read_bytes())
        print("Verified integration backup: " + str(backup), flush=True)
    print(json.dumps({"promoted": list(pins)}, indent=2))


if __name__ == "__main__":
    with campaign_idle():
        promote()
