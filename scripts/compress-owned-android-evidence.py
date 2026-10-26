"""Losslessly compress old Android RAM evidence after exact-owner death checks."""
from pathlib import Path
import argparse
import json
import shutil
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import WindowsProcess, owned_process, sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lease-file", type=Path, required=True)
    args = parser.parse_args()
    lease = json.loads(args.lease_file.read_text(encoding="utf-8"))
    with owned_process(lease["owner"]) as owner:
        if not owner.alive() or not lease.get("held") or lease.get("phase") != "idle":
            raise RuntimeError("Live idle Android reservation required")
    result = {"schema": "agenticvm.android-archive-compression.v2", "passed": False,
              "files_removed": False, "free_before": shutil.disk_usage(ROOT).free, "files": []}
    folder = ROOT / "runtime/android-archive-compression" / str(uuid4())
    folder.mkdir(parents=True)
    output = folder / "report.json"
    for manifest in sorted((ROOT / "runtime/android-validation").glob("*/workspace/sessions/*.json")):
        state = json.loads(manifest.read_text(encoding="utf-8"))
        if state.get("backend") != "android" or state.get("registered") is not False:
            continue
        pins = state.get("processes", []) + ([state["launcher"]] if state.get("launcher") else [])
        if not pins:
            continue
        live = False
        for pin in pins:
            with WindowsProcess(pin["pid"]) as process:
                live |= process.alive() and process.created == pin["created"] and process.executable == Path(pin["executable"]).resolve()
        if live:
            continue
        run = manifest.parents[2]
        for path in run.rglob("ram.img"):
            if shutil.disk_usage(ROOT).free >= 17 * 1024**3:
                break
            if not path.is_file() or path.stat().st_file_attributes & 0x800:
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(run.resolve()):
                raise RuntimeError("Archive path escapes its owner")
            before = sha256(path)
            print(json.dumps({"compressing": str(path), "sha256": before}), flush=True)
            command = subprocess.run(["compact.exe", "/C", "/F", "/I", "/Q", str(path)],
                                     capture_output=True, timeout=180, creationflags=subprocess.CREATE_NO_WINDOW)
            row = {"path": str(path), "manifest": str(manifest), "manifest_sha256": sha256(manifest),
                   "all_exact_owners_dead": True, "sha256": before, "unchanged": sha256(path) == before,
                   "exit_code": command.returncode, "free_after": shutil.disk_usage(ROOT).free}
            result["files"].append(row)
            output.write_text(json.dumps(result, indent=2), encoding="utf-8")
            if command.returncode or not row["unchanged"]:
                raise RuntimeError("Compression did not verify")
    result.update(passed=all(row["unchanged"] for row in result["files"]), free_after=shutil.disk_usage(ROOT).free)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"report": str(output), "free_gib": result["free_after"] / 1024**3, "passed": result["passed"]}), flush=True)


if __name__ == "__main__":
    main()
