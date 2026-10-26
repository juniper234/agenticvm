"""Losslessly compress inactive failed Android evidence without removing files."""
from pathlib import Path
import argparse
import json
import shutil
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import AndroidStore, WindowsProcess, owned_process, sha256
from agenticvm.errors import AgenticVMError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lease-file", type=Path, required=True)
    parser.add_argument("--target-free-gib", type=int, default=12, choices=range(8, 33))
    args = parser.parse_args()
    lease = json.loads(args.lease_file.read_text(encoding="utf-8"))
    if not lease.get("held") or lease.get("phase") != "idle":
        raise RuntimeError("Archive compression requires the idle held native reservation")
    with owned_process(lease["owner"]) as process:
        if not process.alive():
            raise RuntimeError("Reservation owner exited")
    candidates = []
    for receipt in (ROOT / "runtime/android-validation").glob("*/report.json"):
        report = json.loads(receipt.read_text(encoding="utf-8"))
        if report.get("passed") or report.get("all_owned_processes_stopped") is not True:
            continue
        store = AndroidStore(receipt.parent / "workspace")
        try:
            state = store.load(required=False)
        except AgenticVMError:
            # Older experimental manifests can fail today's stronger contract.
            # Leave every file in those runs untouched.
            print(json.dumps({"event": "skipped_invalid_manifest", "receipt": str(receipt)}), flush=True)
            continue
        if not state or state.get("registered"):
            continue
        live = False
        for pin in state["processes"] + ([state["launcher"]] if state.get("launcher") else []):
            with WindowsProcess(pin["pid"]) as process:
                live |= process.alive() and process.created == pin["created"] and process.executable == Path(pin["executable"]).resolve()
        if live:
            continue
        for path in receipt.parent.rglob("*"):
            if path.is_file() and path.name in {"ram.img", "emulator.log"} and path.stat().st_size > 100 * 1024**2:
                if path.is_symlink() or not path.resolve().is_relative_to(receipt.parent.resolve()):
                    raise RuntimeError("Archive evidence redirects outside its owner")
                if not path.stat().st_file_attributes & 0x800:
                    candidates.append(path)
    folder = ROOT / "runtime/android-archive-compression" / str(uuid4())
    folder.mkdir(parents=True)
    result = {"schema": "agenticvm.android-evidence-compression.v1", "passed": False, "raw_files_removed": False,
              "free_before": shutil.disk_usage(ROOT).free, "files": []}
    for path in sorted(candidates, key=lambda p: p.stat().st_size, reverse=True):
        if shutil.disk_usage(ROOT).free >= args.target_free_gib * 1024**3:
            break
        pin = sha256(path)
        print(json.dumps({"event": "compressing", "path": str(path), "size": path.stat().st_size, "sha256": pin}), flush=True)
        command = subprocess.run(["compact.exe", "/C", "/F", "/I", "/Q", str(path)], capture_output=True, timeout=180,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        same = sha256(path) == pin
        row = {"path": str(path), "sha256": pin, "unchanged": same, "exit_code": command.returncode,
               "compressed": bool(path.stat().st_file_attributes & 0x800), "free_after": shutil.disk_usage(ROOT).free}
        result["files"].append(row)
        (folder / "report.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(row), flush=True)
        if command.returncode or not same:
            raise RuntimeError("Lossless archive compression did not verify")
    result.update(passed=shutil.disk_usage(ROOT).free >= args.target_free_gib * 1024**3 and all(row["unchanged"] for row in result["files"]), free_after=shutil.disk_usage(ROOT).free)
    (folder / "report.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(folder / "report.json"), "passed": result["passed"], "free_gib": result["free_after"] / 1024**3}), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
