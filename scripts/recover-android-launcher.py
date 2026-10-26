"""Recover an interrupted emulator launcher child using saved lineage and UUID."""
from pathlib import Path
import argparse
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import SDK, AndroidStore, campaign_idle, process_pin, owned_process, sha256, run


def recover(workspace, session="default"):
    store = AndroidStore(workspace, session)
    state = store.load()
    launcher = state["launcher"]
    query = "$p=Get-CimInstance Win32_Process; @($p | Where-Object { $_.Name -like 'qemu-system-x86_64*' -and $_.CommandLine -like '*" + state["avd_name"] + "*' } | Select-Object ProcessId,ParentProcessId,ExecutablePath) | ConvertTo-Json -Compress"
    rows = json.loads(run(["powershell.exe", "-NoProfile", "-Command", query]).stdout or b"[]")
    if isinstance(rows, dict):
        rows = [rows]
    receipt = {"schema": "agenticvm.android-launcher-recovery.v1", "avd": state["avd_name"], "launcher": launcher, "processes": [], "passed": False}
    pins = json.loads((SDK.parent / "prepared.json").read_text())["files"]
    for row in rows:
        item = process_pin(row["ProcessId"])
        path = Path(item["executable"])
        if row["ParentProcessId"] != launcher["pid"] or int(item["created"]) < int(launcher["created"]) or int(item["created"]) - int(launcher["created"]) > 30 * 10**7:
            raise RuntimeError("Recovery child lineage or creation window differs")
        if path.parent != SDK / "emulator/qemu/windows-x86_64" or path.name not in {"qemu-system-x86_64.exe", "qemu-system-x86_64-headless.exe"}:
            raise RuntimeError("Recovery child executable differs")
        if sha256(path) != pins[path.relative_to(SDK).as_posix()]["sha256"]:
            raise RuntimeError("Recovery child binary digest differs")
        receipt["processes"].append(item)
        (Path(state["run_dir"]) / "cleanup-correction.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        with owned_process(item, terminate=True) as process:
            process.terminate()
            if not process.wait(15):
                raise RuntimeError("Owned headless process did not exit")
    receipt["passed"] = True
    receipt["corrects_initial_incomplete_child_inventory"] = bool(rows)
    (Path(state["run_dir"]) / "cleanup-correction.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--session", default="default")
    args = parser.parse_args()
    with campaign_idle():
        recover(args.workspace, args.session)
