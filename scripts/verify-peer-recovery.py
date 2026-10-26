"""Prove checkpoint recovery after an owned controller exits without cleanup."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import os
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.peers import Runner, VM, recover_run
from agenticvm.state import StateStore, qemu_socket_directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--injected-child", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.injected_child:
        directory = args.injected_child
        runner = Runner(directory, str(uuid4()), 256, 1)
        runner.journal.add("run_started", purpose="controlled interruption recovery check")
        runner.provision()
        VM(runner, "serial-guest").start("--peer-channel")
        runner.journal.add("fault_injected", kind="controller exits without finally cleanup", exit_code=23)
        os._exit(23)  # Only this disposable child, after a durable checkpoint.
    directory = ROOT / "runtime/peer-recovery-check" / str(uuid4())
    directory.mkdir(parents=True, mode=0o700)
    result = None
    try:
        child = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--injected-child", str(directory)],
                               cwd=ROOT, capture_output=True, timeout=90,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if child.returncode != 23:
            raise AssertionError("Controlled interruption was not reached: " + child.stderr.decode("utf-8", "replace")[-1000:])
        state = StateStore(directory / "serial-guest").load()
        if not state["registered"] or not (directory / "private/host.key").is_file():
            raise AssertionError("Recovery fixture did not leave the expected owned resources")
        result = recover_run(directory)
        after = StateStore(directory / "serial-guest").load()
        assert result["passed"] and result["tasks_replayed"] is False
        assert after["registered"] is False and after["status"] == "stopped"
        assert not qemu_socket_directory(state["uuid"]).exists()
        assert not (directory / "private").exists()
        report = {"passed": True, "injected_exit_code": child.returncode, "actual_vm_was_running": True,
                  "owned_vm_stopped": True, "private_files_removed": True, "socket_directory_removed": True,
                  "messages_replayed": False, "recovery": result}
        (directory / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
        print(json.dumps({"passed": True, "report": str(directory / "verification.json")}))
        return 0
    finally:
        if result is None and (directory / "checkpoints.jsonl").exists():
            recover_run(directory)


if __name__ == "__main__":
    raise SystemExit(main())
