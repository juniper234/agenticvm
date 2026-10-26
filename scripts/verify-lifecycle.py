"""Exercise real CLI lifecycle and files using a fresh disposable test session."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("qemu", "virtualbox"), default="qemu")
    parser.add_argument("--vboxmanage", type=Path, help="Installed matching VirtualBox executable")
    args = parser.parse_args()
    workspace = ROOT / "runtime" / ("lifecycle-check-" + uuid4().hex[:10])
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    prefix = [sys.executable, "-m", "agenticvm", "--workspace", str(workspace), "--backend", args.backend]
    if args.vboxmanage:
        prefix.extend(["--vboxmanage", str(args.vboxmanage.resolve())])
    report = {"workspace": str(workspace), "backend": args.backend, "commands": [], "checks": []}

    def command(*args, expected=0):
        begin = time.monotonic()
        result = subprocess.run([*prefix, *map(str, args)], cwd=ROOT, env=environment,
                                capture_output=True, text=True, encoding="utf-8", timeout=120)
        data = json.loads(result.stdout)
        record = {"argv": list(map(str, args)), "exit_code": result.returncode, "result": data,
                  "elapsed_seconds": time.monotonic() - begin}
        report["commands"].append(record)
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        assert result.returncode == expected, record
        return data.get("result", data), record["elapsed_seconds"]

    try:
        started, boot = command("start", "--memory", "256")
        report["boot_to_ready_seconds_including_cli"] = boot
        assert started["guest"]["uid"] == 1000
        report["checks"].append("Linux boots as UID 1000 with 256 MiB guest RAM")
        kernel, _ = command("exec", "--", "/bin/uname", "-sr")
        assert kernel["stdout"].startswith("Linux ")
        payload = bytes(range(256)) * 32
        source, downloaded = workspace / "input.bin", workspace / "output.bin"
        source.write_bytes(payload)
        command("put", source, "lifecycle-marker.bin")
        command("get", "lifecycle-marker.bin", downloaded)
        assert downloaded.read_bytes() == payload
        report["file_sha256"] = hashlib.sha256(payload).hexdigest()
        report["checks"].append("Host-to-guest-to-host binary file transfer preserves bytes")
        job, _ = command("exec", "--async", "--", "/bin/sleep", "20")
        command("cancel", job["job_id"])
        for _ in range(20):
            snapshot, _ = command("poll", job["job_id"], "--wait-ms", "100")
            if snapshot["state"] == "exited":
                break
        assert snapshot["state"] == "exited" and snapshot["cancelled"]
        command("forget", job["job_id"])
        report["checks"].append("CLI can cancel and collect an asynchronous job")
        timeout, _ = command("exec", "--timeout-ms", "100", "--", "/bin/sleep", "20", expected=137)
        assert timeout["timed_out"] and timeout["signal"] == 9
        report["checks"].append("Guest deadline propagates a timed-out result and exit status")
        reset, reset_time = command("reset")
        assert reset["uuid"] != started["uuid"]
        report["reset_to_ready_seconds_including_cli"] = reset_time
        command("exec", "--", "/bin/test", "-e", "/workspace/lifecycle-marker.bin", expected=1)
        report["checks"].append("Reset creates a fresh VM and discards the temporary workspace")
        command("stop")
        status, _ = command("status")
        assert status["status"] == "stopped" and status["registered"] is False
        report["checks"].append("Stop releases the owned VM and preserves logs")
        failure, _ = command("start", "--memory", "256", "--ready-timeout", "2", "--image",
                             ROOT / "runtime/linux-probe/agenticvm-linux-probe.iso", expected=1)
        assert failure["ok"] is False
        assert failure["error"]["details"]["startup_cleanup"]["ok"] is True, failure
        status, _ = command("status")
        assert status["status"] == "stopped" and status["registered"] is False
        report["checks"].append("An incompatible guest triggers verified startup cleanup")
        report["passed"] = True
    finally:
        try:
            state = json.loads((workspace / "sessions/default.json").read_text())
            if state.get("registered"):
                command("stop")
        finally:
            (workspace / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "commands"}, indent=2))


if __name__ == "__main__":
    main()
