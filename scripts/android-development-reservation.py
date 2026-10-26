"""Reserve one sequential Android development window across bounded test iterations."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import runpy
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import campaign_idle, process_pin
from agenticvm.chain import exclusive


def reservation_context(lease):
    """Explicit concurrent lab runs retain one Android campaign at a time."""
    scope = lease.get("lock_scope", "native-host")
    if scope == "android-only":
        folder = ROOT / "runtime/android-development-reservations/campaign"
        folder.mkdir(parents=True, exist_ok=True)
        return exclusive(folder)
    if scope != "native-host":
        raise RuntimeError("Unknown Android reservation lock scope")
    return campaign_idle()


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--concurrent-windows", action="store_true",
                        help="Explicitly allow Windows overlap; retain Android ownership, resource checks and exclusive Android lock")
    args = parser.parse_args()
    folder = ROOT / "runtime/android-development-reservations" / str(uuid4())
    folder.mkdir(parents=True)
    lease = {"schema": "agenticvm.android-development-reservation.v1", "owner": process_pin(os.getpid()),
             "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "held": False, "phase": "waiting",
             "lock_scope": "android-only" if args.concurrent_windows else "native-host"}
    save(folder / "lease.json", lease)
    print(json.dumps({"reservation": str(folder), "phase": "waiting"}), flush=True)
    deadline = time.monotonic() + 7200
    while True:
        context = reservation_context(lease)
        try:
            context.__enter__()
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Native development reservation remained blocked for two hours")
            time.sleep(1)
    try:
        lease.update(held=True, phase="idle")
        save(folder / "lease.json", lease)
        print(json.dumps({"reservation": str(folder), "phase": "idle", "held": True}), flush=True)
        completed = set()
        while time.monotonic() < deadline:
            commands = sorted(p for p in folder.glob("command-*.json") if p.name not in completed and not p.name.endswith(".result.json"))
            if not commands:
                time.sleep(0.25)
                continue
            command_path = commands[0]
            if command_path.stat().st_size > 4096:
                raise RuntimeError("Reservation command exceeds its size limit")
            command = json.loads(command_path.read_text(encoding="utf-8"))
            if set(command) - {"action", "smoke"} or command.get("action") not in {"promote", "verify", "release"}:
                raise RuntimeError("Unknown Android reservation command")
            lease.update(phase=command["action"], command=command_path.name)
            save(folder / "lease.json", lease)
            result = {"command": command_path.name, "action": command["action"], "started_at": time.time(), "passed": False}
            try:
                if command["action"] == "release":
                    result["passed"] = True
                    save(folder / (command_path.stem + ".result.json"), result)
                    break
                if command["action"] == "promote":
                    if args.concurrent_windows:
                        stage = ROOT / "runtime/android-integration-staging"
                        pins = json.loads((stage / "original-pins.json").read_text(encoding="utf-8"))
                        if any((ROOT / name).read_bytes() != (stage / name).read_bytes() for name in pins):
                            raise RuntimeError("Concurrent acceptance requires already-promoted source; no shared runtime edits allowed")
                    runpy.run_path(str(ROOT / "scripts/promote-android-integration.py"))["promote"]()
                    result["passed"] = True
                else:
                    argv = [sys.executable, "-I", "-B", str(ROOT / "scripts/verify-android.py"), "--lease-file", str(folder / "lease.json")]
                    if command.get("smoke"):
                        argv.append("--smoke")
                    log_path = folder / (command_path.stem + ".log")
                    with log_path.open("wb") as log:
                        child = subprocess.Popen(argv, cwd=ROOT, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        lease["test_controller"] = process_pin(child.pid)
                        save(folder / "lease.json", lease)
                        child.wait()
                    result.update(passed=child.returncode == 0, exit_code=child.returncode, log=str(log_path))
            except Exception as error:
                result["error"] = str(error)
            result["finished_at"] = time.time()
            save(folder / (command_path.stem + ".result.json"), result)
            completed.add(command_path.name)
            lease.update(phase="idle")
            lease.pop("test_controller", None)
            save(folder / "lease.json", lease)
            print(json.dumps(result), flush=True)
    finally:
        lease.update(held=False, phase="released")
        save(folder / "lease.json", lease)
        context.__exit__(None, None, None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
