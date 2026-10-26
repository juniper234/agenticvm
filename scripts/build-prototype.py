"""Compile the small guest agent and build its Linux ISO in this workspace."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent


def main():
    compiler = ROOT / "tools/zig/zig-x86_64-windows-0.15.2/zig.exe"
    if not compiler.is_file():
        raise SystemExit("Restore tools first: python -I scripts/prepare-build-tools.py --download")
    lock = json.loads((ROOT / "tools/build-tools-lock.json").read_text(encoding="utf-8"))
    if hashlib.sha256(compiler.read_bytes()).hexdigest() != lock["sources"]["zig"]["exe_sha256"]:
        raise SystemExit("Compiler differs from the pinned build tool lock; restore it first")
    target = ROOT / "runtime/guest-build/agentd"
    target.parent.mkdir(parents=True, exist_ok=True)
    evidence = ROOT / "runtime" / ("build-prototype-" + time.strftime("%Y%m%d-%H%M%S-") + uuid4().hex[:8])
    command = [sys.executable, "-I", str(ROOT / "scripts/run-bounded.py"), "--output", str(evidence), "--",
               str(compiler), "cc", "-target", "x86_64-linux-musl", "-Os", "-static", "-s", "-std=c11",
               "-Wall", "-Wextra", "-Werror", str(ROOT / "guest/agent.c"), "-o", str(target)]
    print("Compiling guest agent with bounded build resources...", file=sys.stderr)
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(result.returncode)
    print("Building verified Linux image...", file=sys.stderr)
    image = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/build-linux-agent.py")], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8")
    if image.returncode:
        sys.stderr.write(image.stdout + image.stderr)
        raise SystemExit(image.returncode)
    manifest = json.loads(image.stdout)
    source_hash = lambda p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
    record = {"agent": manifest["agent"], "image": manifest["output"], "compiler": "Zig 0.15.2 / x86_64-linux-musl",
              "sources": {name: source_hash(name) for name in ("guest/agent.c", "guest/init.sh", "scripts/build-linux-agent.py")},
              "resource_log": str(evidence / "resource-result.json")}
    (evidence / "prototype-build.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
