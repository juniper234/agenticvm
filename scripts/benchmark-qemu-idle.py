"""Compare one QEMU device variant in a new disposable command VM.

Experimental argv are recorded separately from the controller's normal launch
manifest. This script does not change the shipped controller configuration.
"""
import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.cli import main as cli_main


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("baseline", "no-vga", "no-hpet"), required=True)
    parser.add_argument("--seconds", type=int, default=30, choices=range(5, 61))
    args = parser.parse_args()
    workspace = ROOT / "runtime" / ("idle-" + args.variant + "-" + uuid4().hex[:8])
    workspace.mkdir(parents=True)
    prefix = ["--workspace", str(workspace)]
    original = subprocess.Popen

    def launch(argv, *positional, **keywords):
        if isinstance(argv, list) and "-accel" in argv:
            argv = list(argv)
            if args.variant == "no-vga":
                for index in range(len(argv) - 2, -1, -1):
                    if argv[index] == "-device" and argv[index + 1].startswith("VGA,"):
                        del argv[index:index + 2]
            if args.variant == "no-hpet":
                argv[argv.index("-machine") + 1] = "q35,hpet=off"
            (workspace / "experimental-argv.json").write_text(json.dumps(argv, indent=2) + "\n")
        return original(argv, *positional, **keywords)

    def cli(*argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli_main([*prefix, *argv])
        response = json.loads(buffer.getvalue())
        print(json.dumps(response), flush=True)
        assert code == 0 and response["ok"], response
        return response["result"]

    try:
        with patch("agenticvm.qemu.subprocess.Popen", side_effect=launch):
            cli("start", "--memory", "256")
        cli("exec", "--", "/bin/uname", "-sr")
        cli("exec", "--", "/bin/sh", "-c", "sleep 0.1; printf timer-ok")
        result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/measure-session.py"),
            "--workspace", str(workspace), "--seconds", str(args.seconds), "--output", str(workspace / "measurement.json")],
            cwd=ROOT, check=True, capture_output=True, text=True)
        print(result.stdout, end="")
    finally:
        cli("stop")
    print("Evidence: " + str(workspace))


if __name__ == "__main__":
    main()
