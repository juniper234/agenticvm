"""Hold one owned Android guest for bounded diagnostics inside the lab reservation."""
from pathlib import Path
import argparse
import json
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.android import AndroidBackend, AndroidStore, owned_process


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lease-file", type=Path, required=True)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--persistent", action="store_true")
    args = parser.parse_args()
    lease = json.loads(args.lease_file.read_text())
    if not lease["held"] or lease["phase"] != "idle":
        raise RuntimeError("Android debug requires an idle native resource reservation")
    with owned_process(lease["owner"]) as owner:
        if not owner.alive():
            raise RuntimeError("Resource reservation owner exited")
    folder = ROOT / "runtime/android-debug" / str(uuid4())
    folder.mkdir(parents=True)
    backend = AndroidBackend(AndroidStore(args.workspace or folder / "workspace"))
    print(json.dumps({"folder": str(folder), "phase": "booting"}), flush=True)
    try:
        result = backend.start(memory=2560, persistent=args.persistent, network=args.network, timeout=240, campaign_locked=True)
        (folder / "ready.json").write_text(json.dumps(result, indent=2))
        print(json.dumps({"folder": str(folder), "phase": "ready"}), flush=True)
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline and not (folder / "stop").exists():
            time.sleep(0.5)
    finally:
        result = backend.stop()
        (folder / "cleanup.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
