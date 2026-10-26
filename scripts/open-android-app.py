"""Open the native app with a separate Android workspace; no VM auto-start."""
from pathlib import Path
import argparse
import json
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path)
    args = parser.parse_args()
    executable = ROOT / "AgenticVM.exe"
    if not executable.is_file():
        executable = ROOT / "dist/AgenticVM-Android/AgenticVM.exe"
    if not executable.is_file():
        raise RuntimeError("The Android portable app has not been packaged yet")
    candidates = [args.data_dir] if args.data_dir else []
    if os.environ.get("LOCALAPPDATA"):
        candidates.append(Path(os.environ["LOCALAPPDATA"]) / "AgenticVM-Android")
    candidates.append(executable.parent / "runtime/android-app")
    selected = None
    for candidate in candidates:
        try:
            candidate = candidate.resolve()
            workspace = candidate / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            preference = workspace / "viewer-profile-desktop-app.json"
            if not preference.exists():
                with preference.open("x", encoding="utf-8") as stream:
                    json.dump({"profile": "android"}, stream)
            with (candidate / "app.log").open("ab"):
                pass
            selected = candidate
            break
        except OSError:
            continue
    if selected is None:
        raise RuntimeError("No writable Android app workspace was available")
    environment = os.environ.copy()
    environment["AGENTICVM_APP_DATA"] = str(selected)
    bundled_python = executable.parent / "bundle/python/python.exe"
    if bundled_python.is_file():
        environment["AGENTICVM_PYTHON"] = str(bundled_python)
    with (selected / "app.log").open("ab") as log:
        process = subprocess.Popen([str(executable)], cwd=executable.parent, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    receipt = {"pid": process.pid, "executable": str(executable), "data_directory": str(selected), "started_at": time.time(), "auto_start_vm": False}
    (selected / "app-launch.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
