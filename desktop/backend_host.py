"""Launcher used by the native AgenticVM desktop shell.

The shell sets AGENTICVM_HOME and passes the normal viewer arguments. Keeping
this file tiny means the Windows app can supervise a normal Python process
without embedding command-line quoting in C#.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

ROOT = Path(os.environ.get("AGENTICVM_HOME", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT / "src"))
# Keep private VM control sockets out of inherited, sometimes very long temp
# paths. The launcher supplies this; standalone use retains the normal default.
if os.environ.get("AGENTICVM_APP_DATA") and not os.environ.get("AGENTICVM_SOCKET_ROOT"):
    os.environ["AGENTICVM_SOCKET_ROOT"] = str(ROOT / "runtime/ipc")

from agenticvm.viewer import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
