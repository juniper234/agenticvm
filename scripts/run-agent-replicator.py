"""Isolated native-launcher entry point for finite local agent reproduction."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.replicator import main

if __name__ == '__main__':
    raise SystemExit(main())
