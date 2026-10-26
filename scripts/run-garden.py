"""Installed garden entry point, using only the included interpreter/runtime."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.garden import main

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('Sprout could not join: '+str(error),file=sys.stderr,flush=True)
        raise SystemExit(1)
