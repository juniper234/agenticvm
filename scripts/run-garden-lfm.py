"""One-file LFM garden entry point; no system Python or model provider needed."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.garden import main

if __name__ == '__main__':
    try:
        raise SystemExit(main(['--lfm',*sys.argv[1:]]))
    except Exception as error:
        print('LFM sprout could not join: '+str(error),file=sys.stderr,flush=True)
        raise SystemExit(1)
