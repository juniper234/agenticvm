"""Run real Windows evaluation Setup on one owned disposable local VM."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.windows_enrollment import run, CASES
from agenticvm.windows_recovery import recover

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES, default='happy')
    parser.add_argument('--recover')
    args = parser.parse_args()
    if args.recover:
        import json
        value = recover(args.recover)
        print(json.dumps(value, indent=2))
        raise SystemExit(0 if value['passed'] else 1)
    raise SystemExit(run(args.case))
