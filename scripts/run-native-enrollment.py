"""Run one real cloud-init/Ignition garden acceptance profile."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from agenticvm.native_enrollment import ROUTES, CASES, run

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--route', choices=ROUTES, default='cloud-init-local')
    parser.add_argument('--case', choices=CASES, default='happy')
    parser.add_argument('--recover', metavar='RUN_UUID')
    args = parser.parse_args()
    if args.recover:
        import json
        from agenticvm.native_recovery import recover
        result = recover(args.recover)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result['passed'] else 1)
    raise SystemExit(run(args.route, args.case))
