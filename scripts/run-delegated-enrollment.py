"""Run one authorized delegated-enrollment lab; accepts no external targets."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from agenticvm.lan_lab import run
from agenticvm.lan_recovery import recover

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=('happy', 'resume', 'bad-hash', 'wrong-grant', 'ssh-unavailable'), default='happy')
    parser.add_argument('--contact-seconds', type=int, default=30)
    parser.add_argument('--recover', metavar='RUN_UUID')
    args = parser.parse_args()
    if args.recover:
        import json
        result = recover(args.recover, delegated=True)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result['passed'] else 1)
    raise SystemExit(run(args.case, delegated=True, contact_seconds=args.contact_seconds))
