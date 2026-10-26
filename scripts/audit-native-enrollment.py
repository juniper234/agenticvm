"""Independently re-read one completed native enrollment run."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.native_evidence import verify

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('--historical', action='store_true')
    args = parser.parse_args()
    receipt = verify(ROOT / 'runtime/native-enrollment-runs' / args.run_id, current=not args.historical)
    print(json.dumps({'passed': True, 'current_source_required': not args.historical,
                      'route': receipt['route'], 'case': receipt.get('case', 'happy'), 'level': receipt['level']}))
