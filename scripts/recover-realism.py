import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.realism_recovery import recover
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--run',required=True);a=p.parse_args()
    result=recover(a.run);print(json.dumps(result,indent=2));raise SystemExit(0 if result['passed'] else 1)
