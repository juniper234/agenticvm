import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.pxe_recovery import recover
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--run',required=True)
    result=recover(parser.parse_args().run);print(json.dumps(result,indent=2));raise SystemExit(0 if result['passed'] else 1)
