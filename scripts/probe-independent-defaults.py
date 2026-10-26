import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.independent_lab import probe
from agenticvm.independent_recovery import require_clean_history
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--no-server',action='store_true')
    require_clean_history()
    raise SystemExit(probe(not parser.parse_args().no_server))
