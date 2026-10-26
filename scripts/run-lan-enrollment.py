"""Run the bounded same-network enrollment lab; no arbitrary target arguments."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.lan_lab import run
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',choices=('happy','resume','bad-hash','wrong-grant','ssh-unavailable'),default='happy')
    raise SystemExit(run(parser.parse_args().case))
