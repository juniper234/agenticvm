"""Run only the fixed, owned, isolated PXE lab; no arbitrary target addresses."""
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agenticvm.pxe_lab import run,CASES
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',choices=CASES,default='happy')
    raise SystemExit(run(parser.parse_args().case))
