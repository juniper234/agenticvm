import argparse,sys,warnings
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
warnings.filterwarnings('ignore',category=UserWarning)
from agenticvm.secure_network import run
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--tampered',action='store_true');a=p.parse_args();raise SystemExit(run(a.tampered))
