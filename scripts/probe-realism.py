"""Run one bounded owned firmware/DHCP compatibility case."""
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agenticvm.realism_lab import probe,PROFILES
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--profile',choices=PROFILES,default='uefi-e1000')
    p.add_argument('--delay-dhcp',type=int,choices=range(0,31),default=0)
    a=p.parse_args();raise SystemExit(probe(a.profile,a.delay_dhcp))
