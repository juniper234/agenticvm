import argparse,sys,warnings
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
warnings.filterwarnings('ignore',message='pkg_resources is deprecated as an API.*',category=UserWarning)
from agenticvm.enrollment_realism import enroll
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--profile',choices=('uefi-stock-rng','uefi-e1000','uefi-e1000e','uefi-virtio','bios-default'),default='uefi-virtio')
    p.add_argument('--contact-seconds',type=int,default=120)
    p.add_argument('--secure-boot',action='store_true')
    a=p.parse_args();raise SystemExit(enroll(a.profile,contact_seconds=a.contact_seconds,secure=a.secure_boot))
