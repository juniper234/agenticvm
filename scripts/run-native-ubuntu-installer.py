"""Run actual Subiquity on a fresh owned virtual disk, then verify enrollment."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.native_enrollment import run, CASES
from agenticvm.ubuntu_installer_lab import UbuntuInstallerAdapter

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES, default='happy')
    args = parser.parse_args()
    raise SystemExit(run('ubuntu-autoinstall', args.case, adapter=UbuntuInstallerAdapter()))
