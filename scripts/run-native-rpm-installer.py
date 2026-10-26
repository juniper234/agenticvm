"""Run a real owned Linux installer when the pinned DVD and host resources exist."""
import argparse
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.native_enrollment import run, CASES
from agenticvm.rpm_installer_lab import RPMInstallerAdapter

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--route', choices=('anaconda-kickstart', 'autoyast'), required=True)
    parser.add_argument('--case', choices=CASES, default='happy')
    args = parser.parse_args()
    raise SystemExit(run(args.route, args.case, adapter=RPMInstallerAdapter(args.route)))
