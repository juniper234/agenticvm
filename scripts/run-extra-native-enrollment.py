"""Run an explicit local management adapter against one owned native VM."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.native_enrollment import run, CASES
from agenticvm.redfish_lab import RedfishAdapter
from agenticvm.guest_agent_lab import GuestAgentAdapter
from agenticvm.managed_pull_lab import ManagedPullAdapter
from agenticvm.debian_installer_lab import DebianInstallerAdapter
from agenticvm.ipmi_lab import IPMIAdapter
from agenticvm.ubuntu_installer_lab import UbuntuInstallerAdapter
from agenticvm.rpm_installer_lab import RPMInstallerAdapter

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--route', choices=('redfish', 'ipmi', 'guest-agent', 'managed-pull', 'debian-preseed',
        'ubuntu-autoinstall', 'anaconda-kickstart', 'autoyast'), default='redfish')
    parser.add_argument('--case', choices=CASES, default='happy')
    args = parser.parse_args()
    if args.route in ('anaconda-kickstart', 'autoyast'):
        adapter = RPMInstallerAdapter(args.route)
    else:
        adapter = {'redfish': RedfishAdapter, 'guest-agent': GuestAgentAdapter, 'managed-pull': ManagedPullAdapter,
                   'debian-preseed': DebianInstallerAdapter, 'ipmi': IPMIAdapter,
                   'ubuntu-autoinstall': UbuntuInstallerAdapter}[args.route]()
    raise SystemExit(run(args.route, args.case, adapter=adapter))
