"""Independent read-back of the local management mechanism used by each run."""
from __future__ import annotations
import json
from pathlib import Path
import sys

from .lan_lab import ROOT, OPENSSL, digest
from .native_evidence import verify as verify_native


def verify(folder):
    folder = Path(folder)
    receipt = verify_native(folder)
    route, case = receipt['route'], receipt['case']
    positive = case in ('happy', 'resume')
    evidence = receipt['adapter_evidence']
    launch = json.loads((folder / 'target/launch-1.json').read_text())
    target_uuid = launch['uuid']
    if route in ('redfish', 'ipmi', 'guest-agent'):
        expected = {'redfish': 'redfish-operations.json', 'ipmi': 'ipmi-operations.json', 'guest-agent': 'guest-agent-operations.json'}[route]
        if evidence['path'] != expected or digest(folder / expected) != evidence['sha256']:
            raise ValueError('Native management protocol evidence changed')
        protocol = json.loads((folder / expected).read_text())
    if route == 'redfish':
        if protocol['target_uuid'] != target_uuid or protocol['physical_bmc_tested']:
            raise ValueError('Redfish emulator scope/fidelity changed')
        resets = [row['body']['ResetType'] for row in protocol['events'] if row['path'].endswith('/ComputerSystem.Reset')]
        if resets != (['On', 'GracefulShutdown', 'On'] if positive else ['On']):
            raise ValueError('Redfish did not perform the declared power sequence')
        if any(row['tls'] != 'TLSv1.3' for row in protocol['events']):
            raise ValueError('Redfish controller traffic lacks pinned TLS 1.3 evidence')
        if digest(folder / 'seed.iso') != protocol['virtual_media_sha256']:
            raise ValueError('Redfish configuration media changed')
    elif route == 'ipmi':
        if protocol['target_uuid'] != target_uuid or protocol['bind_address'] != '::1' or protocol['physical_bmc_tested'] or protocol['errors']:
            raise ValueError('IPMI emulator scope/fidelity/backend failed')
        operations = [row['operation'] for row in protocol['events']]
        if operations != (['status', 'boot-disk', 'on', 'softoff', 'boot-disk', 'on'] if positive else ['status', 'boot-disk', 'on']):
            raise ValueError('IPMI did not perform the declared power sequence')
        if any(row['target_uuid'] != target_uuid or row['authentication_type'] != 6 or row['integrity'] != 1 or row['privacy'] != 'aes' for row in protocol['events']):
            raise ValueError('IPMI authentication/integrity/privacy evidence missing')
    elif route == 'guest-agent':
        executed = [row for row in protocol['events'] if row['command'] == 'guest-exec']
        if len(executed) != 1 or executed[0]['target_uuid'] != target_uuid or launch['guest_control_exec_channel'] is not True:
            raise ValueError('Guest-agent did not use exactly one declared management invocation')
        if positive and (not protocol['process_completed'] or protocol['events'][-1]['result'].get('exitcode') != 0):
            raise ValueError('Guest-agent bootstrap did not complete successfully')
    elif route == 'managed-pull':
        path = folder / 'signed-pull-job.json'
        if digest(path) != evidence['job_evidence_sha256']:
            raise ValueError('Signed pull job evidence changed')
        material = json.loads(path.read_text())
        sys.path.insert(0, str(ROOT / 'guest'))
        from managed_pull import verify_signature
        verify_signature(material['envelope']['job'], material['envelope']['signature'], material['public_key'], openssl=OPENSSL)
        if positive and not evidence['signed_job_completed']:
            raise ValueError('Signed pull job did not complete')
        if positive and 'MANAGED_PULL_COMPLETE ' in (folder / 'target/boot-2.log').read_text(errors='replace'):
            raise ValueError('Signed pull job replayed on the second boot')
    elif route in ('debian-preseed', 'ubuntu-autoinstall', 'anaconda-kickstart', 'autoyast'):
        transition = folder / 'installer-transition.json'
        if not evidence['native_installer_completed'] or digest(transition) != evidence['transition_sha256']:
            raise ValueError('Native installer completion evidence missing')
        moved = json.loads(transition.read_text())
        if moved['installer_exit_code'] != 0 or moved['target_uuid'] != target_uuid or not launch['blank_target_disk']:
            raise ValueError('Native installation was not observed on a fresh owned disk')
        if digest(folder / 'target/boot-1.log') != moved['installer_console_sha256']:
            raise ValueError('Native installer console evidence changed')
        if positive and (evidence['installed_os_boots'] != 2 or receipt['target_nic_connections'] != 3):
            raise ValueError('Installer boot was incorrectly counted as an installed-OS boot')
    else:
        raise ValueError('Unknown local management route')
    if positive:
        installer = route in ('debian-preseed', 'ubuntu-autoinstall', 'anaconda-kickstart', 'autoyast')
        last = json.loads((folder / ('target/launch-' + str(3 if installer else 2) + '.json')).read_text())
        if any(option in last['argv'] for option in ('-cdrom', '-kernel', '-initrd', '-fw_cfg', '-smbios')):
            raise ValueError('Final installed OS boot still required provisioning inputs')
    return receipt
