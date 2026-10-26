"""Finite authorized enrollment coverage, with explicit fidelity and prerequisites.

Variants sharing an execution mechanism are not counted as new mechanisms.
An adapter/contract test never becomes a native or hardware acceptance result.
"""
from __future__ import annotations
import re

ROUTES = (
    ('ssh-linux', 'Preauthorized Linux SSH', 'existing-os', 'local-linux'),
    ('ssh-delegated-torrent', 'Delegated SSH plus private BitTorrent', 'existing-os', 'local-linux'),
    ('pxe-bios', 'Legacy BIOS PXE/iPXE', 'firmware', 'local-linux'),
    ('pxe-uefi', 'UEFI PXE/iPXE', 'firmware', 'local-linux'),
    ('uefi-secure-boot', 'Owner-provisioned Secure Boot network image', 'firmware', 'local-linux'),
    ('uefi-http', 'Native UEFI HTTP boot', 'firmware', 'local-linux'),
    ('cloud-init-local', 'cloud-init NoCloud configuration drive', 'first-boot', 'local-linux'),
    ('cloud-init-network', 'cloud-init NoCloud network metadata', 'first-boot', 'local-linux'),
    ('ignition-local', 'Ignition QEMU firmware configuration', 'first-boot', 'local-linux'),
    ('ignition-network', 'Ignition verified remote configuration', 'first-boot', 'local-linux'),
    ('ubuntu-autoinstall', 'Ubuntu native unattended installation', 'installer', 'local-linux-installer'),
    ('debian-preseed', 'Debian installer preseed', 'installer', 'local-linux-installer'),
    ('anaconda-kickstart', 'Anaconda/Kickstart unattended installation', 'installer', 'local-linux-installer'),
    ('autoyast', 'openSUSE AutoYaST unattended installation', 'installer', 'local-linux-installer'),
    ('windows-unattend', 'Windows unattended Setup', 'installer', 'local-windows'),
    ('windows-openssh', 'Windows native OpenSSH', 'existing-os', 'local-windows'),
    ('windows-winrm', 'Windows WinRM/PowerShell remoting', 'existing-os', 'local-windows'),
    ('windows-gpo', 'AD computer-assigned software/startup policy', 'managed-fleet', 'local-domain'),
    ('mdm-required-app', 'MDM required application deployment', 'managed-fleet', 'cloud-tenant'),
    ('redfish', 'Redfish power/boot/virtual media', 'out-of-band', 'local-controller-emulation'),
    ('ipmi', 'IPMI virtual management controller', 'out-of-band', 'local-controller-emulation'),
    ('intel-amt', 'Intel AMT owner-configured management', 'out-of-band', 'physical-amt'),
    ('autopilot-self-deploy', 'Windows Autopilot self-deploying mode', 'managed-first-boot', 'physical-tpm-and-tenant'),
    ('apple-ade', 'Apple Automated Device Enrollment/Auto Advance', 'managed-first-boot', 'physical-mac-and-tenant'),
    ('azure-extension', 'Azure VM Agent extension', 'cloud-management', 'cloud-tenant'),
    ('aws-ssm', 'AWS Systems Manager Run Command', 'cloud-management', 'cloud-tenant'),
    ('guest-agent', 'Authorized hypervisor guest agent', 'hypervisor-management', 'local-linux'),
    ('managed-pull', 'Pre-enrolled signed-job pull service', 'managed-fleet', 'local-linux'),
)

STAGES = ('catalogued', 'adapter-built', 'contract-tested', 'native-bootstrap-tested',
          'native-enrollment-tested', 'reboot-tested', 'fault-suite-tested')


def catalog():
    return [{'id': ident, 'name': name, 'family': family, 'resource': resource,
             'stage': 'catalogued', 'receipts': [], 'unmet_prerequisites': []}
            for ident, name, family, resource in ROUTES]


def validate_receipt(receipt):
    required = {'route', 'level', 'passed', 'source_sha256', 'evidence', 'limitations'}
    if not isinstance(receipt, dict) or not required <= set(receipt):
        raise ValueError('An inspectable route receipt is required')
    if receipt['route'] not in {row[0] for row in ROUTES}:
        raise ValueError('Unknown enrollment route')
    if receipt['level'] not in STAGES[1:] or type(receipt['passed']) is not bool:
        raise ValueError('Unknown or ambiguous acceptance level')
    if (not isinstance(receipt['limitations'], list) or any(not isinstance(item, str) for item in receipt['limitations'])
            or not isinstance(receipt['source_sha256'], dict) or not receipt['source_sha256']):
        raise ValueError('Source pins and limitations must be explicit')
    for path, pin in receipt['source_sha256'].items():
        if (not isinstance(path, str) or '\\' in path or ':' in path or path.startswith('/')
                or any(part in ('', '.', '..') for part in path.split('/'))
                or not isinstance(pin, str) or re.fullmatch('[0-9a-f]{64}', pin) is None):
            raise ValueError('Invalid receipt source pin or workspace path')
    if not isinstance(receipt['evidence'], list) or receipt['passed'] and not receipt['evidence']:
        raise ValueError('A passed receipt needs inspectable evidence')
    if STAGES.index(receipt['level']) >= STAGES.index('native-bootstrap-tested') and receipt.get('native_os_observed') is not True:
        raise ValueError('Native acceptance requires real OS observations')
    if receipt['passed'] and receipt['level'] in ('reboot-tested', 'fault-suite-tested'):
        if type(receipt.get('native_cold_boots')) is not int or receipt['native_cold_boots'] < 2:
            raise ValueError('Reboot acceptance requires two observed cold boots')
    return receipt
