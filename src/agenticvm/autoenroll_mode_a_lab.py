"""Mode A bootstrap-listener lab.

Phase 1 bakes only the garden-autoenroll listener, its config, policy and
inventory/torrent support into a stock Ubuntu disk. No agent, model or identity
is present. Phase 2 boots the same disk with no seed; the enabled listener runs,
receives and verifies the mother invite, installs, joins, and cold-boots.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import time
from uuid import uuid4

from .autoenroll_inventory import digest_json, sign_canonical, validate_policy
from .autoenroll_lab import (
    MEMORY, MOTHER_IP, PARENT, TARGET_MAC,
    AutoEnrollSwitch, asset_inputs, manifest_for, openssl, package_autoenroll_agent,
    read_record, seed_mother, write_mother_config,
)
from .chain import exclusive
from .lan_lab import ROOT, LabVM, certificate, digest, save, encoded
from .native_vm import NativeVM, pinned_image, seed_iso
from .peers import Journal
from .qemu import find_qemu
from .realism_lab import DHCPVM, preflight as dhcp_preflight, wait_marker
from .resources import check_memory_budget

MODE_A_PARENT = ROOT / 'runtime/autoenroll-mode-a'


def bake_payloads(folder, policy, owner_public, mother_cert, target_uuid):
    config = {
        'schema': 'garden.autoenroll.target-seed.v1',
        'garden': policy['garden'],
        'target_uuid': target_uuid,
        'target_mac': TARGET_MAC,
        'mother_url': f'https://{MOTHER_IP}:8443',
        'mother_certificate': mother_cert,
        'owner_public_key': owner_public,
        'policy': policy,
        'run_id': folder.name,
    }
    files = {
        '/etc/garden/autoenroll/autoenroll_inventory.py': ((ROOT / 'src/agenticvm/autoenroll_inventory.py').read_text(), '0644'),
        '/etc/garden/autoenroll/autoenroll_bootstrap.py': ((ROOT / 'guest/autoenroll_mode_a_bootstrap.py').read_text(), '0700'),
        '/etc/garden/autoenroll/bounded_torrent.py': ((ROOT / 'src/agenticvm/bounded_torrent.py').read_text(), '0644'),
        '/etc/garden/autoenroll/target-config.json': (json.dumps(config, sort_keys=True), '0600'),
    }
    unit = '''[Unit]
Description=Garden Mode A bootstrap listener
After=network-online.target
Wants=network-online.target
ConditionPathExists=!/var/lib/garden/autoenroll-complete.json
[Service]
Type=exec
ExecStart=/usr/bin/python3 -I -B /etc/garden/autoenroll/autoenroll_bootstrap.py
TimeoutStartSec=900
RuntimeMaxSec=900
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
'''
    files['/etc/systemd/system/garden-autoenroll-listener.service'] = (unit, '0644')
    cfg = {'write_files': [{'path': path, 'permissions': mode, 'content': content}
                           for path, (content, mode) in files.items()],
           'runcmd': [['systemctl', 'daemon-reload'],
                      ['systemctl', 'enable', 'garden-autoenroll-listener.service'],
                      ['sh', '-c', 'echo MODE_A_BAKE_READY > /dev/console']]}
    return {
        'user-data': ('#cloud-config\n' + json.dumps(cfg)).encode(),
        'meta-data': encoded({'instance-id': folder.name, 'local-hostname': 'garden-mode-a'}),
        'network-config': encoded({'version': 2, 'ethernets': {'garden': {
            'match': {'macaddress': TARGET_MAC}, 'dhcp4': True, 'dhcp6': False}}}),
    }


def run():
    if shutil.disk_usage(ROOT).free < 6 * 1024**3:
        raise RuntimeError('At least 6 GiB free is required for Mode A')
    check_memory_budget(MEMORY['mother'] + MEMORY['dhcp'] + MEMORY['target'])
    base = json.loads((ROOT / 'runtime/linux-lan-base-v3/build-manifest.json').read_text())
    dhcp_base = dhcp_preflight()
    MODE_A_PARENT.mkdir(parents=True, exist_ok=True)
    folder = MODE_A_PARENT / str(uuid4())
    folder.mkdir()
    private = folder / 'private'
    private.mkdir()
    switch = AutoEnrollSwitch()
    journal = Journal(folder, folder.name)
    sources = [
        'src/agenticvm/autoenroll_mode_a_lab.py', 'src/agenticvm/autoenroll_lab.py',
        'src/agenticvm/autoenroll_inventory.py', 'src/agenticvm/lan_lab.py',
        'src/agenticvm/native_vm.py', 'src/agenticvm/realism_lab.py',
        'src/agenticvm/bounded_torrent.py', 'src/agenticvm/qemu.py',
        'src/agenticvm/resources.py', 'src/agenticvm/chain.py', 'src/agenticvm/peers.py',
        'src/agenticvm/ext2.py', 'guest/autoenroll_mother.py',
        'guest/autoenroll_bootstrap.py', 'guest/autoenroll_mode_a_bootstrap.py',
        'guest/autoenroll_agent.py', 'guest/local_lfm.py',
    ]
    source_sha256 = {name: digest(ROOT / name) for name in sources}
    report = {'schema': 'garden.autoenroll.mode-a-report.v1', 'passed': False,
              'level': 'native-mode-a-tested', 'mode': 'A-bootstrap-listener',
              'source_sha256': source_sha256,
              'limitations': ['One owned local target; physical hardware untested',
                              'Listener image is the stock Ubuntu disk plus only the bootstrap service/config',
                              'Negative-control evidence is the C5 native suite; no new Mode A denial fixture in this run']}
    machines = []
    started = time.monotonic()
    try:
        owner_key, owner_public = private / 'owner.key', private / 'owner.pub'
        openssl('genpkey', '-algorithm', 'ed25519', '-out', str(owner_key))
        openssl('pkey', '-in', str(owner_key), '-pubout', '-out', str(owner_public))
        mother = certificate(private, 'mother', MOTHER_IP)
        mother_public_path = private / 'mother.pub'
        openssl('pkey', '-in', str(private / 'mother.key'), '-pubout', '-out', str(mother_public_path))
        owner_public_text = owner_public.read_text()
        mother_public_text = mother_public_path.read_text()
        target_base, target_base_sha = pinned_image('ubuntu')
        target_uuid = str(uuid4())
        now = int(time.time())
        policy = {
            'schema': 'garden.mother-policy.v1', 'garden': str(uuid4()),
            'mother_public_key': mother_public_text,
            'mother_certificate': mother['certificate'],
            'owner_public_key': owner_public_text,
            'allowed_targets': [{'uuid': target_uuid, 'mac': TARGET_MAC,
                                 'image_sha256': target_base_sha, 'label': 'mode-a-listener'}],
            'max_targets': 3, 'max_active': 2, 'max_generation': 2,
            'children_per_agent': 1, 'actions': ['install-and-join'],
            'expires_unix': now + 7200,
        }
        policy['owner_signature'] = sign_canonical(owner_key, policy)
        validate_policy(policy, trusted_owner_public_key=owner_public_text, now=now)
        manifest = manifest_for(folder, asset_inputs(), package_autoenroll_agent())
        mother_config = write_mother_config(folder, policy, owner_public_text, mother_public_text,
                                             target_uuid, manifest,
                                             manifest['files']['agent.tar.gz']['sha256'],
                                             manifest['files']['model.gguf']['sha256'])
        mother_vm = LabVM(folder / 'mother', 1, switch, base, find_qemu(), MEMORY['mother'])
        dhcp = DHCPVM(folder / 'dhcp', 5, switch, dhcp_base, find_qemu(), MEMORY['dhcp'])
        machines.extend([mother_vm, dhcp])
        seed_mother(mother_vm, folder, mother_config, manifest, mother['certificate'], private / 'mother.key')
        dhcp.start()
        wait_marker(dhcp, 'REALISM_DHCP_APPLIANCE_READY', 60, switch)
        mother_vm.start()
        wait_marker(mother_vm, 'AUTOENROLL_MOTHER_READY', 240, switch)

        target = NativeVM(folder / 'target', 'ubuntu', memory=MEMORY['target'], switch=switch)
        machines.append(target)
        bake_seed = folder / 'bake.iso'
        seed_iso(bake_seed, bake_payloads(folder, policy, owner_public_text,
                                          mother['certificate'], target_uuid))
        target.start(seed=bake_seed)
        bake_log = target.folder / 'boot-1.log'
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if switch.errors:
                raise RuntimeError('Mode A bake switch failed: ' + str(switch.errors))
            if target.process and target.process.poll() is not None:
                raise RuntimeError('Mode A bake target exited: '
                                   + (target.folder / 'stderr-1.log').read_text(errors='replace')[-800:])
            if bake_log.exists() and 'MODE_A_BAKE_READY' in bake_log.read_text(errors='replace'):
                break
            time.sleep(1)
        else:
            raise TimeoutError('Mode A bake marker missing')
        journal.add('mode_a_baked', target_uuid=target_uuid, base_sha256=target_base_sha)
        switch.arm_reboot()
        target.poweroff()
        time.sleep(3)
        report['bake_files'] = ['/etc/garden/autoenroll/autoenroll_inventory.py',
                                '/etc/garden/autoenroll/autoenroll_bootstrap.py',
                                '/etc/garden/autoenroll/bounded_torrent.py',
                                '/etc/garden/autoenroll/target-config.json',
                                '/etc/systemd/system/garden-autoenroll-listener.service']

        # No seed on this boot: the enabled listener runs from the baked image.
        target.start()
        journal.add('mode_a_listener_booted', ownership=target.binding)
        first_log = target.folder / 'boot-2.log'
        deadline = time.monotonic() + 1200
        complete = None
        while time.monotonic() < deadline:
            if switch.errors:
                raise RuntimeError('Mode A switch failed: ' + str(switch.errors))
            error = read_record(first_log, 'AUTOENROLL_TARGET_ERROR')
            mother_error = read_record(mother_vm.folder / 'boot.log', 'AUTOENROLL_MOTHER_ERROR')
            if error:
                raise RuntimeError('Mode A listener failed: ' + str(error))
            if mother_error:
                raise RuntimeError('Mode A mother failed: ' + str(mother_error))
            complete = read_record(first_log, 'AUTOENROLL_BOOTSTRAP_COMPLETE')
            if complete:
                break
            time.sleep(2)
        if complete is None:
            raise TimeoutError('Mode A listener did not complete')
        if any(complete['initial_absence'].values()):
            raise ValueError('Mode A target was not initially garden-free')
        if complete['receipt']['zero_click'] is not True or complete['receipt']['interactive_input'] is not False:
            raise ValueError('Mode A zero-click/no-input proof failed')
        report['target_first_report'] = complete
        journal.add('mode_a_listener_complete', target_uuid=target_uuid)
        switch.arm_reboot()
        target.poweroff()
        time.sleep(3)
        target.start()
        mother_report = None
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            mother_report = read_record(mother_vm.folder / 'boot.log', 'AUTOENROLL_MOTHER_REPORT')
            if mother_report:
                break
            time.sleep(2)
        if mother_report is None:
            raise TimeoutError('Mode A mother report missing')
        if len(mother_report['boots']) < 2:
            raise ValueError('Mode A cold boot/status missing')
        if not all(row['service']['active'] for row in mother_report['boots']):
            raise ValueError('Mode A service inactive')
        if not all(row['model'].get('calls', 0) >= 2 for row in mother_report['boots']):
            raise ValueError('Mode A model calls missing')
        if mother_report['member']['verified'] != 1:
            raise ValueError('Mode A mother did not admit the member')
        if mother_report['receipt_sha256'] != complete['receipt_sha256']:
            raise ValueError('Mode A receipt mismatch')
        if mother_report['certificate_sha256'] != complete['certificate_sha256']:
            raise ValueError('Mode A certificate mismatch')
        report.update({'passed': True, 'native_mode_a_observed': True,
                       'target_uuid': target_uuid, 'policy_sha256': digest_json(policy),
                       'invite_sha256': mother_report['invite_sha256'],
                       'receipt_sha256': mother_report['receipt_sha256'],
                       'boot_ids': [row['boot_id'] for row in mother_report['boots']],
                       'mother_report': mother_report,
                       'elapsed_seconds': round(time.monotonic() - started, 1)})
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        cleanup = {}
        for name, machine in reversed(list(zip(('mother', 'dhcp', 'target'), machines))):
            try:
                machine.stop()
                cleanup[name + '_stopped'] = True
            except Exception as error:
                cleanup[name + '_stop_error'] = type(error).__name__ + ': ' + str(error)
        switch.close()
        report['cleanup'] = cleanup
        report['source_changed_during_run'] = [name for name, value in source_sha256.items()
                                               if digest(ROOT / name) != value]
        if report['source_changed_during_run']:
            report['passed'] = False
        save(folder / 'report.json', report)
        report['report'] = str(folder / 'report.json')
        journal.add('mode_a_report_written', passed=report.get('passed'))
    return report


if __name__ == '__main__':
    print(json.dumps(run(), indent=2))
