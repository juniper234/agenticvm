"""One-target native C6 courier lab.

Mother (C3 base) + courier VM + one stock Ubuntu target. The target uses the
unchanged C3 bootstrap; only its mother URL points at the courier. The courier
forwards with a mother-issued scoped grant. This is a C6 increment, not the full
three-target pool yet.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
import tarfile
from uuid import uuid4

from .autoenroll_inventory import digest_json, sign_canonical, validate_policy
from .autoenroll_lab import (
    AutoEnrollSwitch, manifest_for, openssl, package_autoenroll_agent, read_record,
)
from .chain import exclusive
from .ext2 import Node, build_ext2
from .lan_lab import ROOT, LabVM, asset_inputs, digest, save, encoded
from .native_vm import NativeVM, pinned_image, seed_iso
from .peers import Journal
from .qemu import find_qemu
from .resources import check_memory_budget

PARENT = ROOT / 'runtime/autoenroll-courier'
MOTHER_IP = '192.0.2.1'
COURIER_IP = '192.0.2.2'
TARGET_IP = '192.0.2.4'
TARGET_MAC = '52:54:00:4c:41:04'
MEMORY = {'mother': 512, 'courier': 256, 'target': 1024}


def add_file(nodes, path, data, mode=0o600):
    nodes[path] = Node(stat.S_IFREG | mode, data if isinstance(data, bytes) else data.encode(), 1000, 1000)


def parents(nodes):
    for path in list(nodes):
        for parent in Path(path).parents:
            if parent.as_posix() != '.':
                nodes.setdefault(parent.as_posix(), Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000))


def issue_cert(folder, name, sans, *, ca_cert=None, ca_key=None):
    key, csr, pem = folder / (name + '.key'), folder / (name + '.csr'), folder / (name + '.pem')
    openssl('genpkey', '-algorithm', 'ed25519', '-out', str(key))
    openssl('req', '-new', '-key', str(key), '-subj', '/CN=' + name, '-out', str(csr))
    ext = folder / (name + '-ext.cnf')
    ext.write_text('basicConstraints=critical,CA:FALSE\n'
                   'keyUsage=critical,digitalSignature,keyEncipherment\n'
                   'extendedKeyUsage=serverAuth,clientAuth\n'
                   'subjectAltName=' + ','.join('IP:' + ip for ip in sans) + '\n')
    args = ['x509', '-req', '-in', str(csr), '-days', '1', '-sha256', '-extfile', str(ext), '-out', str(pem)]
    if ca_cert is None:
        args += ['-signkey', str(key)]
    else:
        args += ['-CA', str(ca_cert), '-CAkey', str(ca_key), '-CAcreateserial']
    openssl(*args)
    return key, pem


def mother_certificate(folder):
    key, pem = folder / 'mother.key', folder / 'mother.pem'
    openssl('req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '1',
            '-keyout', str(key), '-out', str(pem), '-subj', '/CN=mother',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature',
            '-addext', f'subjectAltName=IP:{MOTHER_IP},IP:{COURIER_IP}')
    public = folder / 'mother.pub'
    openssl('pkey', '-in', str(key), '-pubout', '-out', str(public))
    return {'key': key, 'certificate': pem.read_text(), 'public': public.read_text()}


def seed_mother(vm, folder, config, manifest, cert, key):
    nodes = {'': Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000)}
    add_file(nodes, 'lab-address', MOTHER_IP + '\n')
    add_file(nodes, 'autoenroll/mother_config.json', encoded(config))
    add_file(nodes, 'autoenroll/manifest.json', encoded(manifest))
    add_file(nodes, 'autoenroll/autoenroll_inventory.py', (ROOT / 'src/agenticvm/autoenroll_inventory.py').read_bytes())
    add_file(nodes, 'autoenroll/autoenroll_mother.py', (ROOT / 'guest/autoenroll_mother.py').read_bytes())
    add_file(nodes, 'autoenroll/bounded_torrent.py', (ROOT / 'src/agenticvm/bounded_torrent.py').read_bytes())
    add_file(nodes, 'autoenroll/mother.key', key.read_bytes())
    add_file(nodes, 'autoenroll/mother.pem', cert.encode())
    add_file(nodes, 'base/autoenroll_mother.py', (ROOT / 'guest/autoenroll_mother.py').read_bytes())
    add_file(nodes, 'courier/autoenroll_courier_mother.py', (ROOT / 'guest/autoenroll_courier_mother.py').read_bytes())
    for name, item in manifest['files'].items():
        source = folder / ('agent.tar.gz' if name == 'agent.tar.gz' else name)
        if not source.exists():
            source = asset_inputs()[name]
        add_file(nodes, 'autoenroll/assets/' + name, source.read_bytes(), 0o400)
    add_file(nodes, 'lab/start.sh',
             '#!/bin/sh\nexec /usr/bin/python3 -I /workspace/courier/autoenroll_courier_mother.py\n', 0o500)
    parents(nodes)
    build_ext2(vm.disk, nodes, size_mib=1024, label='COURIER_MOTHER')
    save(vm.folder / 'seed-inventory.json', {'files': sorted(nodes), 'disk_sha256': digest(vm.disk)})


def seed_courier(vm, folder, config, courier_pem, courier_key):
    nodes = {'': Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000)}
    add_file(nodes, 'lab-address', COURIER_IP + '\n')
    add_file(nodes, 'courier/courier-config.json', encoded(config))
    add_file(nodes, 'courier/autoenroll_courier.py', (ROOT / 'guest/autoenroll_courier.py').read_bytes())
    add_file(nodes, 'courier/courier.pem', courier_pem.read_bytes())
    add_file(nodes, 'courier/courier.key', courier_key.read_bytes())
    add_file(nodes, 'lab/start.sh',
             '#!/bin/sh\nexec /usr/bin/python3 -I /workspace/courier/autoenroll_courier.py\n', 0o500)
    parents(nodes)
    build_ext2(vm.disk, nodes, size_mib=128, label='COURIER')
    save(vm.folder / 'seed-inventory.json', {'files': sorted(nodes), 'disk_sha256': digest(vm.disk)})


def target_payloads(folder, policy, owner_public, mother_cert, target_uuid):
    config = {
        'schema': 'garden.autoenroll.target-seed.v1', 'garden': policy['garden'],
        'target_uuid': target_uuid, 'target_mac': TARGET_MAC,
        'mother_url': f'https://{COURIER_IP}:8443',
        'mother_certificate': mother_cert,
        'owner_public_key': owner_public, 'policy': policy, 'run_id': folder.name,
    }
    files = {
        '/etc/garden/autoenroll/autoenroll_inventory.py': ((ROOT / 'src/agenticvm/autoenroll_inventory.py').read_text(), '0644'),
        '/etc/garden/autoenroll/autoenroll_bootstrap.py': ((ROOT / 'guest/autoenroll_bootstrap.py').read_text(), '0700'),
        '/etc/garden/autoenroll/bounded_torrent.py': ((ROOT / 'src/agenticvm/bounded_torrent.py').read_text(), '0644'),
        '/etc/garden/autoenroll/target-config.json': (json.dumps(config, sort_keys=True), '0600'),
    }
    unit = '''[Unit]
Description=Auto-enrollment Mode B courier first boot
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
    cfg = {'write_files': [{'path': path, 'permissions': mode, 'content': content}
                           for path, (content, mode) in files.items()],
           'runcmd': [['systemctl', 'daemon-reload'],
                      ['systemctl', 'enable', '--now', 'garden-autoenroll-install.service']]}
    cfg['write_files'].append({'path': '/etc/systemd/system/garden-autoenroll-install.service',
                               'permissions': '0644', 'content': unit})
    return {
        'user-data': ('#cloud-config\n' + json.dumps(cfg)).encode(),
        'meta-data': encoded({'instance-id': folder.name, 'local-hostname': 'garden-autoenroll'}),
        'network-config': encoded({'version': 2, 'ethernets': {'garden': {
            'match': {'macaddress': TARGET_MAC}, 'dhcp4': False, 'dhcp6': False,
            'addresses': [TARGET_IP + '/24']}}}),
    }


def run():
    if shutil.disk_usage(ROOT).free < 6 * 1024**3:
        raise RuntimeError('At least 6 GiB free is required')
    check_memory_budget(sum(MEMORY.values()))
    base = json.loads((ROOT / 'runtime/linux-lan-base-v3/build-manifest.json').read_text())
    PARENT.mkdir(parents=True, exist_ok=True)
    folder = PARENT / str(uuid4())
    folder.mkdir()
    private = folder / 'private'
    private.mkdir()
    switch = AutoEnrollSwitch()
    journal = Journal(folder, folder.name)
    report = {'schema': 'garden.autoenroll.courier-report.v1', 'passed': False,
              'level': 'native-courier-tested', 'target_count': 1,
              'limitations': ['One target only; three-target pool/limits are not yet native',
                              'Fixtures use owned local VMs only']}
    machines = []
    started = time.monotonic()
    try:
        owner_key, owner_public = private / 'owner.key', private / 'owner.pub'
        openssl('genpkey', '-algorithm', 'ed25519', '-out', str(owner_key))
        openssl('pkey', '-in', str(owner_key), '-pubout', '-out', str(owner_public))
        mother = mother_certificate(private)
        courier_key, courier_pem = issue_cert(private, 'courier-1', [COURIER_IP],
                                              ca_cert=private / 'mother.pem', ca_key=private / 'mother.key')
        courier_pem_text = courier_pem.read_text()
        owner_public_text = owner_public.read_text()
        target_base, target_base_sha = pinned_image('ubuntu')
        target_uuid = str(uuid4())
        now = int(time.time())
        policy = {
            'schema': 'garden.mother-policy.v1', 'garden': str(uuid4()),
            'mother_public_key': mother['public'], 'mother_certificate': mother['certificate'],
            'owner_public_key': owner_public_text,
            'allowed_targets': [{'uuid': target_uuid, 'mac': TARGET_MAC,
                                 'image_sha256': target_base_sha, 'label': 'stock-ubuntu-courier'}],
            'max_targets': 3, 'max_active': 2, 'max_generation': 2,
            'children_per_agent': 1, 'actions': ['install-and-join'], 'expires_unix': now + 7200,
        }
        policy['owner_signature'] = sign_canonical(owner_key, policy)
        validate_policy(policy, trusted_owner_public_key=owner_public_text, now=now)
        assets = asset_inputs()
        package = package_autoenroll_agent()
        manifest = manifest_for(folder, assets, package)
        mother_config = {
            'schema': 'garden.autoenroll.mother-seed.v1', 'policy': policy,
            'owner_public_key': owner_public_text, 'mother_public_key': mother['public'],
            'target_uuid': target_uuid, 'target_mac': TARGET_MAC,
            'package_sha256': manifest['files']['agent.tar.gz']['sha256'],
            'model_sha256': manifest['files']['model.gguf']['sha256'],
            'torrent_infohash': manifest['torrent_infohash'],
            'port': 8443, 'status_port': 9443, 'torrent_port': 51413,
        }
        courier_config = {
            'sub_agent': 'courier-1', 'mother_host': MOTHER_IP, 'mother_port': 8443,
            'mother_status_port': 9443, 'listen_port': 8443, 'status_port': 9443,
            'mother_certificate': mother['certificate'],
        }
        mother_vm = LabVM(folder / 'mother', 1, switch, base, find_qemu(), MEMORY['mother'])
        courier_vm = LabVM(folder / 'courier', 2, switch, base, find_qemu(), MEMORY['courier'])
        machines.extend([mother_vm, courier_vm])
        seed_mother(mother_vm, folder, mother_config, manifest, mother['certificate'], mother['key'])
        seed_courier(courier_vm, folder, courier_config, courier_pem, courier_key)
        mother_vm.start()
        courier_vm.start()
        from .realism_lab import wait_marker
        wait_marker(mother_vm, 'AUTOENROLL_COURIER_MOTHER_READY', 240, switch)
        wait_marker(courier_vm, 'AUTOENROLL_COURIER_READY', 240, switch)
        journal.add('courier_ready', policy_sha256=digest_json(policy),
                    courier_cert_sha256=digest(courier_pem))
        payloads = target_payloads(folder, policy, owner_public_text, mother['certificate'], target_uuid)
        seed = folder / 'seed.iso'
        seed_iso(seed, payloads)
        target = NativeVM(folder / 'target', 'ubuntu', memory=MEMORY['target'], switch=switch)
        machines.append(target)
        target.start(seed=seed)
        journal.add('courier_target_started', ownership=target.binding, base_sha256=target.base_sha256)
        first_log = target.folder / 'boot-1.log'
        deadline = time.monotonic() + 1200
        complete = None
        while time.monotonic() < deadline:
            if switch.errors:
                raise RuntimeError('Courier switch failed: ' + str(switch.errors))
            error = read_record(first_log, 'AUTOENROLL_TARGET_ERROR')
            mother_error = read_record(mother_vm.folder / 'boot.log', 'AUTOENROLL_COURIER_MOTHER_ERROR')
            courier_error = read_record(courier_vm.folder / 'boot.log', 'AUTOENROLL_COURIER_ERROR')
            if error:
                raise RuntimeError('Target bootstrap failed: ' + str(error))
            if mother_error:
                raise RuntimeError('Courier mother failed: ' + str(mother_error))
            if courier_error:
                raise RuntimeError('Courier failed: ' + str(courier_error))
            complete = read_record(first_log, 'AUTOENROLL_BOOTSTRAP_COMPLETE')
            if complete:
                break
            time.sleep(2)
        if complete is None:
            raise TimeoutError('Target did not complete courier bootstrap')
        report['target_first_report'] = complete
        if complete['receipt']['target_uuid'] != target_uuid:
            raise ValueError('Receipt target binding mismatch')
        switch.arm_reboot()
        target.poweroff()
        time.sleep(3)
        target.start()
        mother_report = None
        mother_log = mother_vm.folder / 'boot.log'
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            mother_report = read_record(mother_log, 'AUTOENROLL_MOTHER_REPORT')
            if mother_report:
                break
            time.sleep(2)
        if mother_report is None:
            raise TimeoutError('Courier mother did not report after cold boot')
        report['mother_report'] = mother_report
        if mother_report['member']['verified'] != 1:
            raise ValueError('Courier mother did not admit the member')
        if len(mother_report['boots']) < 2:
            raise ValueError('Courier mother did not observe two boots')
        if mother_report['receipt_sha256'] != complete['receipt_sha256']:
            raise ValueError('Courier receipt differs from target receipt')
        if mother_report['certificate_sha256'] != complete['certificate_sha256']:
            raise ValueError('Courier certificate differs from target certificate')
        if not all(row['model'].get('calls', 0) >= 2 for row in mother_report['boots']):
            raise ValueError('Courier target model calls missing')
        if not all(row['service']['active'] for row in mother_report['boots']):
            raise ValueError('Courier target service inactive')
        courier_lines = (courier_vm.folder / 'boot.log').read_text(errors='replace')
        if 'AUTOENROLL_COURIER_DELIVERED' not in courier_lines:
            raise ValueError('Courier did not deliver an invite')
        report.update({
            'passed': True, 'native_os_observed': True, 'target_uuid': target_uuid,
            'policy_sha256': digest_json(policy), 'invite_sha256': mother_report['invite_sha256'],
            'receipt_sha256': mother_report['receipt_sha256'],
            'target_boot_ids': [row['boot_id'] for row in mother_report['boots']],
            'courier_delivered': True, 'courier_cert_sha256': digest(courier_pem),
            'elapsed_seconds': round(time.monotonic() - started, 1),
        })
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        cleanup = {}
        for name, machine in reversed(list(zip(('mother', 'courier', 'target'), machines))):
            try:
                machine.stop()
                cleanup[name + '_stopped'] = True
            except Exception as error:
                cleanup[name + '_stop_error'] = type(error).__name__ + ': ' + str(error)
        switch.close()
        report['cleanup'] = cleanup
        report['source_changed_during_run'] = []
        save(folder / 'report.json', report)
        report['report'] = str(folder / 'report.json')
        journal.add('courier_report_written', passed=report.get('passed'))
    return report


if __name__ == '__main__':
    print(json.dumps(run(), indent=2))
