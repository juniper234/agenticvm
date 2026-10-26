"""Three-target native C6 courier pool lab.

One mother + one courier + three sequential stock Ubuntu targets with distinct
owned MACs and unique policy UUIDs. Target one is cold-booted. The courier
replays each admitted receipt once; the mother must stay idempotent.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
from uuid import uuid4

from .autoenroll_inventory import digest_json, sign_canonical, validate_policy
from .autoenroll_courier_lab import (
    COURIER_IP, MOTHER_IP, TARGET_IP, add_file, issue_cert, mother_certificate,
    parents,
)
from .autoenroll_lab import (
    AutoEnrollSwitch, manifest_for, openssl, package_autoenroll_agent, read_record,
)
from .chain import exclusive
from .ext2 import Node, build_ext2
from .lan_lab import ROOT, LabVM, asset_inputs, digest, save, encoded
from .native_vm import NativeVM, pinned_image, seed_iso
from .peers import Journal
from .qemu import find_qemu, WindowsProcess
from .resources import check_memory_budget

PARENT = ROOT / 'runtime/autoenroll-courier-pool'
TARGET_MACS = ['52:54:00:4c:41:04', '52:54:00:4c:41:06', '52:54:00:4c:41:07']
MEMORY = {'mother': 512, 'courier': 256, 'target': 1024}


class CourierTargetVM(NativeVM):
    def __init__(self, folder, mac_address, *, memory=1024, switch=None):
        super().__init__(folder, 'ubuntu', memory=memory, switch=switch)
        self.mac_address = mac_address

    def start(self, *, seed=None):
        if self.process and self.process.poll() is None:
            raise RuntimeError('Owned target already running')
        if digest(self.base) != self.base_sha256:
            raise ValueError('Target backing image changed')
        self.boot += 1
        log = self.folder / f'boot-{self.boot}.log'
        qemu = find_qemu()
        argv = [str(qemu), '-L', str(qemu.parent / 'share'), '-name', 'Garden-Courier-Target-' + self.uuid,
                '-uuid', self.uuid, '-machine', 'q35', '-accel', 'whpx', '-cpu', 'max',
                '-m', str(self.memory), '-smp', '1', '-nodefaults', '-display', 'none',
                '-monitor', 'none', '-no-reboot', '-serial', 'file:' + str(log),
                '-qmp', 'unix:' + str(self.qmp) + ',server=on,wait=off',
                '-drive', 'file=' + str(self.disk).replace(',', ',,') + ',format=qcow2,if=virtio',
                '-object', 'rng-builtin,id=entropy', '-device', 'virtio-rng-pci,rng=entropy',
                '-netdev', f'socket,id=lan,connect=127.0.0.1:{self.port}',
                '-device', 'e1000,netdev=lan,romfile=,mac=' + self.mac_address]
        if seed:
            argv += ['-cdrom', str(seed)]
        save(self.folder / f'launch-{self.boot}.json', {
            'argv': argv, 'uuid': self.uuid, 'base_sha256': self.base_sha256,
            'mac': self.mac_address})
        with (self.folder / f'stdout-{self.boot}.log').open('wb') as out, \
                (self.folder / f'stderr-{self.boot}.log').open('wb') as err:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as owner:
            if not owner.alive() or owner.executable != qemu:
                raise RuntimeError('Courier target failed to start')
            self.binding = {'pid': self.process.pid, 'created': owner.created,
                            'executable': str(owner.executable), 'uuid': self.uuid}
        save(self.folder / f'ownership-{self.boot}.json', self.binding)
        return log


def seed_pool_mother(vm, folder, config, manifest, cert, key):
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
    add_file(nodes, 'courier/autoenroll_courier_pool_mother.py',
             (ROOT / 'guest/autoenroll_courier_pool_mother.py').read_bytes())
    for name, item in manifest['files'].items():
        source = folder / ('agent.tar.gz' if name == 'agent.tar.gz' else name)
        if not source.exists():
            source = asset_inputs()[name]
        add_file(nodes, 'autoenroll/assets/' + name, source.read_bytes(), 0o400)
    add_file(nodes, 'lab/start.sh',
             '#!/bin/sh\nexec /usr/bin/python3 -I /workspace/courier/autoenroll_courier_pool_mother.py\n', 0o500)
    parents(nodes)
    build_ext2(vm.disk, nodes, size_mib=1024, label='COURIER_POOL_MOTHER')
    save(vm.folder / 'seed-inventory.json', {'files': sorted(nodes), 'disk_sha256': digest(vm.disk)})


def seed_pool_courier(vm, config, courier_pem, courier_key):
    nodes = {'': Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000)}
    add_file(nodes, 'lab-address', COURIER_IP + '\n')
    add_file(nodes, 'courier/courier-config.json', encoded(config))
    add_file(nodes, 'courier/autoenroll_courier_pool.py', (ROOT / 'guest/autoenroll_courier_pool.py').read_bytes())
    add_file(nodes, 'courier/courier.pem', courier_pem.read_bytes())
    add_file(nodes, 'courier/courier.key', courier_key.read_bytes())
    add_file(nodes, 'lab/start.sh',
             '#!/bin/sh\nexec /usr/bin/python3 -I /workspace/courier/autoenroll_courier_pool.py\n', 0o500)
    parents(nodes)
    build_ext2(vm.disk, nodes, size_mib=128, label='COURIER_POOL')
    save(vm.folder / 'seed-inventory.json', {'files': sorted(nodes), 'disk_sha256': digest(vm.disk)})


def target_payloads(folder, policy, owner_public, mother_cert, target_uuid, target_mac):
    config = {
        'schema': 'garden.autoenroll.target-seed.v1', 'garden': policy['garden'],
        'target_uuid': target_uuid, 'target_mac': target_mac,
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
Description=Auto-enrollment Mode B courier pool first boot
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
            'match': {'macaddress': target_mac}, 'dhcp4': False, 'dhcp6': False,
            'addresses': [TARGET_IP + '/24']}}}),
    }


def wait_target(log, mother_log, deadline, switch):
    while time.monotonic() < deadline:
        if switch.errors:
            raise RuntimeError('Courier pool switch failed: ' + str(switch.errors))
        error = read_record(log, 'AUTOENROLL_TARGET_ERROR')
        if error:
            raise RuntimeError('Courier target failed: ' + str(error))
        complete = read_record(log, 'AUTOENROLL_BOOTSTRAP_COMPLETE')
        if complete:
            return complete
        time.sleep(2)
    raise TimeoutError('Courier target did not complete')


def finish_target(vm):
    """Power the guest down through its owned QMP monitor, then stop the owner."""
    try:
        vm.poweroff()
    except Exception:
        pass
    time.sleep(3)
    try:
        vm.stop()
    except Exception:
        vm.poweroff()
        time.sleep(5)
        vm.stop()


def run():
    if shutil.disk_usage(ROOT).free < 8 * 1024**3:
        raise RuntimeError('At least 8 GiB free is required for the courier pool')
    check_memory_budget(sum(MEMORY.values()))
    base = json.loads((ROOT / 'runtime/linux-lan-base-v3/build-manifest.json').read_text())
    PARENT.mkdir(parents=True, exist_ok=True)
    folder = PARENT / str(uuid4())
    folder.mkdir()
    private = folder / 'private'
    private.mkdir()
    switch = AutoEnrollSwitch()
    journal = Journal(folder, folder.name)
    sources = [
        'src/agenticvm/autoenroll_courier_pool_lab.py', 'src/agenticvm/autoenroll_courier_lab.py',
        'src/agenticvm/autoenroll_inventory.py', 'src/agenticvm/autoenroll_lab.py',
        'src/agenticvm/lan_lab.py', 'src/agenticvm/native_vm.py', 'src/agenticvm/realism_lab.py',
        'src/agenticvm/bounded_torrent.py', 'src/agenticvm/qemu.py', 'src/agenticvm/resources.py',
        'src/agenticvm/chain.py', 'src/agenticvm/peers.py', 'src/agenticvm/ext2.py',
        'guest/autoenroll_mother.py', 'guest/autoenroll_bootstrap.py', 'guest/autoenroll_agent.py',
        'guest/local_lfm.py', 'guest/autoenroll_courier_pool_mother.py', 'guest/autoenroll_courier_pool.py',
    ]
    source_sha256 = {name: digest(ROOT / name) for name in sources}
    report = {'schema': 'garden.autoenroll.courier-pool-run.v1', 'passed': False,
              'level': 'native-courier-pool-tested', 'target_count': 3,
              'source_sha256': source_sha256,
              'limitations': ['Three owned local targets, sequential; no physical hardware',
                              'Tampered-invite native denial is not yet included; duplicate receipt replay is']}
    machines = []
    started = time.monotonic()
    try:
        owner_key, owner_public = private / 'owner.key', private / 'owner.pub'
        openssl('genpkey', '-algorithm', 'ed25519', '-out', str(owner_key))
        openssl('pkey', '-in', str(owner_key), '-pubout', '-out', str(owner_public))
        mother = mother_certificate(private)
        courier_key, courier_pem = issue_cert(private, 'courier-1', [COURIER_IP],
                                              ca_cert=private / 'mother.pem', ca_key=private / 'mother.key')
        owner_public_text = owner_public.read_text()
        target_base, target_base_sha = pinned_image('ubuntu')
        target_uuids = [str(uuid4()) for _ in range(3)]
        now = int(time.time())
        allowed = [{'uuid': target_uuids[i], 'mac': TARGET_MACS[i],
                    'image_sha256': target_base_sha, 'label': 'stock-ubuntu-courier-%d' % (i + 1)}
                   for i in range(3)]
        policy = {
            'schema': 'garden.mother-policy.v1', 'garden': str(uuid4()),
            'mother_public_key': mother['public'], 'mother_certificate': mother['certificate'],
            'owner_public_key': owner_public_text, 'allowed_targets': allowed,
            'max_targets': 3, 'max_active': 2, 'max_generation': 1,
            'children_per_agent': 1, 'actions': ['install-and-join'], 'expires_unix': now + 7200,
        }
        policy['owner_signature'] = sign_canonical(owner_key, policy)
        validate_policy(policy, trusted_owner_public_key=owner_public_text, now=now)
        manifest = manifest_for(folder, asset_inputs(), package_autoenroll_agent())
        mother_config = {
            'policy': policy, 'owner_public_key': owner_public_text,
            'mother_public_key': mother['public'], 'target_uuid': target_uuids[0],
            'target_mac': TARGET_MACS[0],
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
        seed_pool_mother(mother_vm, folder, mother_config, manifest, mother['certificate'], mother['key'])
        seed_pool_courier(courier_vm, courier_config, courier_pem, courier_key)
        mother_vm.start()
        courier_vm.start()
        from .realism_lab import wait_marker
        wait_marker(mother_vm, 'AUTOENROLL_COURIER_POOL_MOTHER_READY', 240, switch)
        wait_marker(courier_vm, 'AUTOENROLL_COURIER_POOL_READY', 240, switch)
        journal.add('courier_pool_ready', policy_sha256=digest_json(policy))
        targets = []
        for index, target_uuid in enumerate(target_uuids):
            with switch.lock:
                switch.addresses.pop(4, None)
            target_vm = CourierTargetVM(folder / ('target-%d' % (index + 1)),
                                        TARGET_MACS[index], memory=MEMORY['target'], switch=switch)
            machines.append(target_vm)
            payloads = target_payloads(folder, policy, owner_public_text,
                                       mother['certificate'], target_uuid, TARGET_MACS[index])
            seed = folder / ('seed-%d.iso' % (index + 1))
            seed_iso(seed, payloads)
            target_vm.start(seed=seed)
            log = target_vm.folder / 'boot-1.log'
            complete = wait_target(log, mother_vm.folder / 'boot.log',
                                   time.monotonic() + 1200, switch)
            if complete['receipt']['target_uuid'] != target_uuid:
                raise ValueError('Courier pool receipt target mismatch')
            boot_ids = [complete['agent_ready']['boot_id']]
            if index == 0:
                switch.arm_reboot()
                target_vm.poweroff()
                time.sleep(3)
                target_vm.start()
                cold_boot_id = None
                deadline = time.monotonic() + 240
                while time.monotonic() < deadline:
                    text = (mother_vm.folder / 'boot.log').read_text(errors='replace')
                    lines = [line for line in text.splitlines()
                             if 'AUTOENROLL_COURIER_POOL_STATUS' in line
                             and target_uuid in line]
                    for line in lines:
                        try:
                            payload = json.loads(line[line.find('{'):])
                        except json.JSONDecodeError:
                            continue
                        if payload.get('boots') == 2:
                            cold_boot_id = payload.get('boot_id')
                            break
                    if cold_boot_id:
                        break
                    time.sleep(2)
                if not cold_boot_id:
                    raise TimeoutError('Courier pool target one cold boot status missing')
                boot_ids.append(cold_boot_id)
            targets.append({'target_uuid': target_uuid, 'receipt_sha256': complete['receipt_sha256'],
                            'certificate_sha256': complete['certificate_sha256'],
                            'boot_ids': boot_ids})
            finish_target(target_vm)
            with switch.lock:
                switch.addresses.pop(4, None)
            journal.add('courier_pool_target_complete', target_uuid=target_uuid,
                        target_index=index)
        mother_report = None
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            mother_report = read_record(mother_vm.folder / 'boot.log', 'AUTOENROLL_COURIER_POOL_REPORT')
            if mother_report:
                break
            time.sleep(2)
        if mother_report is None:
            raise TimeoutError('Courier pool mother report missing')
        if len(mother_report['members']) != 3:
            raise ValueError('Courier pool did not admit three members')
        if len(mother_report['sessions']) != 3:
            raise ValueError('Courier pool did not complete three sessions')
        if sum(len(row['boots']) for row in mother_report['sessions']) < 4:
            raise ValueError('Courier pool cold boot/status evidence missing')
        if mother_report['events'][-1]['kind'] != 'member_admitted':
            raise ValueError('Courier pool final event is not member admission')
        courier_log = (courier_vm.folder / 'boot.log').read_text(errors='replace')
        if courier_log.count('AUTOENROLL_COURIER_POOL_REPLAY') < 3:
            raise ValueError('Courier pool duplicate receipt replays missing')
        if 'AUTOENROLL_COURIER_POOL_ERROR' in courier_log:
            raise ValueError('Courier pool emitted an error')
        report.update({'passed': True, 'targets': targets, 'mother_report': mother_report,
                       'courier_replays': courier_log.count('AUTOENROLL_COURIER_POOL_REPLAY'),
                       'elapsed_seconds': round(time.monotonic() - started, 1)})
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        cleanup = {}
        for name, machine in reversed(list(zip(('mother', 'courier', 'target-1', 'target-2', 'target-3'), machines))):
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
        journal.add('courier_pool_report_written', passed=report.get('passed'))
    return report


if __name__ == '__main__':
    print(json.dumps(run(), indent=2))
