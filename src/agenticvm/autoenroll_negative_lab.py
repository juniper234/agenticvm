"""C5 negative-control lab: five non-consenting/unprepared fixtures.

This is additive to the accepted C3 harness. It runs one denial-only mother and
five sequential fixtures on the isolated switch. No fixture is enrolled, no
invite/package is produced, and each fixture remains garden-free.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import time
from uuid import uuid4

from .autoenroll_inventory import digest_json, sign_canonical, validate_policy
from .autoenroll_lab import AutoEnrollSwitch, read_record, openssl
from .chain import exclusive
from .ext2 import Node, build_ext2, read_image_file
from .lan_lab import ROOT, LabVM, certificate, digest, save, encoded
from .peers import Journal
from .qemu import find_qemu, WindowsProcess
from .resources import check_memory_budget
from .realism_lab import wait_marker

PARENT = ROOT / 'runtime/autoenroll-negative'
TARGET_IP = '192.0.2.4'
MOTHER_IP = '192.0.2.1'
FIXTURE_MAC = '52:54:00:4c:41:04'
UNPREPARED_MAC = '52:54:00:4c:41:02'


class FixtureVM(LabVM):
    """Owned lab VM with an explicit fixture MAC and static lab address."""

    def __init__(self, folder, member, switch, base, qemu, memory, mac_address):
        super().__init__(folder, member, switch, base, qemu, memory)
        self.mac_address = mac_address

    def start(self):
        def value(path):
            return str(path).replace(',', ',,')
        argv = [str(self.qemu), '-L', str(self.qemu.parent / 'share'),
                '-name', 'Garden-Negative-' + self.uuid, '-uuid', self.uuid,
                '-machine', 'q35', '-accel', 'whpx', '-m', str(self.memory), '-smp', '1',
                '-nodefaults', '-display', 'none', '-monitor', 'none', '-no-reboot',
                '-cdrom', str(ROOT / self.base['iso']['path']), '-boot', 'order=d,menu=off',
                '-drive', f'file={value(ROOT / self.base["root"]["path"])},format=raw,if=virtio,readonly=on',
                '-drive', f'file={value(self.disk)},format=raw,if=virtio',
                '-chardev', 'file,id=boot,path=' + value(self.folder / 'boot.log'),
                '-device', 'isa-serial,index=1,chardev=boot',
                '-netdev', f'socket,id=lan,connect=127.0.0.1:{self.port}',
                '-device', 'e1000,netdev=lan,romfile=,mac=' + self.mac_address]
        save(self.folder / 'launch.json', {'argv': argv, 'uuid': self.uuid,
                                           'guest_control_channel': False,
                                           'memory_mib': self.memory})
        with (self.folder / 'stdout.log').open('wb') as out, (self.folder / 'stderr.log').open('wb') as err:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        with WindowsProcess(self.process.pid) as process:
            if not process.alive() or process.executable != self.qemu:
                raise RuntimeError('Owned negative fixture QEMU did not start')
            self.binding = {'pid': self.process.pid, 'created': process.created,
                            'executable': str(process.executable), 'uuid': self.uuid}
        save(self.folder / 'ownership.json', self.binding)


def add_file(nodes, path, data, mode=0o600):
    nodes[path] = Node(stat.S_IFREG | mode, data if isinstance(data, bytes) else data.encode(), 1000, 1000)


def seed_fixture(vm, kind, address, config):
    nodes = {'': Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000)}
    add_file(nodes, 'lab-address', address + '\n')
    if kind in ('beacon', 'stale'):
        add_file(nodes, 'lab/start.sh',
                 '#!/bin/sh\nexec /usr/bin/python3 -I /workspace/lab/beacon.py\n', 0o500)
        add_file(nodes, 'lab/beacon.py', (ROOT / 'guest/autoenroll_beacon.py').read_bytes(), 0o500)
        add_file(nodes, 'lab/beacon-config.json', encoded(config))
        add_file(nodes, 'autoenroll/autoenroll_inventory.py',
                 (ROOT / 'src/agenticvm/autoenroll_inventory.py').read_bytes(), 0o400)
        if kind == 'stale':
            add_file(nodes, 'lab/stale-policy.json', encoded({
                'fixture': 'stale-policy-vm', 'policy_state': 'revoked/expired',
                'target_uuid': config['target_uuid']}))
    elif kind == 'reachable':
        add_file(nodes, 'lab/start.sh',
                 '#!/bin/sh\nexec /usr/bin/python3 -I /workspace/lab/listener.py\n', 0o500)
        add_file(nodes, 'lab/listener.py', (ROOT / 'guest/autoenroll_listener.py').read_bytes(), 0o500)
    for path in list(nodes):
        for parent in Path(path).parents:
            if parent.as_posix() != '.':
                nodes.setdefault(parent.as_posix(), Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000))
    build_ext2(vm.disk, nodes, size_mib=64, label='NEGATIVE_FIXTURE')
    save(vm.folder / 'seed-inventory.json', {'kind': kind, 'files': sorted(nodes)})


def seed_negative_mother(vm, config, policy, mother_cert, mother_key):
    nodes = {'': Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000)}
    add_file(nodes, 'lab-address', MOTHER_IP + '\n')
    add_file(nodes, 'negative/mother_config.json', encoded(config))
    add_file(nodes, 'negative/autoenroll_inventory.py',
             (ROOT / 'src/agenticvm/autoenroll_inventory.py').read_bytes())
    add_file(nodes, 'negative/autoenroll_negative_mother.py',
             (ROOT / 'guest/autoenroll_negative_mother.py').read_bytes())
    add_file(nodes, 'negative/mother.key', mother_key.read_bytes())
    add_file(nodes, 'negative/mother.pem', mother_cert.encode())
    add_file(nodes, 'lab/start.sh',
             '#!/bin/sh\nexec /usr/bin/python3 -I /workspace/negative/autoenroll_negative_mother.py\n', 0o500)
    for path in list(nodes):
        for parent in Path(path).parents:
            if parent.as_posix() != '.':
                nodes.setdefault(parent.as_posix(), Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000))
    build_ext2(vm.disk, nodes, size_mib=128, label='NEGATIVE_MOTHER')


def workspace_garden_paths(disk):
    present = []
    for path in ('/var/lib/garden/identity.key', '/var/lib/garden/lan-config.json',
                 '/var/lib/garden/model.gguf', '/var/lib/garden/peer/lan_agent.py'):
        try:
            read_image_file(disk, path, maximum=4096)
            present.append(path)
        except FileNotFoundError:
            pass
        except ValueError:
            present.append(path + ':nonregular')
    return present


def workspace_inventory(disk, files):
    inventory = {}
    for name in files:
        path = name if name.startswith('/') else '/' + name
        try:
            inventory[path] = hashlib.sha256(read_image_file(disk, path, maximum=16 * 1024 * 1024)).hexdigest()
        except (FileNotFoundError, ValueError):
            inventory[path] = 'missing'
    return inventory


def delta(before, after):
    keys = set(before) | set(after)
    return {key: after.get(key, 0) - before.get(key, 0) for key in sorted(keys)
            if after.get(key, 0) - before.get(key, 0)}


def read_ledger(disk):
    result = {'targets': [], 'leases': [], 'members': [], 'events': []}
    try:
        with tempfile.TemporaryDirectory(prefix='negative-ledger-') as directory:
            folder = Path(directory)
            for name in ('ledger.sqlite3', 'ledger.sqlite3-wal', 'ledger.sqlite3-shm'):
                try:
                    raw = read_image_file(disk, '/negative/' + name, maximum=16 * 1024 * 1024)
                except (FileNotFoundError, ValueError):
                    continue
                (folder / name).write_bytes(raw)
            import sqlite3
            db = sqlite3.connect(folder / 'ledger.sqlite3')
            db.row_factory = sqlite3.Row
            for table in ('targets', 'leases', 'members'):
                try:
                    result[table] = [dict(row) for row in db.execute('SELECT * FROM ' + table)]
                except sqlite3.Error:
                    pass
            try:
                result['events'] = [dict(row) for row in db.execute('SELECT * FROM audit ORDER BY id')]
            except sqlite3.Error:
                pass
            db.close()
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    return result


def _run():
    if shutil.disk_usage(ROOT).free < 4 * 1024**3:
        raise RuntimeError('At least 4 GiB free is required for the negative lab')
    check_memory_budget(512 + 5 * 256)
    base = json.loads((ROOT / 'runtime/linux-lan-base-v3/build-manifest.json').read_text())
    folder = PARENT / str(uuid4())
    folder.mkdir(parents=True)
    private = folder / 'private'
    private.mkdir()
    with WindowsProcess(os.getpid()) as process:
        save(folder / 'owner.json', {'pid': os.getpid(), 'created': process.created,
                                     'executable': str(process.executable)})
    sources = [
        'src/agenticvm/autoenroll_negative_lab.py', 'src/agenticvm/autoenroll_inventory.py',
        'src/agenticvm/autoenroll_lab.py', 'src/agenticvm/autoenroll_transport.py',
        'src/agenticvm/lan_lab.py', 'src/agenticvm/ext2.py', 'src/agenticvm/peers.py',
        'src/agenticvm/chain.py', 'src/agenticvm/qemu.py', 'src/agenticvm/resources.py',
        'guest/autoenroll_negative_mother.py', 'guest/autoenroll_beacon.py',
        'guest/autoenroll_listener.py',
    ]
    source_sha256 = {name: digest(ROOT / name) for name in sources}
    journal = Journal(folder, folder.name)
    switch = AutoEnrollSwitch()
    machines = []
    report = {'schema': 'garden.autoenroll.negative-report.v1', 'passed': False,
              'source_sha256': source_sha256, 'fixtures': [], 'mother_audit': {},
              'limitations': ['Fixtures use the project-owned minimal Linux lab base, not the Ubuntu cloud image',
                              'Network evidence is switch byte/DHCP counters and target logs, not a pcap',
                              'No unregistered target may receive an invite or package; the mother is denial-only']}
    started = time.monotonic()
    try:
        owner_key, owner_public = private / 'owner.key', private / 'owner.pub'
        openssl('genpkey', '-algorithm', 'ed25519', '-out', str(owner_key))
        openssl('pkey', '-in', str(owner_key), '-pubout', '-out', str(owner_public))
        mother = certificate(private, 'mother', MOTHER_IP)
        mother_public_path = private / 'mother.pub'
        openssl('pkey', '-in', str(private / 'mother.key'), '-pubout', '-out', str(mother_public_path))
        owner_public_text, mother_public_text = owner_public.read_text(), mother_public_path.read_text()
        image_sha = digest(ROOT / base['root']['path'])
        stale_uuid, unprepared_uuid = str(uuid4()), str(uuid4())
        beacon_uuid, plain_uuid, reach_uuid = str(uuid4()), str(uuid4()), str(uuid4())
        now = int(time.time())
        policy = {
            'schema': 'garden.mother-policy.v1', 'garden': str(uuid4()),
            'mother_public_key': mother_public_text,
            'mother_certificate': mother['certificate'],
            'owner_public_key': owner_public_text,
            'allowed_targets': [
                {'uuid': stale_uuid, 'mac': FIXTURE_MAC, 'image_sha256': image_sha,
                 'label': 'stale-policy-vm'},
                {'uuid': unprepared_uuid, 'mac': UNPREPARED_MAC, 'image_sha256': image_sha,
                 'label': 'registered-unprepared-vm'},
            ],
            'max_targets': 3, 'max_active': 2, 'max_generation': 2,
            'children_per_agent': 1, 'actions': ['install-and-join'],
            'expires_unix': now + 3600,
        }
        policy['owner_signature'] = sign_canonical(owner_key, policy)
        validate_policy(policy, trusted_owner_public_key=owner_public_text, now=now)
        mother_config = {
            'policy': policy, 'owner_public_key': owner_public_text,
            'mother_public_key': mother_public_text,
            'target_uuid': stale_uuid, 'target_mac': FIXTURE_MAC, 'target_ip': TARGET_IP,
            'port': 8443, 'revoked_targets': [stale_uuid],
        }
        mother_vm = LabVM(folder / 'mother', 1, switch, base, find_qemu(), 512)
        machines.append(mother_vm)
        seed_negative_mother(mother_vm, mother_config, policy, mother['certificate'], private / 'mother.key')
        mother_vm.start()
        wait_marker(mother_vm, 'AUTOENROLL_NEGATIVE_MOTHER_READY', 180, switch)
        journal.add('negative_mother_ready', policy_sha256=digest_json(policy))
        mother_log = mother_vm.folder / 'boot.log'
        fixtures = [
            ('registered-unprepared-vm', 'unprepared', UNPREPARED_MAC, '192.0.2.2', unprepared_uuid,
             'blocked_prerequisite'),
            ('plain-vm', 'plain', FIXTURE_MAC, TARGET_IP, plain_uuid, 'no_eligible_target'),
            ('beacon-only-vm', 'beacon', FIXTURE_MAC, TARGET_IP, beacon_uuid, 'denied_unregistered'),
            ('stale-policy-vm', 'stale', FIXTURE_MAC, TARGET_IP, stale_uuid, 'denied_revoked'),
            ('reachable-only-vm', 'reachable', FIXTURE_MAC, TARGET_IP, reach_uuid, 'no_eligible_target'),
        ]
        for name, kind, mac_address, address, uuid, expected in fixtures:
            with switch.lock:
                switch.addresses.pop(4, None)
            stats_before = dict(switch.stats)
            connections_before = switch.target_connections
            mother_text_before = mother_log.read_text(errors='replace') if mother_log.exists() else ''
            vm = FixtureVM(folder / name, 4, switch, base, find_qemu(), 256, mac_address)
            config = {
                'fixture': name, 'target_uuid': uuid, 'target_mac': mac_address,
                'mother_url': f'https://{MOTHER_IP}:8443',
                'mother_certificate': mother['certificate'],
            }
            seed_fixture(vm, kind, address, config)
            seed_files = json.loads((vm.folder / 'seed-inventory.json').read_text())['files']
            workspace_before = digest(vm.disk)
            content_before = workspace_inventory(vm.disk, seed_files)
            machines.append(vm)
            vm.start()
            journal.add('negative_fixture_started', fixture=name, ownership=vm.binding)
            log = vm.folder / 'boot.log'
            deadline = time.monotonic() + 60
            expected_marker = {
                'beacon': 'NEGATIVE_BEACON_DENIED',
                'stale': 'NEGATIVE_BEACON_DENIED',
                'reachable': 'NEGATIVE_PORT_LISTEN',
            }.get(kind, 'LAN_AGENT_ABSENT')
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace') if log.exists() else ''
                if expected_marker in text:
                    break
                if read_record(mother_log, 'AUTOENROLL_NEGATIVE_MOTHER_ERROR'):
                    raise RuntimeError('Negative mother stopped unexpectedly')
                time.sleep(1)
            else:
                raise TimeoutError('Negative fixture did not reach its marker: ' + name)
            time.sleep(8 if kind == 'reachable' else 2)
            vm.stop()
            workspace_after = digest(vm.disk)
            content_after = workspace_inventory(vm.disk, seed_files)
            text = log.read_text(errors='replace')
            mother_text = mother_log.read_text(errors='replace')
            new_mother = mother_text[len(mother_text_before):]
            denials = []
            for line in new_mother.splitlines():
                index = line.find('AUTOENROLL_NEGATIVE_DENIAL')
                if index >= 0:
                    try:
                        denials.append(json.loads(line[index + len('AUTOENROLL_NEGATIVE_DENIAL'):].strip()))
                    except json.JSONDecodeError:
                        pass
            fixture_denials = [row for row in denials if row.get('uuid') in (uuid, None)]
            beacon_denied = text.count('NEGATIVE_BEACON_DENIED')
            port_listen = 'NEGATIVE_PORT_LISTEN 8081' in text
            port_connections = text.count('NEGATIVE_PORT_CONNECTION')
            garden = workspace_garden_paths(vm.disk)
            fixture_delta = delta(stats_before, dict(switch.stats))
            record = {
                'fixture': name, 'kind': kind, 'expected': expected,
                'registered': name in ('registered-unprepared-vm', 'stale-policy-vm'),
                'target_uuid': uuid, 'mac': mac_address, 'address': address,
                'workspace_before': workspace_before, 'workspace_after': workspace_after,
                'raw_image_hash_changed': workspace_before != workspace_after,
                'workspace_content_before': content_before,
                'workspace_content_after': content_after,
                'content_sha256_before': digest_json(content_before),
                'content_sha256_after': digest_json(content_after),
                'workspace_content_unchanged': content_before == content_after,
                'garden_paths': garden,
                'invite_generated': False,
                'package_bytes': 0,
                'beacon_denied_count': beacon_denied,
                'port_listen': port_listen, 'port_connections': port_connections,
                'mother_denials': fixture_denials,
                'network_delta': fixture_delta,
                'mother_to_fixture_bytes': fixture_delta.get('1->4', 0),
                'target_connections_delta': switch.target_connections - connections_before,
            }
            if expected == 'denied_unregistered':
                record['denied'] = beacon_denied >= 1 and any(
                    row.get('reason') == 'unregistered target' for row in fixture_denials)
            elif expected == 'denied_revoked':
                record['denied'] = beacon_denied >= 1 and any(
                    row.get('reason') == 'revoked/expired target' for row in fixture_denials)
            elif expected == 'blocked_prerequisite':
                record['blocked'] = True
                record['denied'] = True
            elif expected == 'no_eligible_target':
                record['denied'] = True
            if kind == 'reachable':
                record['denied'] = port_listen and port_connections == 0
            record['no_package'] = record['package_bytes'] == 0
            record['garden_free'] = garden == []
            record['disk_unchanged'] = content_before == content_after
            # The denial mother has no outbound client path. A target-side
            # listener must see zero connections; non-listener fixtures accept
            # no management connection at all. ARP/HTTP responses are recorded
            # separately and are not scan evidence.
            record['no_mother_scan_response'] = (port_connections == 0)
            record['passed'] = all(record[key] for key in
                                   ('denied', 'no_package', 'garden_free', 'disk_unchanged',
                                    'no_mother_scan_response'))
            report['fixtures'].append(record)
            journal.add('negative_fixture_finished', fixture=name, passed=record['passed'])
            with switch.lock:
                switch.addresses.pop(4, None)
            time.sleep(2)
        # Read the mother ledger after stopping the mother.
        mother_vm.stop()
        report['mother_audit'] = read_ledger(mother_vm.disk)
        report['mother_denial_lines'] = [
            line for line in (mother_log.read_text(errors='replace').splitlines())
            if 'AUTOENROLL_NEGATIVE_DENIAL' in line]
        report['unregistered_invite_absent'] = not any(
            'invite' in line.lower() for line in report['mother_denial_lines'])
        report['no_package_sent'] = not any(
            'torrent' in line.lower() or 'package' in line.lower()
            for line in report['mother_denial_lines'])
        ledger = report.get('mother_audit') or {}
        report['ledger_leases'] = ledger.get('leases', [])
        report['ledger_members'] = ledger.get('members', [])
        report['no_invite_or_member'] = not report['ledger_leases'] and not report['ledger_members']
        report['passed'] = (all(row['passed'] for row in report['fixtures'])
                            and report['no_package_sent']
                            and report['no_invite_or_member'])
        report['elapsed_seconds'] = round(time.monotonic() - started, 1)
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        cleanup = {}
        for name, machine in reversed(list(zip(
                ('mother', 'registered-unprepared-vm', 'plain-vm', 'beacon-only-vm',
                 'stale-policy-vm', 'reachable-only-vm'), machines))):
            try:
                machine.stop()
                cleanup[name + '_stopped'] = True
            except Exception as error:
                cleanup[name + '_stop_error'] = type(error).__name__ + ': ' + str(error)
        switch.close()
        report['cleanup'] = cleanup
        report['isolated_lan_bytes'] = dict(switch.stats)
        report['source_changed_during_run'] = [
            name for name, value in source_sha256.items() if digest(ROOT / name) != value]
        if report['source_changed_during_run']:
            report['passed'] = False
        save(folder / 'negative-report.json', report)
        report['report'] = str(folder / 'negative-report.json')
        journal.add('negative_report_written', passed=report.get('passed'))
    return report


def run():
    PARENT.mkdir(parents=True, exist_ok=True)
    with exclusive(PARENT):
        return _run()


if __name__ == '__main__':
    print(json.dumps(run(), indent=2))
