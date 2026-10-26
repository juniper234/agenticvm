"""C3 native Mother-direct Mode B auto-enrollment harness (one stock VM).

Owned local lab only: one lightweight mother VM, one DHCP appliance and one
stock Ubuntu target on an isolated virtual switch. No physical NIC, no scan, no
console input. The target receives a signed NoCloud seed, verifies the owner
policy and mother invite, downloads only through the pinned private torrent,
installs as UID 1000, joins over mTLS, and is admitted by the mother.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import tarfile
import threading
import time
from uuid import uuid4

from .autoenroll_inventory import (
    canonical, digest_json, sign_canonical, validate_policy,
)
from .bounded_torrent import metadata
from .chain import exclusive
from .ext2 import Node, build_ext2
from .lan_lab import (
    ROOT, LabVM, certificate, asset_inputs, digest, save, encoded, OPENSSL,
)
from .native_vm import NativeVM, seed_iso, pinned_image
from .peers import Journal
from .qemu import find_qemu, WindowsProcess
from .realism_lab import FaultSwitch, DHCPVM, FrameDecoder, wait_marker, preflight as dhcp_preflight
from .resources import check_memory_budget

PARENT = ROOT / 'runtime/autoenroll-runs'
TARGET_MAC = '52:54:00:4c:41:04'
TARGET_IP = '192.0.2.4'
MOTHER_IP = '192.0.2.1'
MEMORY = {'mother': 512, 'dhcp': 256, 'target': 1536}


class AutoEnrollSwitch(FaultSwitch):
    """Owned target port may reconnect after the single cold reboot."""

    def __init__(self):
        super().__init__()
        self.reboot_allowed = False
        self.target_connections = 0

    def arm_reboot(self):
        self.reboot_allowed = True

    def _serve(self, member, listener):
        from .independent_lab import dhcp_event
        while not self.stop.is_set():
            conn = None
            try:
                while not self.stop.is_set():
                    try:
                        conn, _ = listener.accept()
                        break
                    except socket.timeout:
                        continue
                if conn is None:
                    return
                conn.settimeout(.5)
                with self.lock:
                    self.ports[member] = (conn, threading.Lock())
                    if member == 4:
                        self.target_connections += 1
                decoder = FrameDecoder()
                while not self.stop.is_set():
                    try:
                        raw = conn.recv(65536)
                    except socket.timeout:
                        continue
                    if not raw:
                        break
                    for frame in decoder.feed(raw):
                        source = frame[6:12]
                        with self.lock:
                            if member not in self.addresses:
                                if member != 4 or source[0] & 1 or source in self.addresses.values():
                                    raise ValueError('Invalid owned target MAC')
                                self.addresses[member] = source
                            if self.addresses[member] != source:
                                raise ValueError('Owned port hardware identity changed')
                            event = dhcp_event(frame)
                            if event and len(self.dhcp) < 256:
                                self.dhcp.append({**event, 'elapsed_seconds': round(time.monotonic() - self.begin, 3)})
                            dest = next((n for n, address in self.addresses.items() if address == frame[:6]), None)
                            targets = []
                            for n, pair in self.ports.items():
                                if n == member or dest is not None and dest != n:
                                    continue
                                if member in self.blocked or n in self.blocked:
                                    self.drops += 1
                                    continue
                                targets.append((n, pair))
                                key = f'{member}->{n}'
                                self.stats[key] = self.stats.get(key, 0) + len(frame)
                        packet = struct.pack('!I', len(frame)) + frame
                        for n, (peer, guard) in targets:
                            try:
                                with guard:
                                    peer.sendall(packet)
                            except OSError:
                                if n != 4 or not self.reboot_allowed:
                                    raise
            except OSError as error:
                if not self.stop.is_set() and not (member == 4 and self.reboot_allowed):
                    self.errors.append(str(error))
            except Exception as error:
                self.errors.append(type(error).__name__ + ': ' + str(error))
            finally:
                with self.lock:
                    self.ports.pop(member, None)
                if conn:
                    conn.close()
            if member != 4:
                return


def openssl(*args):
    result = subprocess.run([str(OPENSSL), *args], capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Host OpenSSL failed: ' + result.stderr[-800:])
    return result


def package_autoenroll_agent():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as package:
        for name in ('autoenroll_agent.py', 'local_lfm.py'):
            text = (ROOT / 'guest' / name).read_text().replace('/workspace', '/var/lib/garden')
            data = text.encode()
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime = len(data), 0o500, 0
            package.addfile(item, io.BytesIO(data))
    return output.getvalue()


def manifest_for(folder, assets, package):
    paths = {'agent.tar.gz': folder / 'agent.tar.gz', **assets}
    (folder / 'agent.tar.gz').write_bytes(package)
    files = {}
    for name, path in paths.items():
        files[name] = {'bytes': path.stat().st_size, 'sha256': digest(path),
                       'torrent': metadata(path, name=name)}
    infohash = digest_json({name: {'bytes': item['bytes'], 'sha256': item['sha256']}
                            for name, item in sorted(files.items())})
    return {
        'schema': 'garden.autoenroll.package.v1',
        'files': files,
        'torrent_infohash': infohash,
        'peer': MOTHER_IP,
        'port': 51413,
        'trackers': [],
        'dht': False,
        'pex': False,
    }


def write_mother_config(folder, policy, owner_public, mother_public, target_uuid,
                        manifest, package_sha, model_sha):
    config = {
        'schema': 'garden.autoenroll.mother-seed.v1',
        'policy': policy,
        'owner_public_key': owner_public,
        'mother_public_key': mother_public,
        'target_uuid': target_uuid,
        'target_mac': TARGET_MAC,
        'package_sha256': package_sha,
        'model_sha256': model_sha,
        'torrent_infohash': manifest['torrent_infohash'],
        'port': 8443,
        'status_port': 9443,
        'torrent_port': 51413,
    }
    save(folder / 'mother-config.json', config)
    return config


def seed_mother(vm, folder, config, manifest, mother_cert, mother_key):
    nodes = {'': Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000)}

    def add(path, data, mode=0o600):
        nodes[path] = Node(stat.S_IFREG | mode, data, 1000, 1000)

    add('lab-address', (MOTHER_IP + '\n').encode())
    add('autoenroll/mother_config.json', encoded(config))
    add('autoenroll/manifest.json', encoded(manifest))
    add('autoenroll/autoenroll_inventory.py', (ROOT / 'src/agenticvm/autoenroll_inventory.py').read_bytes())
    add('autoenroll/autoenroll_mother.py', (ROOT / 'guest/autoenroll_mother.py').read_bytes())
    add('autoenroll/bounded_torrent.py', (ROOT / 'src/agenticvm/bounded_torrent.py').read_bytes())
    add('autoenroll/mother.key', mother_key.read_bytes())
    add('autoenroll/mother.pem', mother_cert.encode())
    for name, item in manifest['files'].items():
        source = folder / ('agent.tar.gz' if name == 'agent.tar.gz' else name)
        if not source.exists():
            source = asset_inputs()[name]
        add('autoenroll/assets/' + name, source.read_bytes(), 0o400)
    add('lab/start.sh', b'#!/bin/sh\nexport LLAMA_ARG_REPACK=0\nexec /usr/bin/python3 -I /workspace/autoenroll/autoenroll_mother.py\n', 0o500)
    for path in list(nodes):
        for parent in Path(path).parents:
            if parent.as_posix() != '.':
                nodes.setdefault(parent.as_posix(), Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000))
    build_ext2(vm.disk, nodes, size_mib=1024, label='AUTOENROLL_MOTHER')
    save(vm.folder / 'seed-inventory.json', {'files': sorted(nodes), 'disk_sha256': digest(vm.disk)})


def target_payloads(folder, policy, owner_public, mother_cert, target_uuid):
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
    inventory = (ROOT / 'src/agenticvm/autoenroll_inventory.py').read_text()
    bootstrap = (ROOT / 'guest/autoenroll_bootstrap.py').read_text()
    torrent = (ROOT / 'src/agenticvm/bounded_torrent.py').read_text()
    unit = '''[Unit]
Description=Auto-enrollment Mode B first boot
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
    files = {
        '/etc/garden/autoenroll/autoenroll_inventory.py': (inventory, '0644'),
        '/etc/garden/autoenroll/autoenroll_bootstrap.py': (bootstrap, '0700'),
        '/etc/garden/autoenroll/bounded_torrent.py': (torrent, '0644'),
        '/etc/garden/autoenroll/target-config.json': (json.dumps(config, sort_keys=True), '0600'),
    }
    cfg = {
        'write_files': [{'path': path, 'permissions': mode, 'content': content}
                        for path, (content, mode) in files.items()],
        'runcmd': [['systemctl', 'daemon-reload'],
                   ['systemctl', 'enable', '--now', 'garden-autoenroll-install.service']],
    }
    cfg['write_files'].append({'path': '/etc/systemd/system/garden-autoenroll-install.service',
                               'permissions': '0644', 'content': unit})
    payload = {
        'user-data': ('#cloud-config\n' + json.dumps(cfg)).encode(),
        'meta-data': encoded({'instance-id': folder.name, 'local-hostname': 'garden-autoenroll'}),
        'network-config': encoded({'version': 2, 'ethernets': {'garden': {
            'match': {'macaddress': TARGET_MAC}, 'dhcp4': True, 'dhcp6': False}}}),
    }
    return payload


def read_record(path, prefix):
    if not path.exists():
        return None
    for line in reversed(path.read_text(errors='replace').splitlines()):
        index = line.find(prefix)
        if index < 0:
            continue
        payload = line[index + len(prefix):].lstrip()
        if not payload.startswith('{'):
            continue
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            continue
    return None


def wait_record(path, prefix, deadline, switch):
    while time.monotonic() < deadline:
        if switch.errors:
            raise RuntimeError('Auto-enrollment switch failed: ' + str(switch.errors))
        record = read_record(path, prefix)
        if record is not None:
            return record
        time.sleep(1)
    raise TimeoutError('Timed out waiting for ' + prefix + ' in ' + str(path))


def _run(case='happy'):
    if case != 'happy':
        raise ValueError('C3 currently implements only the mother-direct happy case')
    if shutil.disk_usage(ROOT).free < 6 * 1024**3:
        raise RuntimeError('At least 6 GiB free is required for the auto-enrollment fixture')
    check_memory_budget(sum(MEMORY.values()))
    base = json.loads((ROOT / 'runtime/linux-lan-base-v3/build-manifest.json').read_text())
    dhcp_base = dhcp_preflight()
    folder = PARENT / str(uuid4())
    folder.mkdir(parents=True)
    with WindowsProcess(os.getpid()) as process:
        save(folder / 'owner.json', {'pid': os.getpid(), 'created': process.created,
                                     'executable': str(process.executable)})
    journal, switch = Journal(folder, folder.name), AutoEnrollSwitch()
    private = folder / 'private'
    private.mkdir()
    sources = [
        'src/agenticvm/autoenroll_lab.py', 'src/agenticvm/autoenroll_inventory.py',
        'src/agenticvm/autoenroll_transport.py', 'src/agenticvm/lan_lab.py',
        'src/agenticvm/native_vm.py', 'src/agenticvm/realism_lab.py',
        'src/agenticvm/bounded_torrent.py', 'src/agenticvm/qemu.py',
        'src/agenticvm/resources.py', 'src/agenticvm/chain.py', 'src/agenticvm/peers.py',
        'src/agenticvm/ext2.py', 'guest/autoenroll_mother.py',
        'guest/autoenroll_bootstrap.py', 'guest/autoenroll_agent.py', 'guest/local_lfm.py',
    ]
    source_sha256 = {name: digest(ROOT / name) for name in sources}
    report = {
        'route': 'autoenroll-mother-direct', 'case': case,
        'level': 'native-autoenroll-tested', 'passed': False,
        'native_os_observed': False, 'source_sha256': source_sha256,
        'evidence': [], 'limitations': [
            'One owned local target; physical hardware and a real 4 GB host are untested',
            'Mother-direct Mode B only; courier, Mode A, negative-control fixtures and UI are not claimed',
            'The target receives a signed NoCloud seed from the owner-controlled hypervisor',
        ],
    }
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
            'schema': 'garden.mother-policy.v1',
            'garden': str(uuid4()),
            'mother_public_key': mother_public_text,
            'mother_certificate': mother['certificate'],
            'owner_public_key': owner_public_text,
            'allowed_targets': [{'uuid': target_uuid, 'mac': TARGET_MAC,
                                 'image_sha256': target_base_sha, 'label': 'stock-ubuntu-autoenroll'}],
            'max_targets': 3, 'max_active': 2, 'max_generation': 2,
            'children_per_agent': 1, 'actions': ['install-and-join'],
            'expires_unix': now + 7200,
        }
        policy['owner_signature'] = sign_canonical(owner_key, policy)
        validate_policy(policy, trusted_owner_public_key=owner_public_text, now=now)
        assets = asset_inputs()
        package = package_autoenroll_agent()
        manifest = manifest_for(folder, assets, package)
        save(folder / 'asset-manifest.json', manifest)
        mother_config = write_mother_config(folder, policy, owner_public_text, mother_public_text,
                                             target_uuid, manifest,
                                             manifest['files']['agent.tar.gz']['sha256'],
                                             manifest['files']['model.gguf']['sha256'])
        mother_vm = LabVM(folder / 'mother', 1, switch, base, find_qemu(), MEMORY['mother'])
        machines.append(mother_vm)
        seed_mother(mother_vm, folder, mother_config, manifest, mother['certificate'], private / 'mother.key')
        dhcp = DHCPVM(folder / 'dhcp', 5, switch, dhcp_base, find_qemu(), MEMORY['dhcp'])
        machines.append(dhcp)
        dhcp.start()
        wait_marker(dhcp, 'REALISM_DHCP_APPLIANCE_READY', 60, switch)
        mother_vm.start()
        wait_marker(mother_vm, 'AUTOENROLL_MOTHER_READY', 240, switch)
        journal.add('autoenroll_mother_ready', ownership=mother_vm.binding,
                    policy_sha256=digest_json(policy))
        payloads = target_payloads(folder, policy, owner_public_text, mother['certificate'], target_uuid)
        seed = folder / 'seed.iso'
        seed_iso(seed, payloads)
        target = NativeVM(folder / 'target', 'ubuntu', memory=MEMORY['target'], switch=switch)
        machines.append(target)
        target.start(seed=seed)
        journal.add('autoenroll_target_started', ownership=target.binding, base_sha256=target.base_sha256)
        first_log = target.folder / 'boot-1.log'
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            if switch.errors:
                raise RuntimeError('Auto-enrollment switch failed: ' + str(switch.errors))
            error = read_record(first_log, 'AUTOENROLL_TARGET_ERROR')
            mother_error = read_record(mother_vm.folder / 'boot.log', 'AUTOENROLL_MOTHER_ERROR')
            if error:
                raise RuntimeError('Target bootstrap failed: ' + str(error))
            if mother_error:
                raise RuntimeError('Mother failed: ' + str(mother_error))
            complete = read_record(first_log, 'AUTOENROLL_BOOTSTRAP_COMPLETE')
            if complete:
                break
            if shutil.disk_usage(ROOT).free < 1536 * 1024**2:
                raise RuntimeError('Native test stopped to preserve host disk headroom')
            time.sleep(2)
        else:
            raise TimeoutError('Target first boot did not complete')
        report['target_first_report'] = complete
        journal.add('autoenroll_bootstrap_complete', target_uuid=target_uuid)
        first_ready = complete['agent_ready']
        if complete['initial_absence'] and any(complete['initial_absence'].values()):
            raise ValueError('Target was not initially garden-free')
        if complete['receipt']['zero_click'] is not True or complete['receipt']['interactive_input'] is not False:
            raise ValueError('Receipt does not prove zero-click/no-input')
        if complete['receipt']['target_uuid'] != target_uuid:
            raise ValueError('Receipt target binding mismatch')
        switch.arm_reboot()
        target.poweroff()
        journal.add('autoenroll_target_powered_off')
        time.sleep(3)
        target.start()
        journal.add('autoenroll_cold_boot_started', boot=target.boot)
        second_log = target.folder / 'boot-2.log'
        mother_log = mother_vm.folder / 'boot.log'
        mother_report = wait_record(mother_log, 'AUTOENROLL_MOTHER_REPORT', time.monotonic() + 900, switch)
        boots = mother_report.get('boots') or []
        second_boot = next((row for row in boots if row.get('boot_id') != first_ready['boot_id']), None)
        if second_boot is None:
            raise ValueError('Mother did not observe a second boot')
        second_ready = {
            'boot_id': second_boot['boot_id'],
            'identity_fingerprint': mother_report['member']['identity_fingerprint'],
        }
        if 'garden-autoenroll.service' not in second_log.read_text(errors='replace'):
            raise ValueError('Cold boot did not start the auto-enrollment service')
        report['target_second_ready'] = second_ready
        report['mother_report'] = mother_report
        if second_ready['boot_id'] == first_ready['boot_id']:
            raise ValueError('Cold boot did not change the target boot ID')
        if second_ready['identity_fingerprint'] != first_ready['identity_fingerprint']:
            raise ValueError('Cold boot changed the target identity')
        if len(mother_report['boots']) < 2:
            raise ValueError('Mother did not observe two target boots')
        if mother_report['member']['verified'] != 1:
            raise ValueError('Mother did not admit the member')
        if mother_report['receipt_sha256'] != complete['receipt_sha256']:
            raise ValueError('Mother receipt differs from the target receipt')
        if mother_report['invite']['target_uuid'] != target_uuid:
            raise ValueError('Mother invite target binding mismatch')
        if mother_report['policy_sha256'] != digest_json(policy):
            raise ValueError('Mother policy hash mismatch')
        if mother_report['certificate_sha256'] != complete['certificate_sha256']:
            raise ValueError('Issued certificate hash mismatch')
        if not all(row['service']['active'] for row in mother_report['boots']):
            raise ValueError('Auto-enrollment service was not active on both boots')
        if not all(row['model'].get('calls', 0) >= 2 for row in mother_report['boots']):
            raise ValueError('Model completions were not observed on both boots')
        if mother_report['torrent']['payload_bytes_sent'] < sum(
                item['bytes'] for item in complete['torrent_receipts']):
            raise ValueError('Private torrent seeder bytes are below the receipts')
        if switch.target_connections < 2:
            raise ValueError('Target did not reconnect after the cold reboot')
        if read_record(second_log, 'AUTOENROLL_TARGET_ERROR') or read_record(mother_log, 'AUTOENROLL_MOTHER_ERROR'):
            raise ValueError('Unexpected error marker on the cold boot')
        report.update(
            passed=True, native_os_observed=True,
            target_uuid=target_uuid, policy_sha256=digest_json(policy),
            invite_sha256=mother_report['invite_sha256'],
            receipt_sha256=mother_report['receipt_sha256'],
            target_public_key_sha256=first_ready['identity_fingerprint'],
            target_boot_ids=[first_ready['boot_id'], second_ready['boot_id']],
            target_boot_mode='mode-b-signed-seed',
            target_initial_absence=complete['initial_absence'],
            target_zero_click=complete['receipt']['zero_click'],
            target_interactive_input=complete['receipt']['interactive_input'],
            torrent_receipts=complete['torrent_receipts'],
            torrent_seeder=mother_report['torrent'],
            mother_admitted=mother_report['member']['verified'],
            mother_events=mother_report['events'],
            target_certificate_sha256=complete['certificate_sha256'],
            target_connections=switch.target_connections,
            cleanup={'target_stopped': False, 'mother_stopped': False, 'dhcp_stopped': False},
        )
        report['evidence'] = [str((folder / 'asset-manifest.json').relative_to(ROOT)),
                              str((folder / 'mother-config.json').relative_to(ROOT))]
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['failure_stage'] = 'native'
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
        report['isolated_lan_bytes'] = dict(switch.stats)
        report['target_nic_connections'] = switch.target_connections
        report['elapsed_seconds'] = round(time.monotonic() - started, 1)
        changed = [name for name, value in source_sha256.items()
                   if digest(ROOT / name) != value]
        report['source_changed_during_run'] = changed
        if changed:
            report['passed'] = False
            report['error'] = 'Source changed during native run: ' + ', '.join(changed)
        save(folder / 'report.json', report)
        report['report'] = str(folder / 'report.json')
        journal.add('autoenroll_report_written', passed=report.get('passed'))
    return report


def run(case='happy'):
    PARENT.mkdir(parents=True, exist_ok=True)
    with exclusive(PARENT):
        return _run(case)


if __name__ == '__main__':
    print(json.dumps(run(), indent=2))
