"""Native cloud-init/Ignition OS enrollment, persistent service and cold reboot."""
from __future__ import annotations
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import struct
import tarfile
import threading
import time
from uuid import uuid4

from . import realism_lab
from .chain import exclusive
from .ext2 import Node, build_ext2
from .lan_lab import ROOT, LabVM, certificate, asset_inputs, encoded, digest, save, completed_guest_report, MODEL_SHA
from .native_vm import NativeVM, seed_iso
from .peers import Journal, verify_journal
from .qemu import WindowsProcess, find_qemu
from .resources import check_memory_budget

PARENT = ROOT / 'runtime/native-enrollment-runs'
ROUTES = ('cloud-init-local', 'cloud-init-network', 'ignition-local', 'ignition-network')
CASES = ('happy', 'resume', 'bad-hash', 'wrong-grant', 'bad-bootstrap')


class ExpectedDenial(Exception):
    pass


def os_id(text):
    return next((line.split('=', 1)[1].strip().strip('"') for line in text.splitlines() if line.startswith('ID=')), None)


def verify_denial(case, proof, kind):
    expected = {'bad-hash': 'Asset integrity verification failed',
                'wrong-grant': 'HTTP Error 403', 'bad-bootstrap': 'Native installer digest failed before execution'}
    if case not in expected or expected[case] not in proof['error']:
        raise ValueError('Failure is not the deliberate native test fault')
    if (set(proof['activation_paths']) != {'peer/lan_agent.py', 'model.gguf', 'identity.key', 'lan-config.json'}
            or any(proof['activation_paths'].values()) or proof['agent_service_active'] or proof['uid'] != 0
            or os_id(proof['native_os']) != {'ubuntu': 'ubuntu', 'coreos': 'fedora', 'debian': 'debian', 'fedora': 'fedora', 'opensuse': 'opensuse-leap'}[kind]
            or not proof['boot_id']):
        raise ValueError('Native denial did not prevent agent/model/identity activation')
    return True


class ReconnectingSwitch(realism_lab.FaultSwitch):
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
                decoder = realism_lab.FrameDecoder()
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
                                # An ACPI cold reboot closes only target's TCP
                                # NIC. Seed connections must survive that event.
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


def package_agent():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as package:
        for name in ('lan_agent.py', 'local_lfm.py'):
            text = (ROOT / 'guest' / name).read_text().replace('/workspace', '/var/lib/garden')
            if name == 'lan_agent.py':
                if text.count("if __name__=='__main__':") != 1:
                    raise ValueError('Reviewed agent entry point changed')
                text = text.split("if __name__=='__main__':", 1)[0]
                text += '''
_BaseNode=Node
class Node(_BaseNode):
    def snapshot(self):
        value=super().snapshot()
        value.update(native_boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                     uid=os.getuid(),native_os_release=Path('/etc/os-release').read_text(),
                     native_selinux_enforcing=Path('/sys/fs/selinux/enforce').read_text().strip()=='1' if Path('/sys/fs/selinux/enforce').exists() else None)
        return value
if __name__=='__main__': main()
'''
            data = text.encode()
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime = len(data), 0o500, 0
            package.addfile(item, io.BytesIO(data))
    return output.getvalue()


def native_config(route, run_id, public, runtime):
    trust = {'mother_certificate': public['mother']['certificate'], 'installer_sha256': digest(ROOT / 'guest/lan_install.py')}
    shell = '''#!/bin/sh
set -eu
umask 077
mkdir -p /var/lib/garden
if [ ! -x /usr/bin/python3 ]; then
  curl --fail --silent --show-error --tlsv1.3 --max-time 180 --cacert /etc/garden/mother.pem https://192.0.2.1:8443/native/runtime -o /var/lib/garden/runtime.tar.gz
  printf '%s  %s\\n' RUNTIME_SHA /var/lib/garden/runtime.tar.gz | sha256sum -c -
  tar -xzf /var/lib/garden/runtime.tar.gz -C /var/lib/garden
  chown -R 1000:1000 /var/lib/garden/runtime
  python=/var/lib/garden/runtime/python
else
  python=/usr/bin/python3
fi
exec "$python" -I -B /etc/garden/bootstrap.py
'''.replace('RUNTIME_SHA', runtime['sha256'])
    unit = '''[Unit]
Description=Native authorized garden first boot
After=network-online.target
Wants=network-online.target
ConditionPathExists=!/var/lib/garden/native-install-complete.json
[Service]
Type=exec
ExecStart=/bin/sh /etc/garden/bootstrap.sh
TimeoutStartSec=480
RuntimeMaxSec=480
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
'''
    files = {'/etc/garden/bootstrap.sh': (shell, '0700'),
             '/etc/garden/bootstrap.py': ((ROOT / 'guest/native_bootstrap.py').read_text(), '0600'),
             '/etc/garden/trust.json': (json.dumps(trust), '0600'),
             '/etc/garden/mother.pem': (public['mother']['certificate'], '0644')}
    prefix = '/seed/' + run_id + '/'
    if route.startswith('cloud-init'):
        cfg = {'write_files': [{'path': path, 'permissions': mode, 'content': content} for path, (content, mode) in files.items()],
               'runcmd': [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', 'garden-native-install.service']]}
        cfg['write_files'].append({'path': '/etc/systemd/system/garden-native-install.service', 'permissions': '0644', 'content': unit})
        payload = {'user-data': ('#cloud-config\n' + json.dumps(cfg)).encode(),
                   'meta-data': encoded({'instance-id': run_id, 'local-hostname': 'garden-native'}),
                   'network-config': encoded({'version': 2, 'ethernets': {'garden': {'match': {'macaddress': '52:54:00:4c:41:04'},
                                                'dhcp4': True, 'dhcp6': False}}})}
        return payload, {prefix + name: base64.b64encode(data).decode() for name, data in payload.items()}
    cfg = {'ignition': {'version': '3.4.0'}, 'storage': {'files': [
        {'path': path, 'mode': int(mode, 8), 'contents': {'source': 'data:text/plain;base64,' + base64.b64encode(content.encode()).decode()}}
        for path, (content, mode) in files.items()]},
        'systemd': {'units': [{'name': 'garden-native-install.service', 'enabled': True, 'contents': unit}]}}
    full = encoded(cfg)
    if route == 'ignition-local':
        return {'config.ign': full}, {}
    path = '/ignition/' + run_id + '.json'
    initial = {'ignition': {'version': '3.4.0', 'config': {'replace': {'source': 'http://192.0.2.1:8080' + path,
                         'verification': {'hash': 'sha512-' + hashlib.sha512(full).hexdigest()}}}}}
    return {'config.ign': encoded(initial)}, {path: base64.b64encode(full).decode()}


def seed_member(vm, private, public, cfg, assets, package, manifest, metadata, runtime):
    name = ('mother', 'offshoot-1', 'offshoot-2')[vm.member - 1]
    files = {'lab-address': (f'192.0.2.{vm.member}\n'.encode(), 0o600),
             'identity.key': (private / (name + '.key'), 0o600),
             'identity.pem': (public[name]['certificate'].encode(), 0o600),
             'lan-config.json': (encoded(cfg), 0o600),
             'peer/lan_agent.py': (ROOT / 'guest/lan_agent.py', 0o600),
             'peer/local_lfm.py': (ROOT / 'guest/local_lfm.py', 0o600),
             'peer/native_mother.py': (ROOT / 'guest/native_mother.py', 0o600),
             'model.gguf': (assets['model.gguf'], 0o400),
             'dependencies/libgomp.so.1': (assets['libgomp.so.1'], 0o400),
             'lab/start.sh': (b'#!/bin/sh\nexport LLAMA_ARG_REPACK=0\nexec /usr/bin/python3 -I /workspace/peer/native_mother.py\n', 0o500)}
    nodes = {'': Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000)}
    with tarfile.open(assets['llama.tar.gz']) as archive:
        for item in archive:
            if item.name.startswith('/') or '..' in Path(item.name).parts or item.size > 32 * 1024**2:
                raise ValueError('Unsafe inference archive')
            if item.isfile():
                files['llama/' + item.name] = (archive.extractfile(item).read(), item.mode & 0o755)
            elif item.issym() and '/' not in item.linkname:
                nodes['llama/' + item.name] = Node(stat.S_IFLNK | 0o777, item.linkname.encode(), 1000, 1000)
            elif not item.isdir():
                raise ValueError('Unexpected inference archive type')
    if vm.member == 1:
        files.update({'lab/manifest.json': (encoded(manifest), 0o600), 'lab/lan_install.py': (ROOT / 'guest/lan_install.py', 0o600),
                      'lab/assets/agent.tar.gz': (package, 0o400), 'lab/assets/llama.tar.gz': (assets['llama.tar.gz'], 0o400),
                      'lab/native-seeds.json': (encoded(metadata), 0o600),
                      'lab/portable-python.tar.gz': (ROOT / runtime['path'], 0o400)})
    for path, (data, mode) in files.items():
        nodes[path] = Node(stat.S_IFREG | mode, data, 1000, 1000)
    for path in list(nodes):
        for parent in Path(path).parents:
            if parent.as_posix() != '.':
                nodes.setdefault(parent.as_posix(), Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000))
    build_ext2(vm.disk, nodes, size_mib=512, label='NATIVE_GARDEN_SEED')
    save(vm.folder / 'initial-inventory.json', {'files': sorted(nodes), 'disk_sha256': digest(vm.disk)})


def verify_initial(statuses):
    calls, messages, pairs = {}, {}, []
    for name, status in statuses.items():
        model = status['model']
        if not (status['ready'] and not status['error'] and model['server_alive'] and model['weights_verified_inside_vm'] and model['weights_sha256'] == MODEL_SHA):
            raise ValueError('Native inference readiness evidence missing')
        for line in status['routes'].splitlines()[1:]:
            if line.split()[1] == '00000000':
                raise ValueError('Native private lab has an unexpected default route')
        for row in status['calls']:
            proof = row['proof']
            if row['state'] != 'ready' or row['id'] in calls or proof['call_id'] != row['id']:
                raise ValueError('Native inference call is incomplete or duplicated')
            if (json.loads(proof['raw_content']) != {'text': proof['text']} or proof['completion_tokens'] < 1
                    or proof['text_sha256'] != hashlib.sha256(proof['text'].encode()).hexdigest()
                    or proof['prompt_sha256'] != hashlib.sha256(proof['prompt'].encode()).hexdigest()):
                raise ValueError('Native inference provenance mismatch')
            calls[row['id']] = proof
        for pair in status['delivered']:
            hello, reply = pair['hello'], pair['reply']
            peer = hello['to']
            if hello['from'] != name or reply['from'] != peer or reply['to'] != name or reply['reply_to'] != hello['id']:
                raise ValueError('Native inference receipt routing mismatch')
            if hello not in statuses[peer]['received']:
                raise ValueError('Native inference recipient receipt missing')
            for body in (hello, reply):
                if body['id'] in messages:
                    raise ValueError('Native model message duplicated')
                messages[body['id']] = body
            pairs.append((name, peer))
    expected = {('mother', 'offshoot-1'), ('mother', 'offshoot-2'), ('mother', 'sprout-4'),
                ('sprout-4', 'offshoot-1'), ('sprout-4', 'offshoot-2')}
    if set(pairs) != expected or len(pairs) != 5 or len(calls) != 10 or set(calls) != set(messages):
        raise ValueError('Native workflow requires five independently matched exchanges')
    for ident, body in messages.items():
        proof = calls[ident]
        if body['text'] != proof['text'] or body['model']['weights_sha256'] != MODEL_SHA:
            raise ValueError('Native delivered output differs from actual inference')
        if body['kind'] == 'reply':
            source = messages[body['reply_to']]
            if proof['source_message_id'] != source['id'] or json.dumps(source['text']) not in proof['prompt']:
                raise ValueError('Native reply was not generated from its received input')
    return {'initial_actual_model_completions': 10, 'initial_correlated_exchanges': 5}


def run(route, case='happy', *, adapter=None):
    if (route not in ROUTES and (adapter is None or route not in ('redfish', 'guest-agent', 'managed-pull', 'ipmi',
            'ubuntu-autoinstall', 'debian-preseed', 'anaconda-kickstart', 'autoyast') or adapter.route != route)) or case not in CASES:
        raise ValueError('Unknown native route or case')
    PARENT.mkdir(parents=True, exist_ok=True)
    with exclusive(PARENT):
        from .native_recovery import recover_incomplete
        recover_incomplete()
        return _run(route, case, adapter=adapter)


def _run(route, case, *, adapter=None):
    if shutil.disk_usage(ROOT).free < 4 * 1024**3:
        raise RuntimeError('At least 4 GiB free is required for native fixtures')
    kind = adapter.kind if adapter else ('ubuntu' if route.startswith('cloud-init') else 'coreos')
    seed_route = adapter.seed_route if adapter else route
    memory = getattr(adapter, 'memory', 1024 if kind == 'ubuntu' else 1536)
    negative = case not in ('happy', 'resume')
    check_memory_budget((512 if negative else 3 * 512) + 256 + memory)
    base = json.loads((ROOT / 'runtime/linux-lan-base-v3/build-manifest.json').read_text())
    dhcp_base = realism_lab.preflight()
    folder = PARENT / str(uuid4())
    folder.mkdir()
    with WindowsProcess(os.getpid()) as process:
        save(folder / 'owner.json', {'pid': os.getpid(), 'created': process.created, 'executable': str(process.executable)})
    journal, switch = Journal(folder, folder.name), ReconnectingSwitch()
    private = folder / 'private'
    private.mkdir()
    machines, target = [], None
    report = {'route': route, 'case': case, 'native_kind': kind, 'level': 'reboot-tested', 'passed': False, 'native_os_observed': False,
              'source_sha256': {}, 'evidence': [], 'limitations': ['One owned local target; physical hardware and 4 GB hosts are untested',
              'cloud-init network metadata initially trusts the isolated provisioning LAN; Ignition network config has an explicit digest pin']}
    source_paths = ['src/agenticvm/native_enrollment.py', 'src/agenticvm/native_console.py', 'src/agenticvm/native_vm.py', 'src/agenticvm/native_recovery.py', 'guest/native_bootstrap.py',
                    'guest/native_mother.py', 'guest/lan_install.py', 'guest/lan_agent.py', 'guest/local_lfm.py']
    if adapter:
        source_paths += adapter.source_paths
        report['limitations'] += adapter.limitations
    report['source_sha256'] = {name: digest(ROOT / name) for name in source_paths}
    started = time.monotonic()
    try:
        public = {name: certificate(private, name, f'192.0.2.{i}') for i, name in enumerate(('mother', 'offshoot-1', 'offshoot-2'), 1)}
        assets, package = asset_inputs(), package_agent()
        runtime = json.loads((ROOT / 'runtime/enrollment-images/portable-python.json').read_text())
        payloads, metadata = native_config(seed_route, folder.name, public, runtime)
        if adapter:
            payloads, metadata = adapter.prepare_inputs(folder, public, runtime, payloads, metadata)
        manifest = {'schema': 'agenticvm.lan-assets.v1', 'files': {name: {'bytes': path.stat().st_size, 'sha256': digest(path)} for name, path in assets.items()}}
        manifest['files']['agent.tar.gz'] = {'bytes': len(package), 'sha256': hashlib.sha256(package).hexdigest()}
        if case == 'bad-hash':
            manifest['files']['agent.tar.gz']['sha256'] = '0' * 64
        save(folder / 'asset-manifest.json', manifest)
        (folder / 'agent.tar.gz').write_bytes(package)
        save(folder / 'native-input-inventory.json', {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                                                    for name, raw in payloads.items()})
        grant = secrets.token_urlsafe(32)
        seeds = []
        for i, name in enumerate(('mother', 'offshoot-1', 'offshoot-2'), 1):
            if negative and i != 1:
                continue
            cfg = {'identity': name, 'garden': folder.name, 'mother_certificate': public['mother']['certificate'],
                   'peers': public, 'test_case': case, 'route': route}
            if i == 1:
                cfg.update(request_id=folder.name, grant=grant, manifest_sha256=hashlib.sha256(encoded(manifest)).hexdigest())
            vm = LabVM(folder / name, i, switch, base, find_qemu(), 512)
            machines.append(vm)
            seeds.append(vm)
            seed_member(vm, private, public, cfg, assets, package, manifest, metadata, runtime)
        dhcp = realism_lab.DHCPVM(folder / 'dhcp', 5, switch, dhcp_base, find_qemu(), 256)
        machines.append(dhcp)
        dhcp.start()
        realism_lab.wait_marker(dhcp, 'REALISM_DHCP_APPLIANCE_READY', 60, switch)
        for vm in seeds:
            vm.start()
        realism_lab.wait_marker(seeds[0], 'NATIVE_MOTHER_READY', 240, switch)
        target = (adapter.create_vm if adapter else NativeVM)(folder / 'target', kind, memory=memory, switch=switch)
        seed, ignition, smbios = None, None, None
        if seed_route == 'cloud-init-local':
            seed = folder / 'seed.iso'
            seed_iso(seed, payloads)
        elif seed_route == 'cloud-init-network':
            smbios = 'ds=nocloud;s=http://192.0.2.1:8080/seed/' + folder.name + '/'
        else:
            ignition = folder / 'config.ign'
            ignition.write_bytes(payloads['config.ign'])
        target.start(seed=seed, ignition=ignition, smbios=smbios)
        journal.add('native_target_started', route=route, ownership=target.binding, base_sha256=target.base_sha256)
        print('Native OS enrollment: ' + route + '; ' + str(folder), flush=True)
        deadline, rebooted, guest = time.monotonic() + 1000, False, None
        while time.monotonic() < deadline:
            if switch.errors:
                raise RuntimeError('Native private switch failed: ' + str(switch.errors))
            if adapter:
                adapter.tick(target, folder)
            if shutil.disk_usage(ROOT).free < 1536 * 1024**2:
                raise RuntimeError('Native test stopped to preserve host disk headroom')
            text = (seeds[0].folder / 'boot.log').read_text(errors='replace')
            if not rebooted and 'NATIVE_READY_FOR_COLD_REBOOT' in text:
                switch.arm_reboot()
                target.poweroff()
                journal.add('native_target_powered_off')
                target.start()
                journal.add('native_target_cold_started', ownership=target.binding)
                rebooted = True
                print('Cold boot: installed OS/service must reconnect without seed media', flush=True)
            guest = completed_guest_report(text)
            if guest is not None:
                break
            if target.process.poll() is not None:
                raise RuntimeError('Native target exited unexpectedly; inspect its serial log')
            target_log = target.folder / f'boot-{target.boot}.log'
            if target_log.exists():
                serial = target_log.read_text(errors='replace')
                from .native_console import json_records
                failures = json_records(serial, 'NATIVE_DENIAL_PROOF ')
                if failures:
                    denial = failures[-1]
                    save(folder / 'denial-proof.json', denial)
                    if not negative:
                        raise RuntimeError('Unexpected native installation failure: ' + denial['error'])
                    verify_denial(case, denial, kind)
                    report.update(passed=True, level='native-bootstrap-tested', native_os_observed=True,
                                  expected_installation_denial=True, target_base_sha256=target.base_sha256)
                    report['evidence'].append((folder / 'denial-proof.json').relative_to(ROOT).as_posix())
                    report['denial_proof_sha256'] = digest(folder / 'denial-proof.json')
                    journal.add('native_expected_denial_verified', case=case)
                    raise ExpectedDenial()
                if 'NATIVE_INSTALL_FAILED ' in serial:
                    raise RuntimeError('Native bootstrap failed without complete denial proof; inspect ' + str(target_log))
            time.sleep(.5)
        if not guest or not guest.get('passed'):
            raise RuntimeError('Native mother did not accept the workflow: ' + str(guest))
        if case not in ('happy', 'resume'):
            raise ValueError('Deliberately invalid native enrollment unexpectedly succeeded')
        if case == 'resume' and not guest['installed']['installed']['downloads'][0]['resumed']:
            raise ValueError('Interrupted native model transfer did not actually resume')
        proof = verify_initial(guest['initial_statuses'])
        before, after = guest['initial_statuses']['sprout-4'], guest['final_statuses']['sprout-4']
        if not rebooted or before['native_boot_id'] == after['native_boot_id'] or before['public_identity'] != after['public_identity']:
            raise ValueError('Native cold reboot/identity evidence mismatch')
        if kind == 'coreos' and (before.get('native_selinux_enforcing') is not True or after.get('native_selinux_enforcing') is not True):
            raise ValueError('CoreOS acceptance requires SELinux enforcing on both boots')
        challenge = guest['post_reboot_challenge']
        calls = {row['id']: row for row in after['calls']}
        reply = calls[challenge['reply']['id']]['proof']
        if (reply['source_message_id'] != challenge['hello']['id'] or reply['completion_tokens'] < 1
                or reply['text'] != challenge['reply']['text'] or json.dumps(challenge['hello']['text']) not in reply['prompt']
                or challenge['tls']['version'] != 'TLSv1.3'):
            raise ValueError('Post-reboot inference is not independently correlated')
        save(folder / 'guest-report.json', guest)
        report.update(passed=True, native_os_observed=True, **proof, native_cold_boots=2,
                      post_reboot_actual_model_completions=2, target_base_sha256=target.base_sha256,
                      guest_report_sha256=digest(folder / 'guest-report.json'), metadata_transfers=guest['metadata_transfers'])
        expected_connections = getattr(adapter, 'expected_connections', 2)
        if switch.target_connections != expected_connections:
            raise ValueError('Native target connection count differs from the declared boot sequence')
        report.update(target_nic_connections=switch.target_connections, isolated_lan_bytes=dict(switch.stats))
        report['evidence'].append(str((folder / 'guest-report.json').relative_to(ROOT)))
        journal.add('native_reboot_model_workflow_verified', route=route)
    except ExpectedDenial:
        pass
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        journal.add('native_workflow_failed', error=report['error'])
    finally:
        failures = []
        if adapter:
            try:
                report['adapter_evidence'] = adapter.finish(folder)
            except Exception as error:
                failures.append('Native adapter cleanup/evidence: ' + str(error))
        if target:
            try:
                target.clean()
            except Exception as error:
                failures.append(str(error))
        switch.close()
        for vm in reversed(machines):
            try:
                vm.stop()
                if vm.disk.exists():
                    vm.disk.unlink()
            except Exception as error:
                failures.append(str(error))
        if not failures:
            for path in private.iterdir():
                path.unlink()
            private.rmdir()
        report['cleanup_failures'] = failures
        if failures:
            report['passed'] = False
        journal.add('native_cleanup', failures=failures)
        journal.close()
        report['checkpoints'] = verify_journal(folder / 'checkpoints.jsonl')
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['source_changed_during_run'] = any(digest(ROOT / path) != pin for path, pin in report['source_sha256'].items())
        if report['source_changed_during_run']:
            report['passed'] = False
            report['error'] = 'Source changed during native acceptance; repeat with a fixed revision'
        report['all_owned_vms_stopped_and_disks_removed'] = not failures and all(not vm.disk.exists() for vm in machines) and (target is None or not target.disk.exists())
        save(folder / 'report.json', report)
    print(json.dumps({'passed': report['passed'], 'report': str(folder / 'report.json'), 'error': report.get('error')}, indent=2), flush=True)
    return 0 if report['passed'] else 1
