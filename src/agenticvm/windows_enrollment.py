"""Real Windows evaluation Setup, native task enrollment and cold-boot proof."""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import tarfile
import time
from uuid import uuid4
import zipfile

from .chain import exclusive
from .ext2 import Node, build_ext2
from .lan_lab import ROOT, LabVM, certificate, asset_inputs, digest, encoded, save, completed_guest_report
from .native_enrollment import ReconnectingSwitch, PARENT as GLOBAL_VM_LOCK, CASES
from .native_vm import seed_iso
from .peers import Journal, verify_journal
from .qemu import WindowsProcess, find_qemu
from .resources import check_memory_budget
from . import realism_lab
from .windows_inputs import inputs
from .windows_vm import WindowsVM
from .windows_recovery import PARENT, PRIVATE_NAMES, recover_incomplete
from .windows_evidence import verify_guest, verify_denial


def package_agent():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, source in {'lan_agent.py': 'lan_agent.py', 'local_lfm.py': 'windows_lfm.py',
                             'lfm_protocol.py': 'local_lfm.py', 'windows_agent.py': 'windows_agent.py'}.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 18, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (ROOT / 'guest' / source).read_bytes())
    return output.getvalue()


def seed_member(vm, private, public, config, linux, windows, manifest, package):
    name = ('mother', 'offshoot-1', 'offshoot-2')[vm.member - 1]
    files = {'lab-address': (f'192.0.2.{vm.member}\n'.encode(), 0o600),
        'identity.key': (private / (name + '.key'), 0o600), 'identity.pem': (public[name]['certificate'].encode(), 0o600),
        'lan-config.json': (encoded(config), 0o600), 'model.gguf': (linux['model.gguf'], 0o400),
        'dependencies/libgomp.so.1': (linux['libgomp.so.1'], 0o400),
        'peer/lan_agent.py': (ROOT / 'guest/lan_agent.py', 0o500),
        'peer/local_lfm.py': (ROOT / 'guest/local_lfm.py', 0o500),
        'peer/native_mother.py': (ROOT / 'guest/native_mother.py', 0o500),
        'peer/windows_mother.py': (ROOT / 'guest/windows_mother.py', 0o500),
        'lab/start.sh': (b'#!/bin/sh\nexport LLAMA_ARG_REPACK=0\nexec /usr/bin/python3 -I /workspace/peer/windows_mother.py\n', 0o500)}
    nodes = {'': Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000)}
    with tarfile.open(linux['llama.tar.gz']) as archive:
        for item in archive:
            if item.name.startswith('/') or '..' in Path(item.name).parts or item.size > 32 * 1024**2:
                raise ValueError('Unexpected Linux seed inference archive')
            if item.isfile():
                files['llama/' + item.name] = (archive.extractfile(item).read(), item.mode & 0o755)
            elif item.issym() and '/' not in item.linkname:
                nodes['llama/' + item.name] = Node(stat.S_IFLNK | 0o777, item.linkname.encode(), 1000, 1000)
            elif not item.isdir():
                raise ValueError('Unexpected Linux seed archive member type')
    if vm.member == 1:
        files.update({'lab/manifest.json': (encoded(manifest), 0o600),
            'lab/windows_install.py': (ROOT / 'guest/windows_install.py', 0o500),
            'lab/assets/agent.zip': (package, 0o400), 'lab/assets/llama.zip': (windows['llama.zip'], 0o400)})
    for path, (raw, mode) in files.items():
        nodes[path] = Node(stat.S_IFREG | mode, raw, 1000, 1000)
    for path in list(nodes):
        for parent in Path(path).parents:
            if parent.as_posix() != '.':
                nodes.setdefault(parent.as_posix(), Node(stat.S_IFDIR | 0o700, uid=1000, gid=1000))
    build_ext2(vm.disk, nodes, size_mib=512, label='WINDOWS_LAB_SEED')
    save(vm.folder / 'initial-inventory.json', {'files': sorted(nodes), 'disk_sha256': digest(vm.disk)})


def run(case='happy'):
    if case not in CASES:
        raise ValueError('Known bounded Windows case required')
    PARENT.mkdir(parents=True, exist_ok=True)
    GLOBAL_VM_LOCK.mkdir(exist_ok=True)
    with exclusive(GLOBAL_VM_LOCK), exclusive(PARENT):
        recover_incomplete()
        return _run(case)


def _run(case):
    if shutil.disk_usage(ROOT).free < 16 * 1024**3:
        raise RuntimeError('The Windows lab requires 16 GiB free before a fresh evaluation run')
    negative = case not in ('happy', 'resume')
    check_memory_budget(512 + 512 + 512 + 256 + 3072)
    base = json.loads((ROOT / 'runtime/linux-lan-base-v3/build-manifest.json').read_text())
    dhcp_base = realism_lab.preflight()
    folder = PARENT / str(uuid4())
    folder.mkdir()
    with WindowsProcess(os.getpid()) as owner:
        save(folder / 'owner.json', {'pid': os.getpid(), 'created': owner.created, 'executable': str(owner.executable)})
    target_uuid = str(uuid4())
    report = {'route': 'windows-unattend', 'case': case, 'passed': False, 'level': 'adapter-built',
        'native_os_observed': False, 'target_uuid': target_uuid, 'evidence': [], 'source_sha256': {},
        'limitations': ['One disposable owned Windows Server 2025 Standard evaluation Core VM; no physical hardware acceptance',
            'Windows target uses 3,072 MiB with three Linux peers; native security checks are unchanged',
            'Fresh run used a 16 GiB disk guard because Android validation consumed the volume; raw evidence and receipts were preserved',
            'Host disk stop threshold lowered to 6 GiB because the growing Windows qcow2 crossed the former 8 GiB floor late in Setup',
            'Windows CPU model is host (not max) to avoid WHPX unsupported-feature exits; native security checks are unchanged',
            'Windows fixture uses QEMU TCG software virtualization because WHPX exits with VP code 4 during Windows reboot; native OS/security checks are unchanged',
            'TCG Setup can exceed 38 minutes; the campaign and mother enrollment windows were extended to 5,400 seconds for this software-emulated run',
            'Owner-prepared private answer/configuration CD and one blank SATA disk; guest warm Setup resets are not cold boots',
            'Persistent Windows inference runs as Local Service through Task Scheduler; no host inference',
            'Evaluation ISO is official Microsoft HTTPS and locally SHA256 pinned; Setup Authenticode was verified, no independent whole-ISO publisher checksum claim',
            'No tenant, product activation, physical LAN bridge, arbitrary target discovery or recursive enrollment']}
    sources = ['src/agenticvm/windows_enrollment.py', 'src/agenticvm/windows_inputs.py', 'src/agenticvm/windows_vm.py',
        'src/agenticvm/windows_recovery.py', 'src/agenticvm/windows_evidence.py', 'src/agenticvm/native_vm.py',
        'src/agenticvm/native_enrollment.py', 'src/agenticvm/native_console.py', 'src/agenticvm/lan_lab.py', 'src/agenticvm/realism_lab.py',
        'guest/windows_agent.py', 'guest/windows_lfm.py', 'guest/windows_bootstrap.py', 'guest/windows_install.py',
        'guest/windows_mother.py', 'guest/lan_agent.py', 'guest/local_lfm.py', 'guest/native_mother.py',
        'runtime/enrollment-images/windows-installer/manifest.json', 'runtime/enrollment-images/windows-application-runtime.json',
        'scripts/verify-windows-inputs.py']
    report['source_sha256'] = {name: digest(ROOT / name) for name in sources}
    private = folder / 'private'
    private.mkdir()
    journal, switch = Journal(folder, folder.name), ReconnectingSwitch()
    machines, target, passed_denial = [], None, False
    started = time.monotonic()
    try:
        public = {name: certificate(private, name, f'192.0.2.{index}')
            for index, name in enumerate(('mother', 'offshoot-1', 'offshoot-2'), 1)}
        linux, package = asset_inputs(), package_agent()
        dependencies = json.loads((ROOT / 'runtime/enrollment-images/windows-application-runtime.json').read_text())
        llama = dependencies['assets']['llama']
        windows = {'model.gguf': linux['model.gguf'], 'llama.zip': ROOT / llama['path']}
        if digest(windows['llama.zip']) != llama['sha256']:
            raise ValueError('Publisher-pinned Windows inference archive changed')
        manifest = {'schema': 'agenticvm.windows-assets.v1', 'files': {name: {'bytes': path.stat().st_size,
            'sha256': digest(path)} for name, path in windows.items()}}
        manifest['files']['agent.zip'] = {'bytes': len(package), 'sha256': hashlib.sha256(package).hexdigest()}
        if case == 'bad-hash':
            manifest['files']['agent.zip']['sha256'] = '0' * 64
        save(folder / 'asset-manifest.json', manifest)
        (folder / 'agent.zip').write_bytes(package)
        grant = secrets.token_urlsafe(32)
        install_token = secrets.token_urlsafe(32)
        for index, name in enumerate(('mother', 'offshoot-1', 'offshoot-2'), 1):
            if negative and index != 1:
                continue
            config = {'identity': name, 'garden': folder.name, 'mother_certificate': public['mother']['certificate'],
                'peers': public, 'test_case': case, 'route': 'windows-unattend', 'target_uuid': target_uuid}
            if index == 1:
                config.update(request_id=folder.name, grant=grant, install_token=install_token,
                              manifest_sha256=hashlib.sha256(encoded(manifest)).hexdigest())
            vm = LabVM(folder / name, index, switch, base, find_qemu(), 512)
            machines.append(vm)
            seed_member(vm, private, public, config, linux, windows, manifest, package)
        dhcp = realism_lab.DHCPVM(folder / 'dhcp', 5, switch, dhcp_base, find_qemu(), 256)
        machines.append(dhcp)
        dhcp.start()
        realism_lab.wait_marker(dhcp, 'REALISM_DHCP_APPLIANCE_READY', 90, switch)
        for vm in machines[:-1]:
            vm.start()
        realism_lab.wait_marker(machines[0], 'WINDOWS_MOTHER_READY', 300, switch)
        files = inputs(folder.name, target_uuid, public['mother']['certificate'],
                       'Lab1!' + secrets.token_urlsafe(20), install_token=install_token)
        save(folder / 'provisioning-inputs.json', {'target_uuid': target_uuid,
            'files': {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} for name, raw in files.items()},
            'private_answer_file_retained': False, 'native_dependency_only_before_enrollment': True})
        seed = private / 'seed.iso'
        seed_iso(seed, files)
        del files
        target = WindowsVM(folder / 'target', switch=switch, target_uuid=target_uuid, memory=3072)
        target.start(seed=seed)
        journal.add('windows_target_started', ownership=target.binding, target_uuid=target_uuid)
        print('Native Windows Setup/enrollment: ' + str(folder), flush=True)
        deadline, rebooted, guest, captures = time.monotonic() + 7200, False, None, 0
        next_capture = time.monotonic() + 180
        while time.monotonic() < deadline:
            if switch.errors:
                raise RuntimeError('Windows private switch failed: ' + str(switch.errors))
            if shutil.disk_usage(ROOT).free < 6 * 1024**3:
                raise RuntimeError('Windows lab stopped to preserve host disk headroom')
            mother = (machines[0].folder / 'boot.log').read_text(errors='replace')
            if not rebooted and 'WINDOWS_READY_FOR_COLD_REBOOT' in mother:
                switch.arm_reboot()
                target.poweroff()
                journal.add('windows_target_powered_off')
                target.memory = 2048
                target.start()
                journal.add('windows_target_cold_started', ownership=target.binding)
                rebooted = True
                print('Windows cold boot: native startup task must reconnect without any CD', flush=True)
            guest = completed_guest_report(mother)
            if guest is not None:
                break
            if target.process.poll() is not None:
                raise RuntimeError('Windows target exited unexpectedly: ' + (target.folder / f'stderr-{target.boot}.log').read_text(errors='replace')[-1200:])
            serial_path = target.folder / f'boot-{target.boot}.log'
            serial = serial_path.read_text(errors='replace') if serial_path.exists() else ''
            if 'WINDOWS_OS_PREPARED {' in serial:
                report['native_os_observed'] = True
            from .native_console import json_records
            denial = json_records(serial, 'WINDOWS_DENIAL_PROOF ')
            if denial:
                proof = denial[-1]
                save(folder / 'denial-proof.json', proof)
                if not negative:
                    raise RuntimeError('Unexpected Windows installation denial: ' + proof['error'])
                verify_denial(case, proof, target_uuid)
                report.update(passed=True, native_os_observed=True, level='native-bootstrap-tested',
                    expected_installation_denial=True, denial_proof_sha256=digest(folder / 'denial-proof.json'))
                report['evidence'].append((folder / 'denial-proof.json').relative_to(ROOT).as_posix())
                journal.add('windows_expected_denial_verified', case=case)
                passed_denial = True
                break
            if 'WINDOWS_PREPARATION_FAILED' in serial or 'WINDOWS_INSTALL_FAILED' in serial:
                raise RuntimeError('Windows native preparation failed; inspect its serial evidence')
            if captures < 3 and time.monotonic() >= next_capture and not rebooted:
                try:
                    screenshot = target.capture()
                    save(folder / ('display-' + str(captures) + '.json'), {'path': screenshot.name, 'sha256': digest(screenshot)})
                except Exception as error:
                    save(folder / ('display-' + str(captures) + '.json'), {'capture_error': str(error)})
                captures += 1
                next_capture = time.monotonic() + 240
            time.sleep(.5)
        if not passed_denial:
            if negative or not guest or not guest.get('passed') or not rebooted:
                raise RuntimeError('Mother did not accept native Windows enrollment and cold reboot: ' + str(guest))
            proof = verify_guest(guest, target_uuid)
            if case == 'resume' and not guest['installed']['installed']['downloads'][0]['resumed']:
                raise ValueError('Windows model transfer did not actually resume')
            save(folder / 'guest-report.json', guest)
            report.update(passed=True, native_os_observed=True, level='reboot-tested', **proof,
                guest_report_sha256=digest(folder / 'guest-report.json'), target_nic_connections=switch.target_connections)
            if switch.target_connections != 2:
                raise ValueError('Windows host-controlled cold boot count differs from its declared sequence')
            report['evidence'].append((folder / 'guest-report.json').relative_to(ROOT).as_posix())
            journal.add('windows_model_reboot_workflow_verified')
    except Exception as error:
        report.update(passed=False, error=type(error).__name__ + ': ' + str(error))
        journal.add('windows_workflow_failed', error=report['error'])
        if target and target.process and target.process.poll() is None:
            try:
                target.capture()
            except Exception:
                pass
    finally:
        failures = []
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
                if path.name not in PRIVATE_NAMES or not path.is_file():
                    failures.append('Unknown Windows private file retained')
                    break
            if not failures:
                for path in private.iterdir():
                    path.unlink()
                private.rmdir()
        report['cleanup_failures'] = failures
        if failures:
            report['passed'] = False
        journal.add('windows_cleanup', failures=failures)
        journal.close()
        report['checkpoints'] = verify_journal(folder / 'checkpoints.jsonl')
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['source_changed_during_run'] = any(digest(ROOT / name) != pin for name, pin in report['source_sha256'].items())
        if report['source_changed_during_run']:
            report.update(passed=False, error='Windows source changed during acceptance; rerun at a fixed revision')
        report['all_owned_vms_stopped_and_disks_removed'] = (not failures and not (folder / 'target/system.qcow2').exists()
            and not list(folder.glob('*/workspace.ext2')) and not private.exists())
        if not report['all_owned_vms_stopped_and_disks_removed']:
            report['passed'] = False
        save(folder / 'report.json', report)
    print(json.dumps({'passed': report['passed'], 'report': str(folder / 'report.json'), 'error': report.get('error')}, indent=2), flush=True)
    return 0 if report['passed'] else 1
