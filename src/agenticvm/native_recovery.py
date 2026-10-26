"""Abort only an interrupted local native test's bound processes and disks."""
from __future__ import annotations
import json
from pathlib import Path
from uuid import UUID

from .chain import exclusive
from .lan_lab import ROOT, save
from .lan_recovery import plain
from .qemu import WindowsProcess, find_qemu
from .state import qemu_socket_directory

PARENT = ROOT / 'runtime/native-enrollment-runs'
SEEDS = ('mother', 'offshoot-1', 'offshoot-2', 'dhcp')


def recover(run_id, *, locked=False):
    if str(UUID(run_id)) != run_id:
        raise ValueError('A canonical native run UUID is required')
    parent, folder = plain(PARENT), plain(PARENT / run_id)
    if locked:
        return _recover(folder)
    with exclusive(parent):
        return _recover(folder)


def _recover(folder):
    owner = json.loads(plain(folder / 'owner.json').read_text())
    with WindowsProcess(owner['pid']) as process:
        if process.alive() and process.created == owner['created']:
            raise RuntimeError('Native controller is still running; recovery refused')
    prior = plain(folder / 'recovery.json')
    if prior.exists():
        value = json.loads(prior.read_text())
        if not value['passed']:
            raise RuntimeError('Prior native recovery requires review')
        return {**value, 'duplicate': True}
    result = {'passed': False, 'run_id': folder.name, 'duplicate': False,
              'tasks_replayed': False, 'resources': [], 'failures': []}
    qemu = find_qemu()
    bindings = []
    for name in (*SEEDS, 'target'):
        directory = plain(folder / name)
        files = list(directory.glob('ownership-*.json')) if name == 'target' else [directory / 'ownership.json']
        for path in files:
            if not plain(path).is_file():
                continue
            state = json.loads(path.read_text())
            if str(UUID(state['uuid'])) != state['uuid']:
                raise ValueError('Invalid native resource UUID')
            launch_name = path.name.replace('ownership', 'launch')
            launch = json.loads(plain(directory / launch_name).read_text())
            argv = launch['argv']
            if launch['uuid'] != state['uuid'] or '-uuid' not in argv or argv[argv.index('-uuid') + 1] != state['uuid']:
                raise ValueError('Native process binding and launch disagree')
            try:
                with WindowsProcess(state['pid'], terminate=True) as process:
                    if process.alive():
                        if (process.created != state['created'] or process.executable != qemu
                                or str(process.executable) != state['executable']):
                            raise RuntimeError('Native VM process identity changed; left untouched')
                        process.terminate()
                        process.wait(10)
                    if process.alive():
                        raise RuntimeError('Native VM did not stop')
                bindings.append((name, state))
                result['resources'].append({'vm': name, 'uuid': state['uuid'], 'stopped': True})
            except Exception as error:
                result['failures'].append({'vm': name, 'error': str(error)})
    if not result['failures']:
        for name in SEEDS:
            disk = plain(folder / name / 'workspace.ext2')
            if disk.is_file():
                disk.unlink()
        disk = plain(folder / 'target/system.qcow2')
        if disk.is_file():
            disk.unlink()
        for name, state in bindings:
            if name != 'target':
                continue
            ipc = plain(qemu_socket_directory(state['uuid']))
            monitor = plain(ipc / 'q')
            if monitor.exists():
                monitor.unlink()
            agent = plain(ipc / 'g')
            if agent.exists():
                agent.unlink()
            if ipc.exists():
                ipc.rmdir()
        private = plain(folder / 'private')
        if private.exists():
            files = list(private.iterdir())
            allowed = {name + suffix for name in SEEDS[:3] for suffix in ('.key', '.pem')}
            if any(path.name not in allowed or not plain(path).is_file() for path in files):
                result['failures'].append({'private': 'Unexpected private files retained for review'})
            else:
                for path in files:
                    path.unlink()
                private.rmdir()
    result['passed'] = not result['failures']
    result['disposable_disks_and_private_identities_removed'] = result['passed']
    save(folder / 'recovery.json', result)
    return result


def recover_incomplete():
    """Caller holds the parent lock. Incomplete jobs are aborted, never replayed."""
    results = []
    for folder in sorted(plain(PARENT).iterdir()):
        if not folder.is_dir():
            continue
        plain(folder)
        if not (folder / 'owner.json').exists():
            raise ValueError('Unknown native run directory requires review: ' + folder.name)
        if not (folder / 'report.json').exists():
            result = recover(folder.name, locked=True)
            results.append(result)
            if not result['passed']:
                raise RuntimeError('Prior native test cleanup failed')
    return results
