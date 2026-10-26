"""Abort exact owned Windows-lab resources, retaining unknown state for review."""
import json
from uuid import UUID
from .chain import exclusive
from .lan_lab import ROOT, save
from .lan_recovery import plain
from .native_enrollment import PARENT as GLOBAL_VM_LOCK
from .qemu import WindowsProcess, find_qemu
from .state import qemu_socket_directory

PARENT = ROOT / 'runtime/windows-enrollment-runs'
SEEDS = ('mother', 'offshoot-1', 'offshoot-2', 'dhcp')
PRIVATE_NAMES = {name + suffix for name in SEEDS[:3] for suffix in ('.key', '.pem')} | {'seed.iso'}


def recover(run_id, *, locked=False):
    if str(UUID(run_id)) != run_id:
        raise ValueError('Canonical owned Windows run UUID required')
    folder = plain(PARENT / run_id)
    if not locked:
        with exclusive(GLOBAL_VM_LOCK), exclusive(PARENT):
            return recover(run_id, locked=True)
    owner = json.loads(plain(folder / 'owner.json').read_text())
    with WindowsProcess(owner['pid']) as process:
        if process.alive() and process.created == owner['created']:
            raise ValueError('Windows controller is still alive; recovery refused')
    previous = folder / 'recovery.json'
    if previous.exists():
        value = json.loads(previous.read_text())
        if not value['passed']:
            raise ValueError('Prior Windows recovery requires review')
        return value | {'duplicate': True}
    result = {'passed': False, 'run_id': run_id, 'duplicate': False, 'tasks_replayed': False,
              'resources': [], 'failures': []}
    target_ids = set()
    for name in (*SEEDS, 'target'):
        directory = plain(folder / name)
        states = list(directory.glob('ownership-*.json')) if name == 'target' else [directory / 'ownership.json']
        for state_path in states:
            if not plain(state_path).is_file():
                continue
            state = json.loads(state_path.read_text())
            launch = json.loads(plain(state_path.with_name(state_path.name.replace('ownership', 'launch'))).read_text())
            if str(UUID(state['uuid'])) != state['uuid'] or launch['uuid'] != state['uuid'] or launch['argv'][launch['argv'].index('-uuid') + 1] != state['uuid']:
                raise ValueError('Windows-lab resource UUID binding changed')
            try:
                with WindowsProcess(state['pid'], terminate=True) as process:
                    if process.alive():
                        if (process.created != state['created'] or process.executable != find_qemu()
                                or str(process.executable) != state['executable']):
                            raise ValueError('Recorded Windows-lab process identity changed; left untouched')
                        process.terminate()
                        process.wait(10)
                    if process.alive():
                        raise ValueError('Owned Windows-lab process did not stop')
                result['resources'].append({'vm': name, 'uuid': state['uuid'], 'stopped': True})
                if name == 'target':
                    target_ids.add(state['uuid'])
            except Exception as error:
                result['failures'].append({'vm': name, 'error': str(error)})
    private = plain(folder / 'private')
    private_files = list(private.iterdir()) if private.exists() else []
    if any(path.name not in PRIVATE_NAMES or not plain(path).is_file() for path in private_files):
        result['failures'].append({'private': 'Unknown private files retained for review'})
    if not result['failures']:
        for name in SEEDS:
            disk = plain(folder / name / 'workspace.ext2')
            if disk.exists():
                disk.unlink()
        disk = plain(folder / 'target/system.qcow2')
        if disk.exists():
            disk.unlink()
        for identity in target_ids:
            ipc = plain(qemu_socket_directory(identity))
            for name in ('q', 'g'):
                path = plain(ipc / name)
                if path.exists():
                    path.unlink()
            if ipc.exists():
                ipc.rmdir()
        for path in private_files:
            path.unlink()
        if private.exists():
            private.rmdir()
    result['passed'] = not result['failures']
    result['disposable_disks_and_private_fixture_credentials_removed'] = result['passed']
    save(previous, result)
    return result


def recover_incomplete():
    for folder in sorted(PARENT.iterdir()):
        if not folder.is_dir():
            continue
        if not (folder / 'owner.json').exists():
            raise ValueError('Unknown Windows-lab directory requires review')
        report = json.loads((folder / 'report.json').read_text()) if (folder / 'report.json').exists() else None
        if report is None or report.get('cleanup_failures') or not report.get('all_owned_vms_stopped_and_disks_removed', True):
            if not recover(folder.name, locked=True)['passed']:
                raise ValueError('Prior Windows-lab cleanup did not complete')
