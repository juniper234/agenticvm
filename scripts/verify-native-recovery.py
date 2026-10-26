"""Kill our native controller, then independently verify exact-resource cleanup."""
import json
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save
from agenticvm.native_enrollment import PARENT
from agenticvm.native_recovery import recover
from agenticvm.qemu import WindowsProcess


def main():
    evidence = ROOT / 'runtime/native-recovery-probes' / str(uuid4())
    evidence.mkdir(parents=True)
    PARENT.mkdir(parents=True, exist_ok=True)
    before = {path.name for path in PARENT.iterdir() if path.is_dir()}
    child = folder = None
    result = {'passed': False, 'schema': 'agenticvm.native-recovery-probe.v1',
              'source_sha256': {name: digest(ROOT / name) for name in (
                  'scripts/verify-native-recovery.py', 'src/agenticvm/native_recovery.py',
                  'src/agenticvm/native_enrollment.py', 'src/agenticvm/native_vm.py')}}
    try:
        with (evidence / 'controller.log').open('wb') as log:
            child = subprocess.Popen([sys.executable, '-I', '-B', str(ROOT / 'scripts/run-native-enrollment.py'),
                                      '--route', 'cloud-init-local'], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                      creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        deadline = time.monotonic() + 400
        while time.monotonic() < deadline:
            fresh = [path for path in PARENT.iterdir() if path.is_dir() and path.name not in before]
            if len(fresh) > 1:
                raise ValueError('Unexpected concurrent native controller')
            if fresh:
                folder = fresh[0]
            if folder and (folder / 'target/ownership-1.json').exists():
                break
            if child.poll() is not None:
                raise RuntimeError('Recovery controller exited before a target was running')
            time.sleep(.5)
        else:
            raise TimeoutError('Recovery setup did not reach an owned target')
        owner = json.loads((folder / 'owner.json').read_text())
        with WindowsProcess(child.pid, terminate=True) as process:
            if (not process.alive() or child.pid != owner['pid'] or process.created != owner['created']
                    or str(process.executable) != owner['executable']):
                raise ValueError('Controller kill ownership changed')
            process.terminate()
            process.wait(10)
        child.wait(10)
        first = recover(folder.name)
        second = recover(folder.name)
        if not first['passed'] or first['duplicate'] or not second['passed'] or not second['duplicate'] or first['tasks_replayed']:
            raise ValueError('Native recovery failed or replayed an uncertain job')
        if {row['vm'] for row in first['resources']} != {'mother', 'offshoot-1', 'offshoot-2', 'dhcp', 'target'}:
            raise ValueError('Native recovery did not observe every owned VM')
        for path in list(folder.glob('*/ownership.json')) + list(folder.glob('target/ownership-*.json')):
            state = json.loads(path.read_text())
            with WindowsProcess(state['pid']) as process:
                if process.alive() and process.created == state['created']:
                    raise ValueError('An owned VM survived native recovery')
        if (folder / 'private').exists() or (folder / 'target/system.qcow2').exists() or list(folder.glob('*/workspace.ext2')):
            raise ValueError('Native recovery left disposable disks or keys')
        result.update(passed=True, run_id=folder.name, controller_killed_with_target_running=True,
                      no_model_or_installation_replay=True, repeated_recovery_idempotent=True,
                      recovery_report_sha256=digest(folder / 'recovery.json'))
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if child and child.poll() is None:
            # Only this subprocess, held since creation, is eligible here.
            child.terminate()
            child.wait(10)
        if folder and not (folder / 'report.json').exists():
            try:
                cleaned = recover(folder.name)
                if not cleaned['passed']:
                    result.update(passed=False, cleanup_error=cleaned)
            except Exception as error:
                result.update(passed=False, cleanup_error=str(error))
        save(evidence / 'report.json', result)
    print(json.dumps({'passed': result['passed'], 'report': str(evidence / 'report.json'),
                      'error': result.get('error'), 'cleanup_error': result.get('cleanup_error')}, indent=2), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
