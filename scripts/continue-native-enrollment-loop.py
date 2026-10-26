"""Sequential resumable Linux acceptance loop with stable host resource gates.

Existing cases are independently audited before reuse. New cases wait for a
stable RAM/commit budget instead of repeatedly attempting failed VM launches.
There is no background schedule, tenant access or host settings change.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.chain import exclusive
from agenticvm.resources import memory_status
from agenticvm.lan_lab import save, digest
from agenticvm.native_enrollment import CASES

MANAGEMENT = ('redfish', 'guest-agent', 'managed-pull', 'ipmi')
INSTALLERS = ('debian-preseed', 'ubuntu-autoinstall', 'anaconda-kickstart', 'autoyast')


def module(filename):
    spec = importlib.util.spec_from_file_location('enrollment_extra_suite', ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def wait_budget(folder, state, route, case, seconds):
    target = {'debian-preseed': 1536, 'ubuntu-autoinstall': 3072,
              'anaconda-kickstart': 2048, 'autoyast': 2048}.get(route, 1024)
    total = (1536 if case in ('happy', 'resume') else 512) + 256 + target
    required = {'physical_mib': total + 512 + 1024, 'commit_mib': total + 384 + 1024,
                'disk_bytes': (12 if route in INSTALLERS else 4) * 1024**3}
    deadline, stable, printed = time.monotonic() + seconds, None, 0
    while True:
        memory, free = memory_status(), shutil.disk_usage(ROOT).free
        ready = (memory['available_physical_mib'] >= required['physical_mib']
                 and memory['available_commit_mib'] >= required['commit_mib'] and free >= required['disk_bytes'])
        now = time.monotonic()
        stable = now if ready and stable is None else stable if ready else None
        state['current'] = {'route': route, 'case': case, 'phase': 'resource-preflight',
            'required': required, 'observed': memory | {'disk_free_bytes': free},
            'stable_for_seconds': round(now - stable, 1) if stable is not None else 0}
        atomic(folder / 'status.json', state)
        if stable is not None and now - stable >= 20:
            return
        if now >= deadline:
            raise TimeoutError('Host resource budget did not remain available for twenty seconds; no new VM launched')
        if now - printed >= 30:
            print(f"Waiting for stable resources: {route}/{case}; free RAM {memory['available_physical_mib']} MiB, "
                  f"commit {memory['available_commit_mib']} MiB, disk {free / 1024**3:.1f} GiB", flush=True)
            printed = now
        time.sleep(2)


def main(args):
    parent = ROOT / 'runtime/native-continuation-loops'
    parent.mkdir(exist_ok=True)
    folder = parent / str(uuid4())
    folder.mkdir()
    state = {'passed': False, 'complete': False, 'scope': 'Four local management and four native Linux installer routes',
        'overall_28_route_inventory_complete': False, 'cases': [], 'summaries': [], 'current': None}
    extra = module('scripts/verify-extra-native-suite.py')
    order = [(route, case) for case in ('bad-hash', 'wrong-grant', 'bad-bootstrap', 'happy', 'resume') for route in MANAGEMENT]
    order += [(route, case) for route in INSTALLERS for case in CASES]
    if args.management_only:
        order = [(route, case) for route, case in order if route in MANAGEMENT]
    print('Native continuation: ' + str(folder), flush=True)
    try:
        with exclusive(parent):
            for route, case in order:
                found = extra.reusable(route, case)
                if found:
                    run_folder, receipt = found
                    print('Audited existing case: ' + route + '/' + case, flush=True)
                else:
                    wait_budget(folder, state, route, case, args.wait_seconds)
                    state['current'] = {'route': route, 'case': case, 'phase': 'native-test'}
                    atomic(folder / 'status.json', state)
                    log = folder / (route + '-' + case + '.log')
                    print('Running native case: ' + route + '/' + case, flush=True)
                    try:
                        with log.open('wb') as output:
                            child = subprocess.run([sys.executable, '-I', '-B', 'scripts/run-extra-native-enrollment.py',
                                '--route', route, '--case', case], cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=1500)
                    except subprocess.TimeoutExpired:
                        # subprocess.run killed and reaped this exact native
                        # controller. Recovery never replays an uncertain task.
                        from agenticvm.native_enrollment import PARENT
                        from agenticvm.native_recovery import recover_incomplete
                        with exclusive(PARENT):
                            recover_incomplete()
                        raise
                    if child.returncode:
                        raise RuntimeError('Native case failed; inspect ' + str(log))
                    found = extra.reusable(route, case)
                    if not found:
                        raise ValueError('Completed native case did not pass independent current-source read-back')
                    run_folder, receipt = found
                state['cases'].append({'route': route, 'case': case,
                    'report': (run_folder / 'report.json').relative_to(ROOT).as_posix(), 'sha256': digest(run_folder / 'report.json')})
                save(folder / ('progress-' + str(len(state['cases'])) + '.json'), state)
            for route in MANAGEMENT if args.management_only else MANAGEMENT + INSTALLERS:
                log = folder / (route + '-full-suite.log')
                with log.open('wb') as output:
                    child = subprocess.run([sys.executable, '-I', '-B', 'scripts/verify-extra-native-suite.py', '--route', route],
                        cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=120)
                if child.returncode:
                    raise RuntimeError('Current-source full route audit failed: ' + route)
                state['summaries'].append({'route': route, 'log_sha256': digest(log)})
            wait_budget(folder, state, 'cloud-init-local', 'happy', args.wait_seconds)
            for name in ('verify-native-recovery.py', 'verify-enrollment-host-tests.py'):
                with (folder / (name + '.log')).open('wb') as output:
                    child = subprocess.run([sys.executable, '-I', '-B', 'scripts/' + name],
                        cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=900)
                if child.returncode:
                    raise RuntimeError('Final continuation check failed: ' + name)
            state.update(passed=True, complete=True, current=None)
    except Exception as error:
        state['error'] = type(error).__name__ + ': ' + str(error)
        if isinstance(error, TimeoutError):
            state['resource_blocked'] = True
    save(folder / 'report.json', state)
    atomic(folder / 'status.json', state)
    print(json.dumps({'passed': state['passed'], 'cases': len(state['cases']),
        'report': str(folder / 'report.json'), 'error': state.get('error')}, indent=2), flush=True)
    return 0 if state['passed'] else 2 if state.get('resource_blocked') else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wait-seconds', type=int, default=1800)
    parser.add_argument('--management-only', action='store_true')
    args = parser.parse_args()
    if not 20 <= args.wait_seconds <= 7200:
        parser.error('Use a bounded resource wait between twenty seconds and two hours')
    raise SystemExit(main(args))
