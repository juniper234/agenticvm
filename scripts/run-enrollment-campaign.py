"""Continue a bounded local campaign after an existing native first-boot suite."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import save, digest
from agenticvm.qemu import WindowsProcess
from agenticvm.chain import exclusive
from agenticvm.lan_recovery import plain


def main(after):
    if str(UUID(after)) != after:
        raise ValueError('Canonical native suite UUID required')
    prior = ROOT / 'runtime/native-enrollment-suites' / after / 'report.json'
    folder = ROOT / 'runtime/enrollment-campaigns' / str(uuid4())
    folder.mkdir(parents=True)
    with WindowsProcess(os.getpid()) as owner:
        save(folder / 'owner.json', {'pid': os.getpid(), 'created': owner.created, 'executable': str(owner.executable)})
    result = {'schema': 'agenticvm.local-enrollment-campaign.v1', 'passed': False, 'complete': False,
              'scope': 'Four native first-boot routes, five local management/installer routes, controller recovery and host tests',
              'overall_28_route_inventory_complete': False, 'stages': []}
    try:
        print('Waiting for the current owned native suite to finish; no concurrent VM wave', flush=True)
        deadline = time.monotonic() + 7200
        while not prior.exists():
            if time.monotonic() > deadline:
                raise TimeoutError('The prerequisite native suite did not finish')
            time.sleep(.5)
        completed = json.loads(prior.read_text())
        if not completed['passed'] or not completed['complete']:
            raise ValueError('Prerequisite native suite failed; inspect it before continuing')
        result['stages'].append({'stage': 'native-first-boot-suite', 'report': prior.relative_to(ROOT).as_posix(), 'sha256': digest(prior)})
        # These are only the two public CoreOS cache files downloaded by this
        # task. Their publisher pins and immutable URLs remain in the lock.
        # Subsequent routes use Ubuntu/Debian and need installer disk headroom.
        reclaimed = []
        lock = json.loads((ROOT / 'tools/enrollment-assets-lock.json').read_text())
        coreos = next(row for row in lock['assets'] if row['name'].startswith('Fedora CoreOS'))
        parent = ROOT / 'runtime/native-enrollment-runs'
        with exclusive(parent):
            for name, pin in ((coreos['path'], coreos['sha256']), (coreos['uncompressed_path'], coreos['uncompressed_sha256'])):
                path = plain(ROOT / name)
                if (path.name not in ('fedora-coreos-amd64.qcow2.xz', 'fedora-coreos-amd64.qcow2')
                        or not path.resolve().is_relative_to(ROOT)):
                    raise ValueError('Unexpected public image cache path; retained')
                if path.exists():
                    if digest(path) != pin:
                        raise ValueError('Public cache differs from publisher pin; retained for review')
                    reclaimed.append({'path': name, 'sha256': pin, 'bytes': path.stat().st_size})
                    path.unlink()
        save(folder / 'public-cache-recycling.json', {'reason': 'Preserve host headroom for native local installers',
            'removed_only_verified_downloaded_task_assets': reclaimed, 'restore_command': 'python -I -B scripts/prepare-enrollment-images.py'})
        stages = [('local-management-happy', ['scripts/verify-extra-native-suite.py', '--case', 'happy']),
                  ('local-management-faults', ['scripts/verify-extra-native-suite.py']),
                  ('controller-recovery', ['scripts/verify-native-recovery.py'])]
        for name, arguments in stages:
            print('Local enrollment campaign stage: ' + name, flush=True)
            with (folder / (name + '.log')).open('wb') as log:
                child = subprocess.run([sys.executable, '-I', '-B', *arguments], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            result['stages'].append({'stage': name, 'exit_code': child.returncode,
                                    'log': (folder / (name + '.log')).relative_to(ROOT).as_posix(), 'sha256': digest(folder / (name + '.log'))})
            save(folder / ('progress-' + str(len(result['stages'])) + '.json'), result)
            if child.returncode:
                raise RuntimeError('Campaign stage failed: ' + name + '; inspect its log')
        print('Local enrollment campaign stage: host regression tests', flush=True)
        import unittest
        tests = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
        with (folder / 'host-tests.log').open('w') as output:
            checked = unittest.TextTestRunner(stream=output, verbosity=2).run(tests)
        result['host_tests'] = {'tests': checked.testsRun, 'failures': len(checked.failures), 'errors': len(checked.errors), 'skipped': len(checked.skipped)}
        if not checked.wasSuccessful() or checked.skipped:
            raise RuntimeError('Host regression tests did not fully pass')
        result.update(passed=True, complete=True)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    save(folder / 'report.json', result)
    print(json.dumps({'passed': result['passed'], 'report': str(folder / 'report.json'), 'error': result.get('error')}, indent=2), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--after-native-suite', required=True)
    raise SystemExit(main(parser.parse_args().after_native_suite))
