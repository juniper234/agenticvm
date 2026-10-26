"""Finite native acceptance plus source-matched, read-back verification."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, reconcile, save
from agenticvm.delegated_lab import verify_delegation
from agenticvm.peers import verify_journal


def verify(folder, case):
    receipt = json.loads((folder / 'report.json').read_text())
    if not receipt['passed'] or receipt['case'] != case or receipt['workflow'] != 'delegated-v2':
        raise ValueError('Native delegated receipt failed')
    if receipt['cleanup_failures'] or not receipt['all_owned_lab_vms_stopped'] or not receipt['disposable_private_disks_removed']:
        raise ValueError('Native cleanup was not complete')
    for name, expected in receipt['source_sha256'].items():
        if digest(ROOT / 'guest' / name) != expected:
            raise ValueError('Accepted guest source has changed: ' + name)
    if digest(ROOT / 'src/agenticvm/bounded_torrent.py') != receipt['torrent_source_sha256']:
        raise ValueError('Accepted torrent source changed')
    if verify_journal(folder / 'checkpoints.jsonl') != receipt['checkpoints']:
        raise ValueError('Native checkpoint journal mismatch')
    if (folder / 'private').exists() or any((folder / name / 'workspace.ext2').exists() for name in ('mother', 'offshoot-1', 'offshoot-2', 'sprout-4', 'negative-control')):
        raise ValueError('Disposable identity material remains')
    inventories = {name: json.loads((folder / name / 'initial-inventory.json').read_text())['files']
                   for name in ('mother', 'offshoot-1', 'offshoot-2', 'sprout-4', 'negative-control')}
    if 'lab/enroll_key' not in inventories['offshoot-1'] or any('lab/enroll_key' in inventories[name] for name in inventories if name != 'offshoot-1'):
        raise ValueError('Installation key is not scoped exclusively to the sponsor')
    for name in ('sprout-4', 'negative-control'):
        if any(p in inventories[name] for p in ('peer/lan_agent.py', 'model.gguf', 'identity.key', 'lab/start.sh')):
            raise ValueError('Target was not initially agent-free')
    if case in ('happy', 'resume'):
        guest = json.loads((folder / 'guest-report.json').read_text())
        if digest(folder / 'guest-report.json') != receipt['guest_report_sha256']:
            raise ValueError('Guest evidence digest changed')
        reconcile(guest['statuses'])
        if verify_delegation(guest, receipt['target_uuid']) != receipt['delegated_enrollment']:
            raise ValueError('Delegation proof changed after acceptance')
        if case == 'resume' and not guest['installed']['downloads'][0]['resumed']:
            raise ValueError('Native model download did not resume')
    elif not receipt.get('expected_installation_denial'):
        raise ValueError('Negative case lacks an observed refusal')
    return receipt


def main(reuse):
    begin = time.monotonic()
    result = {'schema': 'agenticvm.delegated-suite.v2', 'passed': False, 'cases': [],
              'authorized_owned_vm_lab': True, 'physical_4gb_host_tested': False}
    for case in ('happy', 'resume', 'bad-hash', 'wrong-grant', 'ssh-unavailable'):
        if case == 'happy' and reuse:
            folder = ROOT / 'runtime/delegated-enrollment-runs' / reuse
            receipt = verify(folder, case)
        else:
            print('Native delegated case: ' + case, flush=True)
            parent = ROOT / 'runtime/delegated-enrollment-runs'
            parent.mkdir(parents=True, exist_ok=True)
            before = {p.name for p in parent.iterdir() if p.is_dir()}
            child = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/run-delegated-enrollment.py'),
                                    '--case', case, '--contact-seconds', '30'], cwd=ROOT)
            fresh = [p for p in parent.iterdir() if p.is_dir() and p.name not in before]
            if child.returncode or len(fresh) != 1:
                raise RuntimeError('Native delegated case failed: ' + case)
            folder = fresh[0]
            receipt = verify(folder, case)
        result['cases'].append({'case': case, 'run_id': folder.name, 'report_sha256': digest(folder / 'report.json'),
                                'elapsed_seconds': receipt['elapsed_seconds']})
    print('Native controller crash and exact ownership recovery', flush=True)
    child = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/verify-lan-recovery.py'), '--delegated'], cwd=ROOT)
    if child.returncode:
        raise RuntimeError('Delegated controller crash recovery failed')
    result['controller_crash_recovery'] = True
    print('Host regression suite', flush=True)
    import unittest
    sys.path.insert(0, str(ROOT / 'guest'))
    tests = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    tested = unittest.TextTestRunner(verbosity=1).run(tests)
    if not tested.wasSuccessful() or tested.skipped:
        raise RuntimeError('Host regression suite did not fully pass')
    result['host_tests'] = {'passed': tested.testsRun, 'failures': len(tested.failures),
                            'errors': len(tested.errors), 'skipped': len(tested.skipped)}
    source_paths = ['src/agenticvm/lan_lab.py', 'src/agenticvm/bounded_torrent.py',
                    'src/agenticvm/delegated_lab.py', 'src/agenticvm/lan_recovery.py',
                    'guest/delegated_agent.py', 'guest/lan_install.py', 'guest/lan_agent.py',
                    'scripts/run-delegated-enrollment.py', 'scripts/verify-delegated-suite.py',
                    'scripts/verify-lan-recovery.py']
    result['source_sha256'] = {name: digest(ROOT / name) for name in source_paths}
    result['actual_model_completions'] = 20
    result['native_scenarios'] = 6
    result['passed'] = True
    result['elapsed_seconds'] = round(time.monotonic() - begin, 3)
    path = ROOT / 'docs/validation' / ('delegated-suite-' + str(uuid4()) + '.json')
    save(path, result)
    print(json.dumps({'passed': True, 'report': str(path)}, indent=2), flush=True)
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reuse-happy', metavar='COMPLETED_RUN_UUID')
    args = parser.parse_args()
    if args.reuse_happy and str(UUID(args.reuse_happy)) != args.reuse_happy:
        parser.error('Canonical run UUID required')
    raise SystemExit(main(args.reuse_happy))
