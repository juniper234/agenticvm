"""Reconcile native receipts, exact process ownership and final source hashes."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save
from agenticvm.qemu import WindowsProcess

spec = importlib.util.spec_from_file_location('delegated_suite', ROOT / 'scripts/verify-delegated-suite.py')
suite_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite_tools)


def stopped(folder):
    observed = []
    for name in ('mother', 'offshoot-1', 'offshoot-2', 'sprout-4', 'negative-control'):
        path = folder / name / 'ownership.json'
        if not path.exists():
            continue
        binding = json.loads(path.read_text())
        with WindowsProcess(binding['pid']) as process:
            if process.alive() and process.created == binding['created'] and str(process.executable) == binding['executable']:
                raise ValueError('Exact owned VM remains running: ' + folder.name + '/' + name)
        observed.append(name)
    if (folder / 'private').exists() or any((folder / name / 'workspace.ext2').exists() for name in observed):
        raise ValueError('Disposable disks or private identities remain: ' + folder.name)
    return observed


def main(path):
    path = path.resolve()
    suite = json.loads(path.read_text())
    if (not suite['passed'] or suite['schema'] != 'agenticvm.delegated-suite.v2'
            or suite['native_scenarios'] != 6 or suite['actual_model_completions'] != 20
            or {row['case'] for row in suite['cases']} != {'happy', 'resume', 'bad-hash', 'wrong-grant', 'ssh-unavailable'}
            or len(suite['cases']) != 5):
        raise ValueError('A complete delegated acceptance suite is required')
    if any(digest(ROOT / name) != expected for name, expected in suite['source_sha256'].items()):
        raise ValueError('Accepted suite source changed')
    cases, bytes_transferred = [], 0
    for row in suite['cases']:
        ident = row['run_id']
        if str(UUID(ident)) != ident:
            raise ValueError('Canonical source run UUID required')
        folder = ROOT / 'runtime/delegated-enrollment-runs' / ident
        if digest(folder / 'report.json') != row['report_sha256']:
            raise ValueError('Accepted native report changed')
        receipt = suite_tools.verify(folder, row['case'])
        if len(stopped(folder)) != 5:
            raise ValueError('Five owned machines required per native case')
        if row['case'] in ('happy', 'resume'):
            bytes_transferred += receipt['delegated_enrollment']['actual_torrent_payload_bytes']
        cases.append({'case': row['case'], 'run_id': ident, 'report_sha256': row['report_sha256']})
    recovery_path = ROOT / 'docs/validation/delegated-recovery-report.json'
    recovery = json.loads(recovery_path.read_text())
    if (not recovery['passed'] or not recovery['real_controller_crash_injected']
            or recovery['exact_owned_vms_alive_after_crash'] != 5
            or not recovery['all_five_owned_vms_stopped'] or recovery['tasks_replayed']
            or not recovery['second_recovery_idempotent']):
        raise ValueError('Real crash recovery evidence required')
    recovery_folder = ROOT / 'runtime/delegated-enrollment-runs' / str(UUID(recovery['run_id']))
    if len(stopped(recovery_folder)) != 5:
        raise ValueError('Crash recovery did not account for five machines')
    # Development failures are preserved. Every historical run must also be
    # stopped and have an explicit successful cleanup or recovery result.
    historical = []
    for folder in (ROOT / 'runtime/delegated-enrollment-runs').iterdir():
        if not folder.is_dir() or not (folder / 'owner.json').exists():
            continue
        resources = stopped(folder)
        cleanup_path = folder / 'recovery.json'
        if cleanup_path.exists():
            cleanup = json.loads(cleanup_path.read_text())
            if not cleanup['passed'] or cleanup['tasks_replayed']:
                raise ValueError('Historical recovery was incomplete')
        else:
            cleanup = json.loads((folder / 'report.json').read_text())
            if cleanup['cleanup_failures'] or not cleanup['all_owned_lab_vms_stopped']:
                raise ValueError('Historical cleanup was incomplete')
        historical.append({'run_id': folder.name, 'stopped_vm_count': len(resources)})
    final = {'schema': 'agenticvm.delegated-validation.v2', 'passed': True,
             'suite': {'path': str(path.relative_to(ROOT)), 'sha256': digest(path)},
             'host_tests': suite['host_tests'], 'native_scenarios': 6, 'actual_model_completions': 20,
             'actual_torrent_payload_bytes': bytes_transferred, 'cases': cases,
             'recovery': {'path': str(recovery_path.relative_to(ROOT)), 'sha256': digest(recovery_path)},
             'historical_cleanup_audited': historical,
             'assumptions': ['Explicitly authorized owned VM pool', 'Preauthorized SSH with pinned target host identity',
                             'One named new member per run', 'Fixed mother policy; model generates messages',
                             'All machines share this Windows host; physical 4 GB hardware is untested',
                             'Finite lab ends by stopping and removing disposable guest workspaces'],
             'source_sha256': suite['source_sha256']}
    final['delivery_sha256'] = {name: digest(ROOT / name) for name in
                                ('Garden-Delegated-Lab.cmd', 'scripts/audit-delegated-evidence.py',
                                 'tests/test_delegated_enrollment.py')}
    destination = ROOT / 'docs/validation/delegated-validation-final.json'
    if destination.exists():
        raise ValueError('Final evidence already exists; preserve it before creating a new acceptance record')
    save(destination, final)
    print(json.dumps({'passed': True, 'final_evidence': str(destination), 'historical_runs': len(historical)}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', type=Path, required=True)
    args = parser.parse_args()
    main(args.suite if args.suite.is_absolute() else ROOT / args.suite)
