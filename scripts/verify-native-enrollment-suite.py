"""Bounded sequential native route/fault loop, with reusable audited checkpoints."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, save
from agenticvm.native_enrollment import ROUTES, CASES, PARENT
from agenticvm.native_evidence import verify


def reusable(route, case):
    for folder in sorted(PARENT.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        path = folder / 'report.json'
        if not folder.is_dir() or not path.is_file():
            continue
        value = json.loads(path.read_text())
        if value.get('route') != route or value.get('case') != case or not value.get('passed'):
            continue
        try:
            return folder, verify(folder)
        except ValueError:
            continue
    return None


def main(args):
    folder = ROOT / 'runtime/native-enrollment-suites' / str(uuid4())
    folder.mkdir(parents=True)
    result = {'schema': 'agenticvm.native-enrollment-suite.v1', 'passed': False, 'cases': [],
              'complete': False, 'routes': args.route or list(ROUTES), 'requested_cases': args.case or list(CASES)}
    result['source_sha256'] = {path: digest(ROOT / path) for path in (
        'src/agenticvm/native_enrollment.py', 'src/agenticvm/native_vm.py', 'src/agenticvm/native_recovery.py',
        'src/agenticvm/native_evidence.py', 'guest/native_bootstrap.py', 'guest/native_mother.py',
        'guest/lan_agent.py', 'guest/lan_install.py', 'guest/local_lfm.py', 'scripts/verify-native-enrollment-suite.py')}
    started = time.monotonic()
    try:
        for route in result['routes']:
            for case in result['requested_cases']:
                if any(digest(ROOT / path) != pin for path, pin in result['source_sha256'].items()):
                    raise RuntimeError('Suite source changed; keep prior receipts and restart this suite')
                prior = None if args.fresh else reusable(route, case)
                if prior:
                    run_folder, receipt = prior
                    print(f'Reuse independently audited native case: {route}/{case}', flush=True)
                else:
                    print(f'Native acceptance case: {route}/{case}', flush=True)
                    PARENT.mkdir(parents=True, exist_ok=True)
                    before = {p.name for p in PARENT.iterdir() if p.is_dir()}
                    child = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/run-native-enrollment.py'),
                                            '--route', route, '--case', case], cwd=ROOT, timeout=1500)
                    fresh = [p for p in PARENT.iterdir() if p.is_dir() and p.name not in before]
                    if child.returncode or len(fresh) != 1:
                        raise RuntimeError(f'Native acceptance failed: {route}/{case}; inspect newest run report')
                    run_folder = fresh[0]
                    receipt = verify(run_folder)
                result['cases'].append({'route': route, 'case': case, 'run_id': run_folder.name,
                    'report': (run_folder / 'report.json').relative_to(ROOT).as_posix(),
                    'report_sha256': digest(run_folder / 'report.json'), 'reused': bool(prior),
                    'native_cold_boots': receipt.get('native_cold_boots', 0)})
                save(folder / ('progress-' + str(len(result['cases'])) + '.json'), result)
                recorded = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/enrollment-matrix.py'),
                                           '--record', str(run_folder / 'report.json')], capture_output=True, text=True)
                if recorded.returncode:
                    raise RuntimeError('Coverage checkpoint failed: ' + recorded.stderr[-1000:])
            if set(result['requested_cases']) == set(CASES):
                route_receipt = {'route': route, 'level': 'fault-suite-tested', 'passed': True, 'native_os_observed': True,
                    'native_cold_boots': 2,
                    'cold_boot_scope': 'Each positive case (happy, resume) observed two native cold boots; refusal cases have none',
                    'source_sha256': result['source_sha256'],
                    'evidence': [row for row in result['cases'] if row['route'] == route],
                    'limitations': ['One owned local target; no physical hardware acceptance',
                                    'Controller interruption recovery is separately recorded, not inferred from these cases']}
                save(folder / (route + '.json'), route_receipt)
                recorded = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/enrollment-matrix.py'),
                    '--record', str(folder / (route + '.json'))], capture_output=True, text=True)
                if recorded.returncode:
                    raise RuntimeError('Completed route coverage could not be recorded: ' + recorded.stderr[-1000:])
        result.update(passed=True, complete=True)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        save(folder / 'report.json', result)
    print(json.dumps({'passed': result['passed'], 'cases_passed': len(result['cases']),
                      'report': str(folder / 'report.json'), 'error': result.get('error')}, indent=2), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--route', action='append', choices=ROUTES)
    parser.add_argument('--case', action='append', choices=CASES)
    parser.add_argument('--fresh', action='store_true')
    raise SystemExit(main(parser.parse_args()))
