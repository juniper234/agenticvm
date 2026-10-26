"""Sequential native management/installer acceptance with audited case reuse."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.native_enrollment import PARENT, CASES
from agenticvm.extra_native_evidence import verify
from agenticvm.lan_lab import save, digest

ROUTES = ('redfish', 'guest-agent', 'managed-pull', 'ipmi', 'debian-preseed')
ALL_ROUTES = (*ROUTES, 'ubuntu-autoinstall', 'anaconda-kickstart', 'autoyast')


def reusable(route, case):
    for folder in sorted(PARENT.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        path = folder / 'report.json'
        if not path.is_file():
            continue
        value = json.loads(path.read_text())
        if value.get('route') == route and value.get('case') == case and value.get('passed'):
            if any(digest(ROOT / name) != pin for name, pin in value['source_sha256'].items()):
                continue
            try:
                return folder, verify(folder)
            except ValueError:
                pass
    return None


def main(args):
    folder = ROOT / 'runtime/extra-native-suites' / str(uuid4())
    folder.mkdir(parents=True)
    result = {'passed': False, 'complete': False, 'cases': [], 'routes': args.route or list(ROUTES),
              'requested_cases': args.case or list(CASES)}
    try:
        for route in result['routes']:
            for case in result['requested_cases']:
                existing = None if args.fresh else reusable(route, case)
                if existing:
                    run_folder, receipt = existing
                    print('Reusing audited native adapter: ' + route + '/' + case, flush=True)
                else:
                    print('Native management/installer case: ' + route + '/' + case, flush=True)
                    before = {p.name for p in PARENT.iterdir() if p.is_dir()}
                    child = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/run-extra-native-enrollment.py'),
                                            '--route', route, '--case', case], cwd=ROOT, timeout=1500)
                    fresh = [p for p in PARENT.iterdir() if p.is_dir() and p.name not in before]
                    if child.returncode or len(fresh) != 1:
                        raise RuntimeError('Native adapter failed: ' + route + '/' + case)
                    run_folder = fresh[0]
                    receipt = verify(run_folder)
                row = {'route': route, 'case': case, 'report': (run_folder / 'report.json').relative_to(ROOT).as_posix(),
                       'report_sha256': digest(run_folder / 'report.json')}
                result['cases'].append(row)
                save(folder / ('progress-' + str(len(result['cases'])) + '.json'), result)
                recorded = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/enrollment-matrix.py'),
                    '--record', str(run_folder / 'report.json')], capture_output=True, text=True)
                if recorded.returncode:
                    raise RuntimeError('Native adapter coverage could not be recorded: ' + recorded.stderr[-800:])
            if set(result['requested_cases']) == set(CASES):
                source = {**receipt['source_sha256'], 'src/agenticvm/extra_native_evidence.py': digest(ROOT / 'src/agenticvm/extra_native_evidence.py'),
                          'scripts/verify-extra-native-suite.py': digest(Path(__file__))}
                summary = {'route': route, 'level': 'fault-suite-tested', 'passed': True, 'native_os_observed': True,
                           'native_cold_boots': 2,
                           'cold_boot_scope': 'Each positive case (happy, resume) observed two native cold boots; refusal cases have none',
                           'source_sha256': source,
                           'evidence': [row for row in result['cases'] if row['route'] == route],
                           'limitations': receipt['limitations']}
                save(folder / (route + '.json'), summary)
                child = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/enrollment-matrix.py'),
                    '--record', str(folder / (route + '.json'))], capture_output=True, text=True)
                if child.returncode:
                    raise RuntimeError('Native adapter fault-suite coverage could not be recorded')
        result.update(passed=True, complete=True)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    save(folder / 'report.json', result)
    print(json.dumps({'passed': result['passed'], 'cases_passed': len(result['cases']),
                      'report': str(folder / 'report.json'), 'error': result.get('error')}, indent=2), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--route', action='append', choices=ALL_ROUTES)
    parser.add_argument('--case', action='append', choices=CASES)
    parser.add_argument('--fresh', action='store_true')
    raise SystemExit(main(parser.parse_args()))
