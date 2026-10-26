"""Index prior native observations with their original source pins and limits."""
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.lan_lab import digest, reconcile, save


def read(path):
    return json.loads(path.read_text())


def inside(value):
    path = Path(value.replace('\\', '/'))
    path = path.resolve() if path.is_absolute() else (ROOT / path).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError('Historical evidence escaped the workspace')
    return path


def native_case(route, path, expected, sources):
    if digest(path) != expected:
        raise ValueError('Historical native receipt changed')
    receipt = read(path)
    if not receipt['passed'] or receipt.get('cleanup_failures') or receipt.get('source_changed_during_run'):
        raise ValueError('Historical case did not pass cleanly at a fixed source revision')
    guest = path.parent / 'guest-report.json'
    if digest(guest) != receipt['guest_report_sha256']:
        raise ValueError('Historical model ledger changed')
    proof = reconcile(read(guest)['statuses'])
    if proof['actual_model_completions'] != 10:
        raise ValueError('Historical case does not reconcile ten model completions')
    if (path.parent / 'private').exists() or list(path.parent.glob('*/workspace.ext2')):
        raise ValueError('Historical disposable keys or work disks remain')
    pins = {name.replace('\\', '/'): pin for name, pin in sources.items()}
    return {'route': route, 'level': 'native-enrollment-tested', 'passed': True, 'native_os_observed': True,
        'source_sha256': pins, 'evidence': [{'path': path.relative_to(ROOT).as_posix(), 'sha256': expected,
            'guest_report_sha256': digest(guest), 'actual_model_completions_reconciled': 10}],
        'limitations': ['Historical native receipt and model correlation rechecked; the VM was not rerun by this indexer',
            'The original suite verified process cleanup; this indexer checks retained evidence and absence of disposable keys/disks',
            'Original source pins are retained: changed sources must remain historical in the coverage matrix',
            'No cold-reboot acceptance; firmware/network targets used a RAM-resident Debian environment',
            'Owner-prepared SSH, network boot or firmware trust is required; no physical hardware acceptance']}


def main():
    folder = ROOT / 'runtime/enrollment-legacy-index' / str(uuid4())
    folder.mkdir(parents=True)
    rows = []
    lan = read(ROOT / 'docs/validation/lan-validation-final.json')
    selected = next(row for row in lan['scenarios'] if row['case'] == 'happy')['receipt']
    path = inside(selected['path'])
    value = read(path)
    rows.append(native_case('ssh-linux', path, selected['sha256'], {'guest/' + name: pin for name, pin in value['source_sha256'].items()}))
    pxe = read(ROOT / 'docs/validation/pxe-validation-final.json')
    selected = next(row for row in pxe['cases'] if row['case'] == 'happy')
    path = inside(selected['report'])
    value = read(path)
    pins = {'guest/' + name: pin for name, pin in value['source_sha256'].items()}
    pins['src/agenticvm/pxe_lab.py'] = value['host_source_sha256']
    rows.append(native_case('pxe-bios', path, selected['sha256'], pins))
    final = read(ROOT / 'docs/validation/realistic-validation-final.json')
    suite_path = inside(final['suite']['path'])
    if digest(suite_path) != final['suite']['sha256']:
        raise ValueError('Historical firmware suite changed')
    suite = read(suite_path)
    for route, profile in (('pxe-uefi', 'uefi-stock-rng'), ('uefi-secure-boot', 'uefi-secure-uki')):
        selected = next(row for row in suite['cases'] if row['profile'] == profile and 'lfm-fault-enrollment' in row['case'])
        path = inside(selected['path'])
        value = read(path)
        if route == 'uefi-secure-boot' and not (value['initial_boot_authenticated'] and value['secure_boot_enabled']):
            raise ValueError('Historical protected model boot was not enforced')
        rows.append(native_case(route, path, selected['sha256'], value['source_sha256'] | value['additional_source_sha256']))
    failed_path = ROOT / 'runtime/realism-runs/08e8cc9a-ccf1-4af0-8e33-9d32f6363309/report.json'
    failed = read(failed_path)
    if failed['passed'] or failed['profile'] != 'uefi-http':
        raise ValueError('Expected the retained unsuccessful native HTTP boot probe')
    rows.append({'route': 'uefi-http', 'level': 'adapter-built', 'passed': True,
        'native_os_observed': False, 'source_sha256': {'src/agenticvm/realism_lab.py': digest(ROOT / 'src/agenticvm/realism_lab.py')},
        'evidence': [{'path': failed_path.relative_to(ROOT).as_posix(), 'sha256': digest(failed_path),
            'native_probe_passed': False, 'observed_error': failed['error']}],
        'limitations': ['The source adapter exists; the retained native HTTP boot probe failed to find a usable firmware boot entry',
            'No successful native UEFI HTTP boot, enrollment, model or reboot acceptance is claimed']})
    receipts = []
    for row in rows:
        path = folder / (row['route'] + '.json')
        save(path, row)
        receipts.append(path.relative_to(ROOT).as_posix())
        child = subprocess.run([sys.executable, '-I', '-B', 'scripts/enrollment-matrix.py', '--record', str(path)],
            cwd=ROOT, capture_output=True, text=True)
        if child.returncode:
            raise RuntimeError('Historical evidence index failed: ' + child.stderr[-500:])
    save(folder / 'report.json', {'passed': True, 'native_cases_rerun': 0, 'receipts': receipts})
    print(json.dumps({'passed': True, 'native_cases_rerun': 0, 'report': str(folder / 'report.json')}, indent=2))


if __name__ == '__main__':
    main()
