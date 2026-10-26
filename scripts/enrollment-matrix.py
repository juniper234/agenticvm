"""Inspect coverage and persist checkpoints for the local enrollment work."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.enrollment_catalog import catalog, validate_receipt, STAGES
from agenticvm.chain import exclusive

PATH = ROOT / 'docs/enrollment-matrix-progress.json'


def locked_main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', type=Path)
    args = parser.parse_args()
    if PATH.exists():
        state = json.loads(PATH.read_text())
    else:
        state = {'schema': 'agenticvm.enrollment-matrix.v1', 'scope': 'Owned local isolated labs; public evaluation media permitted',
                 'complete': False, 'routes': catalog(), 'current_work': 'Acquire public Ubuntu/CoreOS images and build native first-boot profiles'}
    if args.record:
        source = args.record.resolve()
        if not source.is_relative_to(ROOT):
            raise ValueError('Receipts must be inside this workspace')
        receipt = validate_receipt(json.loads(source.read_text()))
        route = next(row for row in state['routes'] if row['id'] == receipt['route'])
        name = source.relative_to(ROOT).as_posix()
        if name not in route['receipts']:
            route['receipts'].append(name)
        if receipt['passed'] and STAGES.index(receipt['level']) > STAGES.index(route['stage']):
            route['stage'] = receipt['level']
    for row in state['routes']:
        row['unmet_prerequisites'] = []
        row['current_source_receipts'], row['historical_receipts'] = [], []
        for name in row['receipts']:
            path = (ROOT / name).resolve()
            if not path.is_relative_to(ROOT) or not path.is_file():
                raise ValueError('Missing or redirected coverage receipt: ' + name)
            receipt = validate_receipt(json.loads(path.read_text()))
            if receipt['route'] != row['id']:
                raise ValueError('Coverage receipt route changed')
            changed = []
            for source_name, pin in receipt['source_sha256'].items():
                source_path = (ROOT / source_name).resolve()
                if not source_path.is_relative_to(ROOT) or not source_path.is_file():
                    changed.append(source_name)
                    continue
                with source_path.open('rb') as stream:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                if actual != pin:
                    changed.append(source_name)
            if changed:
                row['historical_receipts'].append({'receipt': name, 'changed_sources': changed})
            elif receipt['passed']:
                row['current_source_receipts'].append(name)
        levels = [validate_receipt(json.loads((ROOT / name).read_text()))['level'] for name in row['current_source_receipts']]
        row['current_source_stage'] = max(['catalogued', *levels], key=STAGES.index)
        if row['resource'] in ('cloud-tenant', 'physical-amt', 'physical-tpm-and-tenant', 'physical-mac-and-tenant'):
            row['unmet_prerequisites'] = ['Full native acceptance requires external tenant or physical hardware outside the approved local-only scope']
        elif row['resource'] in ('local-windows', 'local-domain') and shutil.disk_usage(ROOT).free < 40 * 1024**3:
            row['unmet_prerequisites'] = ['Local lab storage policy requires 40 GiB free for evaluation media, a 32 GB Windows system partition and headroom; current host storage is insufficient']
    state['current_work'] = 'Four current-source first-boot routes (cloud-init local/network, ignition local/network) passed all twenty native cases. Redfish, IPMI, guest-agent and managed-pull hold current-source five-case native suites. Native installer routes remain untested; gated platform contracts are offline preparation only. Separately, the owner-authorized auto-enrollment profile has native current-source C3 mother-direct, C5 negative controls, C6 three-target courier pool, and C7 Mode A listener evidence; C4 is the C3 audit; auto-enrollment is not one of these 28 routes and its evidence boundaries are recorded in the auto-enrollment checkpoints. C8 coverage/docs passed: current pins verified, matrix generator current-work corrected, pre-C8 indexes archived, and auto-enrollment coverage/boundaries recorded separately. C9 UI redesign and C10 final acceptance passed; no installer, tenant, physical, Windows or public-swarm claim.'
    state['host_free_bytes_at_checkpoint'] = shutil.disk_usage(ROOT).free
    temp = PATH.with_suffix('.tmp')
    temp.write_text(json.dumps(state, indent=2) + '\n')
    temp.replace(PATH)
    print(json.dumps({'complete': state['complete'], 'routes': len(state['routes']),
                      'coverage': [{'id': row['id'], 'stage': row['current_source_stage'], 'prerequisites': row['unmet_prerequisites']} for row in state['routes']]}, indent=2))


if __name__ == '__main__':
    lock = ROOT / 'runtime/enrollment-matrix-state'
    lock.mkdir(exist_ok=True)
    deadline = time.monotonic() + 15
    while True:
        try:
            with exclusive(lock):
                locked_main()
            break
        except RuntimeError as error:
            if str(error) != 'Another agent chain is running in this folder' or time.monotonic() >= deadline:
                raise
            time.sleep(.1)
