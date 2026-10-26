"""Exercise offline platform preparation and scope/expiry/tampering controls."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.platform_contracts import REFERENCES, preparation, validate_preparation
from agenticvm.lan_lab import digest, save


def main():
    folder = ROOT / 'runtime/platform-contracts' / str(uuid4())
    folder.mkdir(parents=True)
    sources = {name: digest(ROOT / name) for name in ('src/agenticvm/platform_contracts.py', 'scripts/verify-platform-contracts.py')}
    now, target = int(time.time()), str(uuid4())
    payload = hashlib.sha256(b'inert local contract fixture; not a native platform installer').hexdigest()
    receipts = []
    for route in REFERENCES:
        plan = preparation(route, folder.name, target, payload, now=now)
        scope = dict(route=route, run_id=folder.name, target_id=target, payload_sha256=payload, now=now)
        pin = validate_preparation(plan, **scope)
        rejected = []
        for name, change in (
            ('wrong-target', lambda v: v.update(owned_target_uuid=str(uuid4()))),
            ('changed-payload', lambda v: v.update(payload_sha256='0' * 64)),
            ('arbitrary-command', lambda v: v['artifact'].update(command='unreviewed')),
            ('enabled-delivery', lambda v: v.update(delivery_enabled=True)),
            ('false-native-claim', lambda v: v.update(native_acceptance=True)),
            ('credential-injection', lambda v: v.update(credentials='inert-invalid-value')),
            ('expired', lambda v: v.update(expires_at=now)),
        ):
            altered = copy.deepcopy(plan)
            change(altered)
            try:
                validate_preparation(altered, **scope)
            except ValueError:
                rejected.append(name)
            else:
                raise ValueError('Contract accepted ' + name)
        path = folder / (route + '.preparation.json')
        save(path, plan)
        receipt = {'route': route, 'level': 'contract-tested', 'passed': True, 'native_os_observed': False,
            'source_sha256': sources, 'evidence': [{'path': path.relative_to(ROOT).as_posix(), 'sha256': digest(path),
                'canonical_plan_sha256': pin, 'rejected': rejected}],
            'limitations': ['Offline preparation/owner-scope contract checks only; no platform API or native schema certification',
                'No Windows package, tenant delivery client, AMT wire client, OS/model/reboot or hardware acceptance is implemented by this contract',
                'Resources and native implementation listed in the preparation are still required']}
        output = folder / (route + '.json')
        save(output, receipt)
        receipts.append(output.relative_to(ROOT).as_posix())
        child = subprocess.run([sys.executable, '-I', '-B', 'scripts/enrollment-matrix.py', '--record', str(output)],
            cwd=ROOT, capture_output=True, text=True)
        if child.returncode:
            raise RuntimeError('Could not record preparation contract: ' + child.stderr[-500:])
    save(folder / 'report.json', {'passed': True, 'native_acceptance': False, 'routes': len(receipts),
        'contract_checks': len(receipts) * 8, 'receipts': receipts, 'source_sha256': sources})
    print(json.dumps({'passed': True, 'native_acceptance': False, 'routes': len(receipts),
        'contract_checks': len(receipts) * 8, 'report': str(folder / 'report.json')}, indent=2))


if __name__ == '__main__':
    main()
