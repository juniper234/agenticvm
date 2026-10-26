"""Owner-prepared receiver: one signed fixed action, bounded scope and no replay."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time
import urllib.request

CONFIG = Path('/etc/garden/pull-receiver.json')
CONTROL = Path('/var/lib/garden-control')
FIELDS = {'schema', 'request_id', 'target', 'mac', 'expires_unix', 'nonce', 'bootstrap_sha256', 'action'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def validate_job(job, config, now):
    if (not isinstance(job, dict) or set(job) != FIELDS or job['schema'] != 'garden.owned-job.v1'
            or job['request_id'] != config['request_id'] or job['target'] != 'sprout-4'
            or job['mac'] != '52:54:00:4c:41:04' or job['action'] != 'install-native-garden'
            or type(job['expires_unix']) is not int or not now < job['expires_unix'] <= now + 1200
            or not isinstance(job['nonce'], str) or len(job['nonce']) != 36
            or job['bootstrap_sha256'] != config['bootstrap_sha256']):
        raise ValueError('Signed pull job scope, lifetime or action mismatch')
    return True


def verify_signature(job, signature, public_key, *, openssl='/usr/bin/openssl'):
    with tempfile.TemporaryDirectory(prefix='garden-signed-job-') as directory:
        folder = Path(directory)
        (folder / 'payload').write_bytes(canonical(job))
        (folder / 'signature').write_bytes(base64.b64decode(signature, validate=True))
        (folder / 'public.pem').write_text(public_key)
        result = subprocess.run([str(openssl), 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(folder / 'public.pem'),
            '-sigfile', str(folder / 'signature'), '-in', str(folder / 'payload')], capture_output=True, timeout=10)
        if result.returncode:
            raise ValueError('Signed pull job authentication failed')


def main():
    config = json.loads(CONFIG.read_text())
    CONTROL.mkdir(mode=0o700, parents=True, exist_ok=True)
    CONTROL.chmod(0o700)
    ledger = CONTROL / 'pull-ledger.json'
    if ledger.exists():
        raise ValueError('Prior signed job is not replayed; reconciliation is required')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 120
    while True:
        try:
            with opener.open('http://192.0.2.1:8080/managed/' + config['request_id'] + '/job.json', timeout=10) as response:
                raw = response.read(16385)
            if len(raw) > 16384:
                raise ValueError('Signed pull job exceeds input bound')
            envelope = json.loads(raw)
            break
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)
    if set(envelope) != {'job', 'signature'}:
        raise ValueError('Unexpected signed pull envelope')
    job = envelope['job']
    verify_signature(job, envelope['signature'], config['public_key'])
    validate_job(job, config, int(time.time()))
    if not any(Path('/sys/class/net').glob('*/address')) or not any(
            path.read_text().strip() == job['mac'] for path in Path('/sys/class/net').glob('*/address')):
        raise ValueError('Signed pull target MAC does not match this native VM')
    bootstrap = Path('/etc/garden/bootstrap.py')
    if hashlib.sha256(bootstrap.read_bytes()).hexdigest() != job['bootstrap_sha256']:
        raise ValueError('Signed pull bootstrap content changed')
    with ledger.open('x') as output:
        json.dump({'nonce': job['nonce'], 'request_id': job['request_id'], 'state': 'executing'}, output)
        output.flush()
        os.fsync(output.fileno())
    runpy.run_path(str(bootstrap), run_name='__main__')
    temporary = ledger.with_suffix('.tmp')
    temporary.write_text(json.dumps({'nonce': job['nonce'], 'request_id': job['request_id'], 'state': 'complete'}))
    temporary.replace(ledger)
    with open('/dev/ttyS0', 'w') as console:
        print('\nMANAGED_PULL_COMPLETE ' + json.dumps({'nonce': job['nonce'], 'request_id': job['request_id'],
              'signature_verified': True, 'action': job['action']}), file=console, flush=True)
    os.sync()


if __name__ == '__main__':
    main()
