"""Unregistered/stale negative-control beacon.

Generates an ephemeral local hello key, sends exactly one signed TARGET_HELLO,
records the mother denial, and keeps no identity, key, service, model or garden
state. The key exists only in a temporary directory for the duration of the
request.
"""
from __future__ import annotations

import json
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, '/workspace/autoenroll')
from autoenroll_inventory import sign_canonical  # noqa: E402

CONFIG = json.loads(Path('/workspace/lab/beacon-config.json').read_text())
OPENSSL = '/usr/bin/openssl'


def post_hello(hello):
    context = ssl.create_default_context(cadata=CONFIG['mother_certificate'])
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(CONFIG['mother_url'] + '/autoenroll/hello',
                                     data=json.dumps(hello).encode(),
                                     headers={'Content-Type': 'application/json'})
    with opener.open(request, timeout=20) as response:
        return response.status, response.read(4096).decode(errors='replace')


def main():
    print('NEGATIVE_BEACON_START ' + json.dumps({'fixture': CONFIG['fixture'],
                                                 'target_uuid': CONFIG['target_uuid']}), flush=True)
    with tempfile.TemporaryDirectory(prefix='negative-beacon-') as directory:
        folder = Path(directory)
        key, pub = folder / 'identity.key', folder / 'identity.pub'
        subprocess.run([OPENSSL, 'genpkey', '-algorithm', 'ed25519', '-out', str(key)],
                       check=True, capture_output=True, timeout=15)
        subprocess.run([OPENSSL, 'pkey', '-in', str(key), '-pubout', '-out', str(pub)],
                       check=True, capture_output=True, timeout=15)
        hello = {
            'schema': 'garden.target-hello.v1',
            'target_uuid': CONFIG['target_uuid'],
            'mac': CONFIG['target_mac'],
            'nonce': str(uuid4()),
            'timestamp': int(time.time()),
            'public_key': pub.read_text(),
        }
        hello['signature'] = sign_canonical(key, hello)
        try:
            status, body = post_hello(hello)
            print('NEGATIVE_BEACON_RESPONSE ' + json.dumps({'status': status, 'body': body}), flush=True)
        except urllib.error.HTTPError as error:
            detail = error.read(4096).decode(errors='replace')
            print('NEGATIVE_BEACON_DENIED ' + json.dumps({'status': error.code, 'body': detail,
                                                          'fixture': CONFIG['fixture']}), flush=True)
        except Exception as error:
            print('NEGATIVE_BEACON_ERROR ' + json.dumps({
                'fixture': CONFIG['fixture'], 'error': type(error).__name__ + ': ' + str(error)}), flush=True)
            raise


if __name__ == '__main__':
    main()
