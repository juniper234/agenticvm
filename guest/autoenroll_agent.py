"""Unprivileged auto-enrolled member agent: model evidence plus mTLS status.

The target generated its key locally and received its client certificate only
after the mother verified the installation receipt. This service has no
invite-signing or admission capability.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import ssl
import sys
import time
import urllib.request

SEED = Path('/etc/garden/autoenroll')
sys.path.insert(0, str(SEED))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from autoenroll_inventory import sign_canonical  # noqa: E402
from local_lfm import LocalLFM  # noqa: E402

BASE = Path('/var/lib/garden')
CONFIG = json.loads((BASE / 'autoenroll-config.json').read_text())
BOOT_ID = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
STATUS = Path('/var/lib/garden/autoenroll-status.json')


def context():
    ctx = ssl.create_default_context(cadata=CONFIG['mother_certificate'])
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(CONFIG['identity_certificate'], CONFIG['identity_key'])
    return ctx


def post_status(model, completions):
    snapshot = model.snapshot()
    body = {
        'schema': 'garden.autoenroll.agent-status.v1',
        'target_uuid': CONFIG['target_uuid'],
        'boot_id': BOOT_ID,
        'identity_fingerprint': CONFIG['identity_fingerprint'],
        'public_key': CONFIG['target_public_key'],
        'model': {**snapshot, 'calls': model.calls, 'completions': completions},
        'service': {'active': True, 'uid': os.getuid(), 'name': 'garden-autoenroll.service'},
        'signed_unix': int(time.time()),
    }
    body['signature'] = sign_canonical(CONFIG['identity_key'], body)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context()))
    request = urllib.request.Request(CONFIG['mother_status_url'], data=json.dumps(body).encode(),
                                     headers={'Content-Type': 'application/json'})
    with opener.open(request, timeout=30) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError('Mother status response exceeded its bound')
    return json.loads(raw)


def main():
    model = LocalLFM()
    model.start()
    completions = []
    for prompt in ('Greet the mother after zero-click enrollment.',
                   'Confirm the locally installed model is ready.'):
        completions.append(model.generate(prompt))
    ready = {
        'schema': 'garden.autoenroll.agent-ready.v1',
        'target_uuid': CONFIG['target_uuid'],
        'boot_id': BOOT_ID,
        'identity_fingerprint': CONFIG['identity_fingerprint'],
        'uid': os.getuid(),
        'pid': os.getpid(),
        'service': 'garden-autoenroll.service',
        'model': {**model.snapshot(), 'calls': model.calls, 'completions': completions},
    }
    STATUS.write_text(json.dumps(ready, sort_keys=True) + '\n')
    print('AUTOENROLL_AGENT_READY ' + json.dumps(ready, sort_keys=True), flush=True)
    while True:
        try:
            answer = post_status(model, completions)
            if answer.get('ok') is not True:
                raise ValueError('Mother did not accept the status')
            model.ensure_alive()
        except Exception as error:
            print('AUTOENROLL_AGENT_RETRY ' + json.dumps({
                'boot_id': BOOT_ID, 'error': type(error).__name__ + ': ' + str(error)}), flush=True)
        time.sleep(5)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('AUTOENROLL_AGENT_ERROR ' + json.dumps({
            'boot_id': BOOT_ID, 'error': type(error).__name__ + ': ' + str(error)}), flush=True)
        raise
