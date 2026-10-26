"""Mode B root bootstrap: verify policy/invite, private torrent install, join.

The target starts with no garden artifacts. This script is delivered by the
owner-controlled NoCloud seed, verifies the owner policy and mother-signed
invite before any execution, installs as UID/GID 1000, and records a signed
receipt. It never uses console input.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from uuid import uuid4

SEED = Path('/etc/garden/autoenroll')
sys.path.insert(0, str(SEED))
from autoenroll_inventory import (  # noqa: E402
    canonical, digest_json, identity_fingerprint, sign_canonical,
    strict_json, verify_invite, verify_policy,
)
from bounded_torrent import download  # noqa: E402

CONFIG = json.loads((SEED / 'target-config.json').read_text())
HOME = Path('/var/lib/garden')
OPENSSL = '/usr/bin/openssl'
POLICY = CONFIG['policy']
TARGET_UUID = CONFIG['target_uuid']
TARGET_MAC = CONFIG['target_mac']
MOTHER = CONFIG['mother_url']
MOTHER_CERT = CONFIG['mother_certificate']
OWNER_PUBLIC = CONFIG['owner_public_key']
ABSENCE_NAMES = ('peer/lan_agent.py', 'model.gguf', 'identity.key', 'lan-config.json')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def context():
    ctx = ssl.create_default_context(cadata=MOTHER_CERT)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def post(path, body, *, timeout=60):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context()))
    request = urllib.request.Request(MOTHER + path, data=json.dumps(body).encode(),
                                     headers={'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        detail = error.read(65537).decode(errors='replace')
        raise RuntimeError(f'Mother rejected {path}: HTTP {error.code}: {detail}') from error
    if len(raw) > 1024 * 1024:
        raise ValueError('Mother response exceeded its bound')
    return strict_json(raw)


def openssl(*args):
    result = subprocess.run([OPENSSL, *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('OpenSSL failed: ' + result.stderr[-800:])
    return result


def verify_target_seed():
    if any((HOME / name).exists() for name in ABSENCE_NAMES):
        raise ValueError('Target is not initially garden-free')
    verify_policy(POLICY, trusted_owner_public_key=OWNER_PUBLIC)
    if POLICY['garden'] != CONFIG['garden']:
        raise ValueError('Target garden seed mismatch')
    target = next((row for row in POLICY['allowed_targets'] if row['uuid'] == TARGET_UUID), None)
    if target is None or target['mac'] != TARGET_MAC:
        raise ValueError('Target is not registered in the owner policy')


def generate_identity():
    key = HOME / 'identity.key'
    csr = HOME / 'identity.csr'
    public = HOME / 'identity.pub'
    openssl('genpkey', '-algorithm', 'ed25519', '-out', str(key))
    openssl('req', '-new', '-key', str(key), '-subj', '/CN=' + TARGET_UUID,
            '-addext', f'subjectAltName=URI:urn:agenticvm:autoenroll:{TARGET_UUID},IP:192.0.2.4',
            '-out', str(csr))
    openssl('pkey', '-in', str(key), '-pubout', '-out', str(public))
    key.chmod(0o600)
    return key, csr, public.read_text()


def install_agent(manifest, stage):
    peer = HOME / 'peer'
    peer.mkdir(parents=True, exist_ok=True)
    with tarfile.open(stage / 'agent.tar.gz') as archive:
        for item in archive:
            if not item.isfile() or Path(item.name).name != item.name or item.name not in ('autoenroll_agent.py', 'local_lfm.py'):
                raise ValueError('Unexpected agent archive member')
            target = peer / item.name
            target.write_bytes(archive.extractfile(item).read())
            target.chmod(0o500)
    with tarfile.open(stage / 'llama.tar.gz') as archive:
        for item in archive:
            if item.name.startswith('/') or '..' in Path(item.name).parts or item.size > 32 * 1024**2:
                raise ValueError('Unsafe inference archive')
            target = HOME / 'llama' / item.name
            if item.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(item).read())
                target.chmod(item.mode & 0o755)
            elif item.issym() and '/' not in item.linkname:
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    target.symlink_to(item.linkname)
            elif not item.isdir():
                raise ValueError('Unexpected inference archive type')
    (HOME / 'dependencies').mkdir(parents=True, exist_ok=True)
    for source, target in ((stage / 'model.gguf', HOME / 'model.gguf'),
                           (stage / 'libgomp.so.1', HOME / 'dependencies/libgomp.so.1')):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        if sha(target) != manifest['files'][source.name]['sha256']:
            raise ValueError('Activated package digest mismatch')
        target.chmod(0o400)
    for path in (HOME,):
        path.chmod(0o700)


def service(agent_config):
    unit = '''[Unit]
Description=Authorized auto-enrolled garden member
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/garden/autoenroll-config.json
[Service]
User=1000
Group=1000
Environment=MALLOC_ARENA_MAX=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 LLAMA_ARG_REPACK=0
Environment=HOME=/var/lib/garden
ExecStart=/usr/bin/python3 -I -B /var/lib/garden/peer/autoenroll_agent.py
Restart=on-failure
RestartSec=3
StandardOutput=append:/var/lib/garden/agent.log
StandardError=append:/var/lib/garden/agent.log
[Install]
WantedBy=multi-user.target
'''
    path = Path('/etc/systemd/system/garden-autoenroll.service')
    path.write_text(unit)
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, capture_output=True, timeout=20)
    subprocess.run(['/usr/bin/systemctl', 'enable', 'garden-autoenroll.service'], check=True,
                   capture_output=True, timeout=20)


def service_diagnostics():
    details = {}
    for name, args in (
        ('is_active', ['/usr/bin/systemctl', 'is-active', 'garden-autoenroll.service']),
        ('is_enabled', ['/usr/bin/systemctl', 'is-enabled', 'garden-autoenroll.service']),
        ('status', ['/usr/bin/systemctl', 'status', '--no-pager', '-n', '20', 'garden-autoenroll.service']),
        ('journal', ['/usr/bin/journalctl', '--no-pager', '-n', '25', '-u', 'garden-autoenroll.service']),
    ):
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=15)
            details[name] = (result.stdout + result.stderr)[-3000:]
        except Exception as error:
            details[name] = type(error).__name__ + ': ' + str(error)
    for name in ('agent.log', 'autoenroll-config.json'):
        try:
            details[name] = (HOME / name).read_text(errors='replace')[-3000:]
        except Exception as error:
            details[name] = type(error).__name__ + ': ' + str(error)
    return details


def main():
    before = {name: (HOME / name).exists() for name in ABSENCE_NAMES}
    verify_target_seed()
    HOME.mkdir(parents=True, exist_ok=True)
    os.chown(HOME, 1000, 1000)
    key, csr, public = generate_identity()
    hello = {
        'schema': 'garden.target-hello.v1',
        'target_uuid': TARGET_UUID,
        'mac': TARGET_MAC,
        'nonce': str(uuid4()),
        'timestamp': int(time.time()),
        'public_key': public,
    }
    hello['signature'] = sign_canonical(key, hello)
    answer = post('/autoenroll/hello', hello)
    invite = answer['invite']
    verify_invite(invite, POLICY, target_uuid=TARGET_UUID, target_mac=TARGET_MAC)
    invite_sha = digest_json(invite)
    started = post('/autoenroll/start', {
        'invite_sha256': invite_sha, 'request_id': invite['request_id'],
        'target_uuid': TARGET_UUID})
    manifest = started['manifest']
    if (manifest.get('schema') != 'garden.autoenroll.package.v1'
            or manifest.get('torrent_infohash') != invite['torrent_infohash']
            or manifest['files']['model.gguf']['sha256'] != invite['model_sha256']
            or manifest['files']['agent.tar.gz']['sha256'] != invite['package_sha256']):
        raise ValueError('Package manifest does not match the invite')
    stage = HOME / 'download'
    stage.mkdir(parents=True, exist_ok=True)
    receipts = []
    for name, item in manifest['files'].items():
        receipts.append(download(item['torrent'], stage / name, name=name, size=item['bytes'],
                                 sha256=item['sha256'], source=(started['peer'], started['port'])))
    total_bytes = sum(item['bytes'] for item in receipts)
    install_agent(manifest, stage)
    (HOME / 'autoenroll-config.json').write_text(json.dumps({
        'schema': 'garden.autoenroll.agent-config.v1',
        'garden': POLICY['garden'],
        'target_uuid': TARGET_UUID,
        'target_mac': TARGET_MAC,
        'mother_url': MOTHER,
        'mother_status_url': MOTHER.replace(':8443', ':9443') + '/autoenroll/status',
        'mother_certificate': MOTHER_CERT,
        'identity_key': str(key),
        'identity_certificate': str(HOME / 'identity.pem'),
        'target_public_key': public,
        'identity_fingerprint': identity_fingerprint(public),
        'policy_sha256': digest_json(POLICY),
        'invite_sha256': invite_sha,
        'package_sha256': invite['package_sha256'],
        'model_sha256': invite['model_sha256'],
        'torrent_infohash': invite['torrent_infohash'],
        'torrent_receipt': {'peer': started['peer'], 'bytes': total_bytes, 'trackers': 0,
                            'dht': False, 'pex': False},
    }, sort_keys=True) + '\n')
    receipt = {
        'schema': 'garden.autoenroll.receipt.v1',
        'request_id': invite['request_id'],
        'lease_id': invite['lease_id'],
        'target_uuid': TARGET_UUID,
        'target_mac': TARGET_MAC,
        'action': invite['action'],
        'package_sha256': invite['package_sha256'],
        'model_sha256': invite['model_sha256'],
        'torrent_infohash': invite['torrent_infohash'],
        'torrent_receipt': {'peer': started['peer'], 'bytes': total_bytes, 'trackers': 0,
                            'dht': False, 'pex': False},
        'identity_fingerprint': identity_fingerprint(public),
        'target_public_key': public,
        'initial_absence': before,
        'boot_id': boot_id(),
        'zero_click': True,
        'interactive_input': False,
        'signed_unix': int(time.time()),
    }
    receipt['target_signature'] = sign_canonical(key, receipt)
    admitted = post('/autoenroll/receipt', {'invite': invite, 'receipt': receipt})
    if admitted.get('admitted') is not True:
        raise ValueError('Mother did not admit the receipt')
    issued = post('/autoenroll/certificate', {'target_uuid': TARGET_UUID,
                                              'csr': csr.read_text()})
    (HOME / 'identity.pem').write_text(issued['certificate'])
    os.chown(HOME / 'identity.pem', 1000, 1000)
    os.chown(HOME / 'identity.key', 1000, 1000)
    for path in (HOME / 'peer', HOME / 'llama', HOME / 'dependencies'):
        subprocess.run(['/bin/chown', '-R', '1000:1000', str(path)], check=True, timeout=30)
    for path in (HOME / 'model.gguf', HOME / 'autoenroll-config.json', HOME / 'agent.log'):
        if path.exists():
            os.chown(path, 1000, 1000)
    (HOME / 'agent.log').touch()
    os.chown(HOME / 'agent.log', 1000, 1000)
    service(None)
    subprocess.run(['/usr/bin/systemctl', 'start', 'garden-autoenroll.service'], check=True,
                   capture_output=True, timeout=30)
    deadline = time.monotonic() + 300
    ready = None
    while time.monotonic() < deadline:
        text = (HOME / 'agent.log').read_text(errors='replace') if (HOME / 'agent.log').exists() else ''
        for line in reversed(text.splitlines()):
            if line.startswith('AUTOENROLL_AGENT_READY '):
                ready = json.loads(line.split(' ', 1)[1])
                break
        if ready:
            break
        if subprocess.run(['/usr/bin/systemctl', 'is-active', 'garden-autoenroll.service'],
                          capture_output=True, text=True, timeout=10).stdout.strip() != 'active':
            details = service_diagnostics()
            raise RuntimeError('Auto-enrollment agent service is not active: ' + json.dumps(details, sort_keys=True))
        time.sleep(1)
    if ready is None:
        raise TimeoutError('Auto-enrollment agent did not become ready')
    complete = {
        'schema': 'garden.autoenroll.target-report.v1',
        'target_uuid': TARGET_UUID,
        'receipt': receipt,
        'receipt_sha256': digest_json(receipt),
        'admitted': admitted,
        'certificate_sha256': issued['certificate_sha256'],
        'torrent_receipts': receipts,
        'initial_absence': before,
        'boot_id': boot_id(),
        'agent_ready': ready,
        'zero_click': True,
        'interactive_input': False,
        'boot_mode': 'mode-a-bootstrap-listener',
    }
    (HOME / 'autoenroll-complete.json').write_text(json.dumps(complete, sort_keys=True) + '\n')
    print('AUTOENROLL_BOOTSTRAP_COMPLETE ' + json.dumps(complete, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        try:
            HOME.mkdir(parents=True, exist_ok=True)
            (HOME / 'autoenroll-error.json').write_text(json.dumps({
                'error': type(error).__name__ + ': ' + str(error),
                'initial_absence': {name: (HOME / name).exists() for name in ABSENCE_NAMES},
                'boot_id': boot_id(), 'uid': os.getuid(),
                'service': service_diagnostics(),
            }) + '\n')
        except Exception:
            pass
        print('AUTOENROLL_TARGET_ERROR ' + json.dumps({'error': type(error).__name__ + ': ' + str(error)}), flush=True)
        raise
