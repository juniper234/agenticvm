#!/usr/bin/python3
"""Target-side one-shot join service: verify invite, send signed TLS request."""
import base64
import json
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time

CONFIG = pathlib.Path(sys.argv[1])
STATE = pathlib.Path('/var/lib/agenticvm')
KEY = STATE / 'member.key'
JOINED = STATE / 'joined.json'
NS = 'agenticvm-garden-v1'


def load(path):
    return json.loads(pathlib.Path(path).read_text())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def verify(allowed, principal, payload, signature, sig_path):
    pathlib.Path(sig_path).write_bytes(base64.b64decode(signature))
    result = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', allowed,
                             '-I', principal, '-n', NS, '-s', sig_path],
                            input=payload, capture_output=True, timeout=15)
    return result.returncode == 0


def sign(private, payload, path):
    path = pathlib.Path(path)
    path.write_bytes(payload)
    signature_path = pathlib.Path(str(path) + '.sig')
    if signature_path.exists():
        signature_path.unlink()
    result = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', private,
                             '-n', NS, str(path)], capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError('ssh-keygen sign failed')
    return signature_path.read_bytes()


def main():
    config = load(CONFIG)
    STATE.mkdir(parents=True, exist_ok=True)
    allowed_mother = pathlib.Path(config['mother_allowed'])
    invite = load(config['invite'])
    invite_raw = pathlib.Path(config['invite']).read_bytes()
    # Private 0700 directory: no /tmp symlink/FIFO dependence or cross-run races.
    with tempfile.TemporaryDirectory(prefix='join-', dir=STATE) as temp:
        temp = pathlib.Path(temp)
        if not verify(allowed_mother, config['mother_member'], invite_raw,
                      load(config['invite_sig'])['sig'], temp / 'invite.sig'):
            raise RuntimeError('invite signature rejected')
        if (invite.get('member') != config['member'] or invite.get('garden') != config['garden']
                or invite.get('package_sha256') != config['package_sha256']
                or int(invite.get('expires', 0)) <= int(time.time())):
            raise RuntimeError('invite binding rejected')
        if not KEY.exists():
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', config['member'],
                            '-f', str(KEY)], check=True, timeout=30)
        public = pathlib.Path(str(KEY) + '.pub').read_text().strip()
        request = {'schema': 'agenticvm.garden-join-request.v1', 'member': config['member'],
                   'garden': config['garden'], 'package_sha256': config['package_sha256'],
                   'nonce': invite['nonce'], 'issued': int(time.time()),
                   'expires': int(time.time()) + 30, 'public_key': public}
        signature = sign(str(KEY), canonical(request), temp / 'join-request')
        request['sig'] = base64.b64encode(signature).decode()
        context = ssl.create_default_context(cafile=config['mother_cert'])
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((config['mother_host'], int(config['mother_port'])), timeout=20) as raw:
            with context.wrap_socket(raw, server_hostname=config['mother_host']) as tls:
                tls.sendall((json.dumps(request) + '\n').encode())
                data = b''
                while b'\n' not in data and len(data) < 65536:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        receipt = json.loads(data.split(b'\n', 1)[0])
        if receipt.get('schema') != 'agenticvm.garden-join-receipt.v1':
            raise RuntimeError('receipt schema rejected')
        body = {key: value for key, value in receipt.items() if key != 'sig'}
        if not verify(allowed_mother, config['mother_member'], canonical(body),
                      receipt['sig'], temp / 'receipt.sig'):
            raise RuntimeError('receipt signature rejected')
        now = int(time.time())
        expected = {'member': config['member'], 'garden': config['garden'],
                    'nonce': invite['nonce'], 'package_sha256': config['package_sha256']}
        for field, value in expected.items():
            if body.get(field) != value:
                raise RuntimeError('receipt ' + field + ' mismatch')
        if int(body.get('issued', 0)) < now - 300 or int(body.get('issued', 0)) > now + 60:
            raise RuntimeError('receipt freshness rejected')
        if int(body.get('expires', 0)) < now:
            raise RuntimeError('receipt expired')
        if not body.get('admitted'):
            raise RuntimeError('join was not admitted')
        JOINED.write_text(json.dumps({'joined': True, 'receipt': receipt,
                                      'public_key': public}, indent=2) + '\n')
        print('JOINED ' + json.dumps({'member': config['member'], 'garden': config['garden'],
                                      'duplicate': bool(body.get('duplicate'))}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('JOIN_ERROR ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise
