"""Asymmetric member identity using OpenSSH Ed25519 SSHSIG.

No custom cryptography: ssh-keygen signs and verifies a canonical JSON payload
in a fixed namespace; the allowed-signers file binds a member ID to its public
key. Callers still own transport and replay policy.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

NAMESPACE = 'agenticvm-garden-v1'
MEMBER = re.compile(r'^m-[0-9a-f]{16}$')
PUBLIC = re.compile(r'^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]+)?$')
SSH_KEYGEN = Path(os.environ.get('AGENTICVM_SSH_KEYGEN', r'C:\Windows\System32\OpenSSH\ssh-keygen.exe'))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def generate(member, folder):
    if not MEMBER.fullmatch(member):
        raise ValueError('member ID must be m- followed by 16 lowercase hex characters')
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    private, public = folder / 'member.key', folder / 'member.key.pub'
    for path in (private, public):
        if path.exists():
            raise ValueError('identity path already exists')
    result = subprocess.run([str(SSH_KEYGEN), '-q', '-t', 'ed25519', '-N', '', '-C', member,
                             '-f', str(private)], capture_output=True, text=True, timeout=30)
    if result.returncode or not private.is_file() or not public.is_file():
        raise RuntimeError('ssh-keygen failed: ' + result.stderr[-500:])
    return {'member': member, 'private': str(private), 'public': public.read_text().strip(),
            'public_path': str(public), 'namespace': NAMESPACE}


def allowed_signers(member, public):
    if not MEMBER.fullmatch(member):
        raise ValueError('member ID must be m- followed by 16 lowercase hex characters')
    if not isinstance(public, str) or not PUBLIC.fullmatch(public):
        raise ValueError('single-line Ed25519 public key required')
    return f'{member} namespaces="{NAMESPACE}" {public}\n'


def sign(private, payload, *, folder=None):
    private = Path(private)
    if not private.is_file():
        raise ValueError('private key missing')
    base = Path(folder) if folder else private.parent
    base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sshsig-', dir=base) as temp:
        message, signature = Path(temp) / 'message', Path(temp) / 'message.sig'
        message.write_bytes(payload)
        result = subprocess.run([str(SSH_KEYGEN), '-Y', 'sign', '-f', str(private),
                                 '-n', NAMESPACE, str(message)],
                                capture_output=True, timeout=30)
        if result.returncode or not signature.is_file():
            raise RuntimeError('ssh-keygen sign failed: ' + result.stderr.decode(errors='replace')[-500:])
        return signature.read_bytes()


def verify(allowed, member, payload, signature, *, folder=None):
    allowed = Path(allowed)
    if not allowed.is_file():
        raise ValueError('allowed-signers file missing')
    base = Path(folder) if folder else allowed.parent
    base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sshsig-', dir=base) as temp:
        signature_path = Path(temp) / 'signature.sig'
        signature_path.write_bytes(signature)
        result = subprocess.run([str(SSH_KEYGEN), '-Y', 'verify', '-f', str(allowed),
                                 '-I', member, '-n', NAMESPACE, '-s', str(signature_path)],
                                input=payload, capture_output=True, timeout=30)
        return result.returncode == 0
