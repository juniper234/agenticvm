"""CP6 package verification and safe staging extraction.

The Ed25519 signature, package hash, version floor and archive inventory are
checked before any activation. This module never executes package contents.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tarfile

from .garden_identity import NAMESPACE, canonical, verify

SCHEMA = 'agenticvm.cp6-package.v1'
NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
VERSION = re.compile(r'^cp6[a-z]?-([0-9]+)$')


def _sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def version(value):
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise ValueError('Package version must be cp6?-<integer>')
    return int(match.group(1))


def validate(manifest, signature, allowed, member, *, expected_sha, current_version=None,
             namespace=NAMESPACE):
    """Verify the signed manifest and enforce package identity/anti-rollback."""
    if not isinstance(manifest, dict) or set(manifest) != {'schema', 'version', 'payload'}:
        raise ValueError('Invalid package manifest fields')
    if manifest['schema'] != SCHEMA:
        raise ValueError('Unknown package schema')
    number = version(manifest['version'])
    if current_version is not None and number <= version(current_version):
        raise ValueError('Package rollback rejected')
    payload = manifest['payload']
    if not isinstance(payload, dict) or set(payload) != {'name', 'bytes', 'sha256', 'torrent'}:
        raise ValueError('Invalid package payload fields')
    if not NAME.fullmatch(payload['name']) or not 1 <= payload['bytes'] <= 250 * 1024**2:
        raise ValueError('Invalid package payload')
    if not isinstance(payload['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', payload['sha256']):
        raise ValueError('Invalid package SHA-256')
    if payload['sha256'] != expected_sha:
        raise ValueError('Package hash pin mismatch')
    if not isinstance(payload['torrent'], str) or len(payload['torrent']) > 180 * 1024:
        raise ValueError('Invalid package torrent metadata')
    if not verify(allowed, member, canonical(manifest), signature):
        raise ValueError('Package signature rejected')
    return payload


def extract(archive, staging, *, expected_sha, expected_names=None):
    """Extract a verified archive without symlinks, devices or path escapes."""
    archive, staging = Path(archive), Path(staging)
    if not archive.is_file() or _sha(archive) != expected_sha:
        raise ValueError('Archive SHA-256 mismatch')
    staging.mkdir(parents=True, exist_ok=True)
    names = []
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe archive entry type')
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe archive path')
            names.append(member.name)
        if len(names) != len(set(names)):
            raise ValueError('Duplicate archive entry')
        if expected_names is not None and set(names) != set(expected_names):
            raise ValueError('Archive inventory mismatch')
        tar.extractall(staging, filter='data')
    files = {path.relative_to(staging).as_posix() for path in staging.rglob('*') if path.is_file()}
    if expected_names is not None and files != set(expected_names):
        raise ValueError('Extracted inventory mismatch')
    return sorted(files)
