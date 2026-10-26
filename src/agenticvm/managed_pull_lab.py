"""Deliver a signed fixed enrollment job to an owner-prepared native receiver."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
from uuid import uuid4

from .lan_lab import ROOT, OPENSSL, digest, save
from .native_console import json_records
from .native_vm import NativeVM


class ManagedPullAdapter:
    route, kind, seed_route = 'managed-pull', 'ubuntu', 'cloud-init-local'
    source_paths = ['src/agenticvm/managed_pull_lab.py', 'guest/managed_pull.py']
    limitations = ['The owner prepares the signed-job receiver and public trust key using NoCloud in this local fixture',
                   'One fixed install action; run identity and target MAC scope are not TPM hardware attestation']
    def prepare_inputs(self, folder, public, runtime, payloads, metadata):
        config = json.loads(payloads['user-data'].decode().split('\n', 1)[1])
        bootstrap = next(item['content'] for item in config['write_files'] if item['path'] == '/etc/garden/bootstrap.py')
        pin = hashlib.sha256(bootstrap.encode()).hexdigest()
        job = {'schema': 'garden.owned-job.v1', 'request_id': folder.name, 'target': 'sprout-4', 'mac': '52:54:00:4c:41:04',
               'expires_unix': int(time.time()) + 1200, 'nonce': str(uuid4()), 'bootstrap_sha256': pin, 'action': 'install-native-garden'}
        canonical = json.dumps(job, sort_keys=True, separators=(',', ':')).encode()
        with tempfile.TemporaryDirectory(prefix='garden-job-issuer-') as directory:
            temp = Path(directory)
            key, pub = temp / 'issuer.key', temp / 'issuer.pem'
            subprocess.run([str(OPENSSL), 'genpkey', '-algorithm', 'ed25519', '-out', str(key)], check=True, capture_output=True, timeout=10)
            subprocess.run([str(OPENSSL), 'pkey', '-in', str(key), '-pubout', '-out', str(pub)], check=True, capture_output=True, timeout=10)
            (temp / 'job.json').write_bytes(canonical)
            signed = subprocess.run([str(OPENSSL), 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(temp / 'job.json')],
                                    check=True, capture_output=True, timeout=10).stdout
            public_key = pub.read_text()
        envelope = json.dumps({'job': job, 'signature': base64.b64encode(signed).decode()}).encode()
        metadata = {**metadata, '/managed/' + folder.name + '/job.json': base64.b64encode(envelope).decode()}
        receiver_config = {'request_id': folder.name, 'bootstrap_sha256': pin, 'public_key': public_key}
        unit = '''[Unit]
Description=Owner-prepared signed job receiver
After=network-online.target
Wants=network-online.target
ConditionPathExists=!/var/lib/garden/native-install-complete.json
[Service]
Type=exec
ExecStart=/usr/bin/python3 -I -B /etc/garden/managed-pull.py
RuntimeMaxSec=600
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
'''
        config['write_files'] += [
            {'path': '/etc/garden/managed-pull.py', 'permissions': '0600', 'content': (ROOT / 'guest/managed_pull.py').read_text()},
            {'path': '/etc/garden/pull-receiver.json', 'permissions': '0600', 'content': json.dumps(receiver_config)},
            {'path': '/etc/systemd/system/garden-pull.service', 'permissions': '0644', 'content': unit}]
        config['runcmd'] = [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', 'garden-pull.service']]
        self.job = job
        self.envelope_sha256 = hashlib.sha256(envelope).hexdigest()
        save(folder / 'signed-pull-job.json', {'envelope': json.loads(envelope), 'public_key': public_key})
        return {**payloads, 'user-data': ('#cloud-config\n' + json.dumps(config)).encode()}, metadata
    def create_vm(self, *args, **kwargs):
        self.vm = NativeVM(*args, **kwargs)
        return self.vm
    def tick(self, target, folder):
        pass
    def finish(self, folder):
        log = getattr(self, 'vm', None)
        path = log.folder / 'boot-1.log' if log else None
        completed = False
        if path and path.exists():
            markers = json_records(path.read_text(errors='replace'), 'MANAGED_PULL_COMPLETE ')
            if markers:
                observed = markers[-1]
                completed = observed == {'nonce': self.job['nonce'], 'request_id': self.job['request_id'],
                                         'signature_verified': True, 'action': self.job['action']}
        if (folder / 'guest-report.json').exists() and not completed:
            raise ValueError('Native signed job has no completed receiver proof')
        return {'signed_job_completed': completed, 'envelope_sha256': self.envelope_sha256,
                'job_evidence': 'signed-pull-job.json', 'job_evidence_sha256': digest(folder / 'signed-pull-job.json')}
