"""Actual Ed25519 signatures, scoped jobs, expiry and interrupted-job refusal."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'guest')]
from agenticvm.lan_lab import OPENSSL
from agenticvm.managed_pull_lab import ManagedPullAdapter
import managed_pull as receiver


class SignedPullTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.key = self.folder / 'issuer.key'
        subprocess.run([str(OPENSSL), 'genpkey', '-algorithm', 'ed25519', '-out', str(self.key)], check=True, capture_output=True)
        self.public = subprocess.run([str(OPENSSL), 'pkey', '-in', str(self.key), '-pubout'], check=True, capture_output=True).stdout.decode()
        self.now = int(time.time())
        self.job = {'schema': 'garden.owned-job.v1', 'request_id': str(uuid4()), 'target': 'sprout-4',
                    'mac': '52:54:00:4c:41:04', 'expires_unix': self.now + 300, 'nonce': str(uuid4()),
                    'bootstrap_sha256': 'a' * 64, 'action': 'install-native-garden'}
        self.config = {'request_id': self.job['request_id'], 'bootstrap_sha256': 'a' * 64}

    def sign(self, job):
        path = self.folder / 'job'
        path.write_bytes(receiver.canonical(job))
        raw = subprocess.run([str(OPENSSL), 'pkeyutl', '-sign', '-rawin', '-inkey', str(self.key), '-in', str(path)],
                              check=True, capture_output=True).stdout
        return base64.b64encode(raw).decode()

    def test_actual_signature_does_not_authenticate_changed_job_or_wrong_issuer(self):
        signature = self.sign(self.job)
        receiver.verify_signature(self.job, signature, self.public, openssl=OPENSSL)
        with self.assertRaisesRegex(ValueError, 'authentication'):
            receiver.verify_signature({**self.job, 'action': 'different-command'}, signature, self.public, openssl=OPENSSL)
        changed = bytearray(base64.b64decode(signature));changed[3] ^= 1
        with self.assertRaisesRegex(ValueError, 'authentication'):
            receiver.verify_signature(self.job, base64.b64encode(changed).decode(), self.public, openssl=OPENSSL)

    def test_signed_but_expired_overscoped_or_arbitrary_action_is_rejected(self):
        receiver.validate_job(self.job, self.config, self.now)
        for change in ({'expires_unix': self.now}, {'expires_unix': self.now + 1201}, {'expires_unix': True},
                       {'target': 'another-system'}, {'mac': '52:54:00:4c:41:05'}, {'action': '/bin/sh'},
                       {'bootstrap_sha256': 'b' * 64}, {'request_id': str(uuid4())}, {'extra': 'unapproved'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                receiver.validate_job({**self.job, **change}, self.config, self.now)

    def test_interrupted_or_completed_job_is_not_fetched_or_replayed(self):
        config = self.folder / 'receiver.json'
        config.write_text(json.dumps(self.config))
        control = self.folder / 'control'
        control.mkdir()
        (control / 'pull-ledger.json').write_text(json.dumps({'state': 'executing'}))
        with patch.object(receiver, 'CONFIG', config), patch.object(receiver, 'CONTROL', control), patch.object(receiver.urllib.request, 'build_opener') as network:
            with self.assertRaisesRegex(ValueError, 'not replayed'):
                receiver.main()
            network.assert_not_called()


class ManagedPullEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        (self.folder / 'signed-pull-job.json').write_text('{}')
        self.adapter = ManagedPullAdapter()
        self.adapter.job = {'nonce': 'nonce', 'request_id': 'request', 'action': 'install-native-garden'}
        self.adapter.envelope_sha256 = '0' * 64
        self.adapter.vm = type('VM', (), {'folder': self.folder})()
        self.completion = {'nonce': 'nonce', 'request_id': 'request',
                           'signature_verified': True, 'action': 'install-native-garden'}

    def write_log(self, suffix='\n'):
        (self.folder / 'boot-1.log').write_text('MANAGED_PULL_COMPLETE ' + json.dumps(self.completion) + suffix)

    def test_clean_completion_is_accepted(self):
        self.write_log()
        self.assertTrue(self.adapter.finish(self.folder)['signed_job_completed'])

    def test_completion_json_survives_systemd_suffix(self):
        self.write_log('[  OK  ] Finished cloud-final.service - Cloud-init: Final Stage.\n')
        self.assertTrue(self.adapter.finish(self.folder)['signed_job_completed'])

    def test_wrong_or_partial_completion_is_rejected(self):
        for value in ({**self.completion, 'nonce': 'other'}, {**self.completion, 'action': '/bin/sh'}):
            with self.subTest(value=value):
                (self.folder / 'boot-1.log').write_text('MANAGED_PULL_COMPLETE ' + json.dumps(value) + '\n')
                self.assertFalse(self.adapter.finish(self.folder)['signed_job_completed'])
        (self.folder / 'boot-1.log').write_text('MANAGED_PULL_COMPLETE {"nonce":\n')
        self.assertFalse(self.adapter.finish(self.folder)['signed_job_completed'])


if __name__ == '__main__':
    unittest.main()
