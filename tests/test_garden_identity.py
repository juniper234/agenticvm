"""Ed25519 member identity tests; no network, no persistent secrets."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from agenticvm.garden_identity import allowed_signers, canonical, generate, sign, verify

WORK = Path(__file__).resolve().parents[1] / 'runtime'


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='garden-identity-', dir=WORK))
        self.member = 'm-0123456789abcdef'
        self.identity = generate(self.member, self.root / 'one')
        self.allowed = self.root / 'allowed'
        self.allowed.write_text(allowed_signers(self.member, self.identity['public']))
        self.payload = canonical({'schema': 'agenticvm.garden-response.v1', 'id': 'x', 'member': self.member})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_round_trip(self):
        signature = sign(self.identity['private'], self.payload)
        self.assertTrue(verify(self.allowed, self.member, self.payload, signature))

    def test_tampered_payload_fails(self):
        signature = sign(self.identity['private'], self.payload)
        self.assertFalse(verify(self.allowed, self.member, self.payload + b' ', signature))

    def test_wrong_member_fails(self):
        signature = sign(self.identity['private'], self.payload)
        other = 'm-fedcba9876543210'
        self.assertFalse(verify(self.allowed, other, self.payload, signature))

    def test_wrong_key_fails(self):
        signature = sign(self.identity['private'], self.payload)
        second = generate('m-1111111111111111', self.root / 'two')
        allowed = self.root / 'second-allowed'
        allowed.write_text(allowed_signers('m-1111111111111111', second['public']))
        self.assertFalse(verify(allowed, 'm-1111111111111111', self.payload, signature))

    def test_namespace_and_id_validation(self):
        from agenticvm.garden_identity import NAMESPACE
        self.assertEqual(NAMESPACE, 'agenticvm-garden-v1')
        with self.assertRaises(ValueError):
            generate('not-a-member', self.root / 'bad')
        with self.assertRaises(ValueError):
            allowed_signers(self.member, 'ssh-rsa AAAA')

    def test_public_key_must_be_single_line(self):
        with self.assertRaisesRegex(ValueError, 'single-line'):
            allowed_signers(self.member, self.identity['public'] + '\nm-other AAAA')
        with self.assertRaisesRegex(ValueError, 'single-line'):
            allowed_signers(self.member, self.identity['public'].replace(' ', ' \n', 1))
        self.assertIn('garden key comment',
                      allowed_signers(self.member, self.identity['public'] + ' garden key comment'))
