"""Receipt body must verify every signed field, including duplicate/expires."""
from pathlib import Path
import shutil
import tempfile
import unittest

from agenticvm.garden_identity import allowed_signers, canonical, generate, sign, verify


class ReceiptContractTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='receipt-contract-', dir=Path(__file__).resolve().parents[1] / 'runtime'))
        self.mother = generate('m-cccccccccccccccc', self.root / 'mother')
        self.allowed = self.root / 'allowed'
        self.allowed.write_text(allowed_signers('m-cccccccccccccccc', self.mother['public']))
        self.receipt = {
            'schema': 'agenticvm.garden-join-receipt.v1',
            'member': 'm-dddddddddddddddd',
            'garden': 'garden',
            'nonce': 'nonce',
            'package_sha256': 'a' * 64,
            'admitted': True,
            'duplicate': True,
            'issued': 1,
            'expires': 2,
        }
        self.signature = sign(self.mother['private'], canonical(self.receipt))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_all_signed_fields_verify(self):
        body = {key: value for key, value in self.receipt.items() if key != 'sig'}
        self.assertTrue(verify(self.allowed, 'm-cccccccccccccccc', canonical(body), self.signature))

    def test_old_seven_key_body_omitting_duplicate_fails(self):
        old = {key: self.receipt[key] for key in
               ('schema', 'member', 'garden', 'nonce', 'package_sha256', 'admitted', 'issued')}
        self.assertFalse(verify(self.allowed, 'm-cccccccccccccccc', canonical(old), self.signature))


if __name__ == '__main__':
    unittest.main()
