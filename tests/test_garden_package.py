"""CP6 package trust tests: signature, hash, rollback, extraction safety."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from agenticvm.garden_identity import allowed_signers, canonical, generate, sign
from agenticvm.garden_package import extract, validate, version


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='cp6-package-', dir=Path(__file__).resolve().parents[1] / 'runtime'))
        self.member = 'm-0123456789abcdef'
        self.identity = generate(self.member, self.root / 'key')
        self.allowed = self.root / 'allowed'
        self.allowed.write_text(allowed_signers(self.member, self.identity['public']))
        self.data = b'package-bytes'
        import hashlib
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.manifest = {'schema': 'agenticvm.cp6-package.v1', 'version': 'cp6b-2',
                         'payload': {'name': 'agent.tar.gz', 'bytes': len(self.data),
                                     'sha256': self.digest, 'torrent': 'd'}}

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def signature(self, manifest=None):
        return sign(self.identity['private'], canonical(manifest or self.manifest))

    def test_valid_signature_and_hash(self):
        payload = validate(self.manifest, self.signature(), self.allowed, self.member,
                           expected_sha=self.digest, current_version='cp6b-1')
        self.assertEqual(payload['sha256'], self.digest)

    def test_tampered_manifest_signature_rejected(self):
        bad = dict(self.manifest, version='cp6b-3')
        with self.assertRaisesRegex(ValueError, 'signature'):
            validate(bad, self.signature(), self.allowed, self.member, expected_sha=self.digest)

    def test_wrong_hash_and_rollback_rejected(self):
        with self.assertRaisesRegex(ValueError, 'hash'):
            validate(self.manifest, self.signature(), self.allowed, self.member, expected_sha='0' * 64)
        with self.assertRaisesRegex(ValueError, 'rollback'):
            validate(self.manifest, self.signature(), self.allowed, self.member,
                     expected_sha=self.digest, current_version='cp6b-2')

    def test_version_parser(self):
        self.assertEqual(version('cp6b-12'), 12)
        for value in ('cp6b', 'cp6b-x', '1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                version(value)

    def test_extract_rejects_traversal_and_partial_inventory(self):
        archive = self.root / 'agent.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            info = tarfile.TarInfo('../escape')
            info.size = 1
            tar.addfile(info, io.BytesIO(b'x'))
        with self.assertRaisesRegex(ValueError, 'path'):
            extract(archive, self.root / 'out', expected_sha=self._sha(archive))
        good = self.root / 'good.tar.gz'
        with tarfile.open(good, 'w:gz') as tar:
            for name in ('agent/a.py', 'agent/b.py'):
                info = tarfile.TarInfo(name)
                info.size = 1
                tar.addfile(info, io.BytesIO(b'x'))
        with self.assertRaisesRegex(ValueError, 'inventory'):
            extract(good, self.root / 'out2', expected_sha=self._sha(good),
                    expected_names={'agent/a.py', 'agent/b.py', 'agent/c.py'})

    def _sha(self, path):
        import hashlib
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
