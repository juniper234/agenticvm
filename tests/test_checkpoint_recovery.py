"""CP10 checkpoint contract: hash chain, resume, identity and tamper denial."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from uuid import uuid4

from agenticvm.chain import Checkpoints
from agenticvm.peers import verify_journal


class CheckpointContract(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='cp10-checkpoints-', dir=Path(__file__).resolve().parents[1] / 'runtime'))
        self.run_id = str(uuid4())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def make(self, events=('created', 'downloading', 'download_verified')):
        journal = Checkpoints(self.root, self.run_id)
        for event in events:
            journal.add(event, sample=True)
        journal.close()
        return verify_journal(self.root / 'checkpoints.jsonl')

    def test_chain_verifies_and_reports_count(self):
        result = self.make()
        self.assertEqual(result['records'], 3)
        self.assertTrue(result['verified'])
        self.assertRegex(result['sha256'], r'^[0-9a-f]{64}$')

    def test_resume_appends_continuously(self):
        before = self.make()
        journal = Checkpoints(self.root, self.run_id, resume=True)
        journal.add('vms_starting', memory_mib=512)
        journal.close()
        after = verify_journal(self.root / 'checkpoints.jsonl')
        self.assertEqual(after['records'], 4)
        self.assertNotEqual(after['sha256'], before['sha256'])
        rows = [json.loads(line) for line in (self.root / 'checkpoints.jsonl').read_text().splitlines()]
        self.assertEqual(rows[-1]['previous'], before['sha256'])

    def test_tamper_is_rejected(self):
        self.make()
        path = self.root / 'checkpoints.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[1]['sample'] = False
        path.write_text(''.join(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n' for row in rows))
        with self.assertRaisesRegex(ValueError, 'chain'):
            verify_journal(path)

    def test_wrong_run_identity_is_rejected(self):
        self.make()
        with self.assertRaisesRegex(ValueError, 'identity'):
            Checkpoints(self.root, str(uuid4()), resume=True)

    def test_reserved_metadata_cannot_be_overwritten(self):
        journal = Checkpoints(self.root, self.run_id)
        for field, value in (('index', 9), ('sha256', '0' * 64), ('run_id', 'x'), ('previous', '0' * 64)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'reserved'):
                journal.add('phase', **{field: value})
        journal.close()
        self.assertEqual(verify_journal(self.root / 'checkpoints.jsonl')['records'], 0)


if __name__ == '__main__':
    unittest.main()
