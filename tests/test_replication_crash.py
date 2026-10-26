"""CP10 child-reservation crash recovery; no VM or model execution."""
import json
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4

from agenticvm.replication_policy import Ledger


CHILD = r'''
import json, os, pathlib, sys
sys.path.insert(0, sys.argv[2])
from agenticvm.replication_policy import Ledger
path, root, run_id, request_id, marker = sys.argv[1:]
ledger = Ledger(pathlib.Path(path), run_id=run_id, package_sha='a'*64, agent_sha='b'*64)
ledger.set_state('replica-0', 'starting')
ledger.set_state('replica-0', 'running')
ledger.handle('replica-0', {'op': 'hello', 'node_id': 'replica-0', 'parent': None,
    'generation': 0, 'package_sha256': 'a'*64, 'agent_sha256': 'b'*64,
    'reproduction_capable': True})
result = ledger.handle('replica-0', {'op': 'replicate', 'request_id': request_id,
    'package_sha256': 'a'*64})
pathlib.Path(marker).write_text(json.dumps(result))
os._exit(23)
'''


class ChildCrashRecovery(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='cp10-child-', dir=Path(__file__).resolve().parents[1] / 'runtime'))
        self.db = self.root / 'ledger.sqlite'
        self.run_id = str(uuid4())
        self.request_id = str(uuid4())
        self.marker = self.root / 'reservation.json'
        self.child = self.root / 'crash.py'
        self.child.write_text(CHILD)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def crash(self):
        env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}
        result = subprocess.run([sys.executable, '-I', '-B', str(self.child), str(self.db),
                                 str(Path(__file__).resolve().parents[1] / 'src'), self.run_id,
                                 self.request_id, str(self.marker)], env=env,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 23, result.stderr)
        return json.loads(self.marker.read_text())

    def test_crash_reservation_is_durable_aborted_and_not_replayed(self):
        reservation = self.crash()
        self.assertEqual(reservation['state'], 'queued')
        self.assertEqual(reservation['child'], 'replica-1')
        ledger = Ledger(self.db)
        try:
            before = ledger.snapshot()
            self.assertEqual([node['state'] for node in before['nodes']], ['running', 'queued'])
            recovered = ledger.recover_interrupted()
            self.assertEqual(recovered['aborted'], ['replica-0', 'replica-1'])
            self.assertEqual([node['state'] for node in recovered['nodes']], ['aborted', 'aborted'])
            with self.assertRaisesRegex(ValueError, 'running'):
                ledger.handle('replica-0', {'op': 'replicate', 'request_id': str(uuid4()),
                                             'package_sha256': 'a'*64})
            self.assertEqual(len(ledger.nodes()), 2)
            self.assertEqual(len(ledger.snapshot()['requests']), 1)
            self.assertEqual(ledger.recover_interrupted()['status'], 'clean')
        finally:
            ledger.close()

    def test_completed_replica_is_not_aborted(self):
        ledger = Ledger(self.db, run_id=self.run_id, package_sha='a'*64, agent_sha='b'*64)
        try:
            ledger.set_state('replica-0', 'starting')
            ledger.set_state('replica-0', 'running')
            ledger.handle('replica-0', {'op': 'hello', 'node_id': 'replica-0', 'parent': None,
                'generation': 0, 'package_sha256': 'a'*64, 'agent_sha256': 'b'*64,
                'reproduction_capable': True})
            ledger.set_state('replica-0', 'finishing')
            ledger.set_state('replica-0', 'completed')
            result = ledger.recover_interrupted()
            self.assertEqual(result['status'], 'clean')
            self.assertEqual(ledger.node('replica-0')['state'], 'completed')
        finally:
            ledger.close()


if __name__ == '__main__':
    unittest.main()
