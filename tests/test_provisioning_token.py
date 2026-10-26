"""Provisioning control endpoints require the per-target bearer token."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import shutil
import sys
from pathlib import Path
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'guest'))
import lan_agent
from lan_agent import Handler

TOKEN = 't' * 43


class Node:
    install_token = TOKEN


class ProvisioningTokenTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='token-', dir=ROOT / 'runtime'))
        (self.root / 'lab').mkdir()
        (self.root / 'lab/manifest.json').write_text('{"files":{}}')
        self.old_base = lan_agent.BASE
        lan_agent.BASE = self.root
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.control = True
        self.server.node = Node()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        lan_agent.BASE = self.old_base
        shutil.rmtree(self.root, ignore_errors=True)

    def get(self, token=None):
        connection = HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            headers = {'Authorization': 'Bearer ' + token} if token else {}
            connection.request('GET', '/manifest', headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_missing_token_rejected(self):
        status, raw = self.get()
        self.assertEqual(status, 403)
        self.assertIn(b'Wrong provisioning token', raw)

    def test_correct_token_accepted(self):
        status, raw = self.get(TOKEN)
        self.assertEqual(status, 200)
        self.assertIn(b'"files"', raw)

    def test_wrong_token_rejected(self):
        status, raw = self.get('x' * 43)
        self.assertEqual(status, 403)


if __name__ == '__main__':
    unittest.main()
