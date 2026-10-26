"""JoinServer survives failed pre-auth connections; one peer cannot kill it."""
import importlib.util
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agenticvm.garden_identity import generate
from agenticvm.garden_policy import GardenPolicy
from agenticvm.garden_store import GardenStore

spec = importlib.util.spec_from_file_location('cp6b_support', ROOT / 'scripts/run-redteam-cp6b-join.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


class JoinServerAcceptTests(unittest.TestCase):
    def test_two_plain_connections_do_not_close_listener(self):
        work = ROOT / 'runtime' / ('join-accept-' + uuid.uuid4().hex[:8])
        work.mkdir(parents=True)
        probe = socket.socket()
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        support.WORK, support.JOIN_PORT = work, port
        support.TARGET_MEMBER = 'm-aaaaaaaaaaaaaaaa'
        crt, key = support.cert()
        policy = GardenPolicy.create('join-accept', ['10.0.2.0/24'], methods=('tcp',), max_total=3,
                                     max_depth=1, max_active=1)
        store = GardenStore(work / 'garden')
        store.init(policy)
        mother = generate('m-bbbbbbbbbbbbbbbb', work / 'mother')
        server = support.JoinServer(crt, key, mother, {'nonce': '00' * 16, 'package_sha256': '0' * 64},
                                    b'{}', store, policy)
        try:
            for _ in range(2):
                sock = socket.create_connection(('127.0.0.1', port), timeout=2)
                sock.close()
            deadline = time.monotonic() + 5
            while len(server.errors) < 2 and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertGreaterEqual(len(server.errors), 2)
            self.assertTrue(server.thread.is_alive())
            self.assertIsNone(server.result)
        finally:
            server.close()
        self.assertFalse(server.thread.is_alive())
        self.assertFalse(work.joinpath('target-allowed').exists())


if __name__ == '__main__':
    unittest.main()
