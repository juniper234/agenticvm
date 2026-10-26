"""Wire integrity, independent interoperability and durable delegation checks."""
import base64
import gc
import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'guest'))
from agenticvm import bounded_torrent as wire
sys.modules.setdefault('bounded_torrent', wire)
import delegated_agent as agent


class TorrentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.seed = self.folder / 'model.gguf'
        self.data = bytes(range(251)) * 13000
        self.seed.write_bytes(self.data)
        self.entry = {'bytes': len(self.data), 'sha256': hashlib.sha256(self.data).hexdigest(), 'torrent': wire.metadata(self.seed)}
        self.output = self.folder / 'received'
        self.output.mkdir()
        self.destination = self.output / 'model.gguf'

    def start(self, **kwargs):
        seed = wire.Seeder({'model.gguf': (self.seed, self.entry)}, ('127.0.0.1', 0), '127.0.0.1', **kwargs)
        self.addCleanup(seed.close)
        return seed

    def download(self, seed, **kwargs):
        values = {'name': 'model.gguf', 'size': len(self.data), 'sha256': self.entry['sha256'], 'source': seed.address}
        return wire.download(self.entry['torrent'], self.destination, **{**values, **kwargs})

    def test_real_socket_transfer_and_piece_resume_after_disconnect(self):
        seed = self.start(interrupt=True)
        receipt = self.download(seed)
        self.assertEqual(self.destination.read_bytes(), self.data)
        self.assertTrue(receipt['resumed'])
        self.assertGreaterEqual(receipt['resume_verified_bytes'], 2 * 1024**2 - wire.PIECE)
        self.assertEqual(receipt['reconnections'], 1)
        self.assertEqual(seed.stats['injected_disconnects'], 1)
        self.assertFalse(seed.errors)

    def test_complete_sha256_failure_never_activates(self):
        seed = self.start()
        with self.assertRaisesRegex(ValueError, 'integrity'):
            self.download(seed, sha256='0' * 64)
        self.assertFalse(self.destination.exists())

    def test_modified_partial_is_repaired_before_activation(self):
        partial = self.destination.with_suffix('.gguf.partial')
        partial.write_bytes(self.data[:wire.PIECE] + b'changed' * 50)
        receipt = self.download(self.start())
        self.assertEqual(self.destination.read_bytes(), self.data)
        self.assertEqual(receipt['resume_verified_bytes'], wire.PIECE)

    def test_metadata_cannot_add_peers_trackers_paths_or_size(self):
        meta = wire.bdecode(base64.b64decode(self.entry['torrent']))
        bad = [base64.b64encode(wire.bencode({**meta, b'announce': b'http://elsewhere'})).decode()]
        for field, value in ((b'name', b'../escape'), (b'length', len(self.data) + 1), (b'private', 0), (b'piece length', 16384)):
            other = {b'info': {**meta[b'info'], field: value}}
            bad.append(base64.b64encode(wire.bencode(other)).decode())
        for value in bad:
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                wire.parse(value, 'model.gguf', len(self.data))

    def test_noncanonical_duplicate_deep_and_trailing_bencoding_rejected(self):
        for raw in (b'd1:ai01ee', b'd1:ai1e1:ai2ee', b'd1:bi1e1:ai2ee', b'i1ex', b'9:short', b'd' * 10):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                wire.bdecode(raw)

    def test_oversized_wire_frame_and_handshake_mismatch_fail_closed(self):
        left, right = socket.socketpair()
        with left, right:
            right.sendall(b'\xff\xff\xff\xff')
            with self.assertRaisesRegex(ValueError, 'limit'):
                wire.receive(left)
        seed = self.start()
        with socket.create_connection(seed.address, timeout=2) as conn:
            conn.sendall(wire.HEADER + bytes(40))
            self.assertEqual(conn.recv(1), b'')

    def test_download_from_independent_libtorrent_seeder(self):
        from agenticvm.torrent import load_libtorrent, local_session, add
        lt = load_libtorrent(ROOT)
        torrent = self.folder / 'asset.torrent'
        torrent.write_bytes(base64.b64decode(self.entry['torrent']))
        session = local_session(lt)
        handle = add(lt, session, lt.torrent_info(str(torrent)), self.folder)
        try:
            deadline = time.monotonic() + 10
            while not handle.status().is_seeding or not session.is_listening():
                if time.monotonic() > deadline:
                    self.fail('Independent seeder did not become ready')
                time.sleep(.05)
            fixture = type('Seed', (), {'address': ('127.0.0.1', session.listen_port())})()
            self.download(fixture)
            self.assertEqual(self.destination.read_bytes(), self.data)
        finally:
            session.remove_torrent(handle)
            session.pause()
            handle = session = None
            gc.collect()

    def test_independent_libtorrent_downloads_from_new_seeder(self):
        from agenticvm.torrent import load_libtorrent, local_session, add
        lt = load_libtorrent(ROOT)
        seed = self.start()
        torrent = self.folder / 'asset.torrent'
        torrent.write_bytes(base64.b64decode(self.entry['torrent']))
        session = local_session(lt)
        session.apply_settings({'out_enc_policy': int(lt.enc_policy.disabled),
                                'in_enc_policy': int(lt.enc_policy.disabled)})
        handle = add(lt, session, lt.torrent_info(str(torrent)), self.output)
        try:
            deadline, reconnect = time.monotonic() + 12, 0
            while not handle.status().is_seeding:
                if time.monotonic() > deadline:
                    self.fail('Independent receiver did not complete: ' + str(seed.errors))
                if time.monotonic() > reconnect:
                    handle.connect_peer(seed.address)
                    reconnect = time.monotonic() + 1
                time.sleep(.05)
            self.assertEqual(self.destination.read_bytes(), self.data)
            self.assertGreaterEqual(seed.stats['payload_bytes_sent'], len(self.data))
            self.assertFalse(seed.errors)
        finally:
            session.remove_torrent(handle)
            session.pause()
            handle = session = None
            gc.collect()


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.node = object.__new__(agent.Node)
        self.node.config = {'garden': str(uuid4()), 'request_id': str(uuid4()), 'target_uuid': str(uuid4()),
                            'manifest_sha256': '1' * 64, 'bootstrap_sha256': '2' * 64}
        self.node.identity = 'offshoot-1'
        self.node.lock = threading.RLock()
        self.node.db = sqlite3.connect(':memory:')
        self.node.db.row_factory = sqlite3.Row
        self.node.db.execute('CREATE TABLE delegation(id TEXT PRIMARY KEY,task_sha256 TEXT,state TEXT,receipt TEXT)')
        self.addCleanup(self.node.db.close)
        self.task = {**self.node.config, 'target': 'sprout-4', 'sponsor': 'offshoot-1', 'grant': 'g' * 40,
                     'deadline_unix_ms': int(time.time() * 1000) + 300_000}

    def test_complete_duplicate_calls_installer_once_without_storing_grant(self):
        receipt = {'ok': True, 'duplicate': False, 'fixture': 'completed proof'}
        with patch.object(self.node, 'provision', return_value=receipt) as provision:
            self.assertEqual(self.node.delegate('mother', self.task), receipt)
            self.assertEqual(self.node.delegate('mother', self.task), {**receipt, 'duplicate': True})
            self.assertEqual(provision.call_count, 1)
        dump = '\n'.join(self.node.db.iterdump())
        self.assertNotIn(self.task['grant'], dump)
        self.assertNotIn('deadline_unix_ms', dump)

    def test_failed_or_uncertain_installation_is_never_replayed(self):
        with patch.object(self.node, 'provision', side_effect=OSError('fixture interruption')) as provision:
            with self.assertRaises(OSError):
                self.node.delegate('mother', self.task)
            with self.assertRaisesRegex(ValueError, 'not replayed'):
                self.node.delegate('mother', self.task)
            self.assertEqual(provision.call_count, 1)

    def test_wrong_actor_target_package_scope_and_expiry_denied(self):
        invalid = [('offshoot-2', self.task), ('mother', {**self.task, 'target': 'negative-control'}),
                   ('mother', {**self.task, 'target_uuid': str(uuid4())}),
                   ('mother', {**self.task, 'manifest_sha256': '0' * 64}),
                   ('mother', {**self.task, 'deadline_unix_ms': 0}),
                   ('mother', {**self.task, 'shell': 'unapproved'})]
        with patch.object(self.node, 'provision') as provision:
            for actor, task in invalid:
                with self.subTest(actor=actor, task=task), self.assertRaises(ValueError):
                    self.node.delegate(actor, task)
            provision.assert_not_called()

    def test_changed_duplicate_cannot_reuse_completed_transaction(self):
        with patch.object(self.node, 'provision', return_value={'ok': True, 'duplicate': False}):
            self.node.delegate('mother', self.task)
            with self.assertRaisesRegex(ValueError, 'Changed duplicate'):
                self.node.delegate('mother', {**self.task, 'grant': 'x' * 40})

    def test_bootstrap_is_valid_python_without_running_fixture(self):
        script = agent.bootstrap_source({'fixture': True}, (ROOT / 'guest/lan_install.py').read_text(),
                                        (ROOT / 'src/agenticvm/bounded_torrent.py').read_text())
        compile(script, '<reviewed-bootstrap>', 'exec')
        self.assertNotIn('garden@', script)


class DelegationTLSTests(unittest.TestCase):
    def test_only_authenticated_mother_can_trigger_the_prepared_sponsor(self):
        from agenticvm.lan_lab import certificate
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            public = {name: certificate(folder, name, address) for name, address in
                      (('mother', '192.0.2.1'), ('offshoot-1', '192.0.2.2'), ('offshoot-2', '192.0.2.3'))}
            (folder / 'identity.pem').write_bytes((folder / 'offshoot-1.pem').read_bytes())
            (folder / 'identity.key').write_bytes((folder / 'offshoot-1.key').read_bytes())
            node = object.__new__(agent.Node)
            node.identity, node.known, node.lock = 'offshoot-1', public, threading.RLock()
            node.config = {'garden': str(uuid4()), 'request_id': str(uuid4()), 'target_uuid': str(uuid4()),
                           'manifest_sha256': '1' * 64, 'bootstrap_sha256': '2' * 64}
            node.db = sqlite3.connect(':memory:', check_same_thread=False)
            node.db.row_factory = sqlite3.Row
            node.db.execute('CREATE TABLE delegation(id TEXT PRIMARY KEY,task_sha256 TEXT,state TEXT,receipt TEXT)')
            task = {**node.config, 'target': 'sprout-4', 'sponsor': 'offshoot-1', 'grant': 'g' * 40,
                    'deadline_unix_ms': int(time.time() * 1000) + 300_000}
            with patch.object(agent.base, 'BASE', folder), patch.object(node, 'provision', return_value={'ok': True, 'duplicate': False}) as provision:
                server = agent.base.SecureServer(('127.0.0.1', 0), agent.Handler)
                server.node, server.control = node, False
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    for identity in ('offshoot-2', 'mother'):
                        ctx = ssl.create_default_context(cadata=public['offshoot-1']['certificate'])
                        ctx.check_hostname = False  # Host fixture uses loopback, native VMs use their real IP SANs.
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                        ctx.load_cert_chain(folder / (identity + '.pem'), folder / (identity + '.key'))
                        if identity == 'offshoot-2':
                            with self.assertRaisesRegex(ValueError, 'Only mother'):
                                agent.base.request('127.0.0.1', server.server_port, '/delegate', ctx,
                                                   body=task, expected=public['offshoot-1']['sha256'], timeout=3)
                        else:
                            response, tls = agent.base.request('127.0.0.1', server.server_port, '/delegate', ctx,
                                                               body=task, expected=public['offshoot-1']['sha256'], timeout=3)
                            self.assertTrue(response['ok'])
                            self.assertEqual(tls['version'], 'TLSv1.3')
                    self.assertEqual(provision.call_count, 1)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(2)
                    node.db.close()


if __name__ == '__main__':
    unittest.main()
