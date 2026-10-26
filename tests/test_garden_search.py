"""Bounded search evidence and adapter behavior; read-only local loopback."""
import contextlib
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from agenticvm import cli
from agenticvm.garden_search import SearchRequest, search


class LocalService:
    def __init__(self):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(8)
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with connection:
                try:
                    connection.sendall(b'TEST-BANNER\n')
                except OSError:
                    pass
        self.socket.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stopped.set()
        self.thread.join(2)


class SearchTests(unittest.TestCase):
    def test_inventory_is_not_authorization_and_tcp_is_evidence(self):
        with LocalService() as service:
            request = SearchRequest('127.0.0.1/32', (service.port,), timeout_ms=500)
            result = search(request, inventory=['127.0.0.1'])
            candidate = result['candidates'][0]
            self.assertEqual(candidate['state'], 'inventory_responsive')
            self.assertEqual(result['responsive'], 1)
            self.assertEqual([obs['method'] for obs in candidate['observations']],
                             ['inventory', 'tcp'])
            tcp = candidate['observations'][1]
            self.assertTrue(tcp['reachable'])
            self.assertEqual(tcp['banner_bytes'], 12)
            self.assertEqual(len(tcp['banner_sha256']), 64)

    def test_closed_port_is_silent_but_evidence_is_retained(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        result = search(SearchRequest('127.0.0.1/32', (port,), timeout_ms=100))
        self.assertEqual(result['responsive'], 0)
        self.assertEqual(result['candidates'][0]['state'], 'silent')
        self.assertFalse(result['candidates'][0]['observations'][0]['reachable'])

    def test_passive_observation_and_scope_bounds(self):
        result = search(SearchRequest('127.0.0.1/32', (1,), timeout_ms=60),
                        passive=[{'address': '127.0.0.1', 'source': 'arp'}])
        self.assertEqual(result['candidates'][0]['observations'][0]['method'], 'passive')
        with self.assertRaises(ValueError):
            SearchRequest('10.66.0.0/23')
        with self.assertRaises(ValueError):
            SearchRequest('10.66.0.0/24', (22, 22))
        with self.assertRaises(ValueError):
            SearchRequest('10.66.0.0/24', (0,))
        with self.assertRaises(ValueError):
            SearchRequest('not-a-scope')

    def test_probe_adapter_failure_is_bounded(self):
        def boom(*_):
            raise RuntimeError('adapter failed')
        result = search(SearchRequest('127.0.0.1/32', (1,)), connect=boom)
        self.assertFalse(result['candidates'][0]['observations'][0]['reachable'])
        self.assertEqual(result['candidates'][0]['observations'][0]['error'], 'RuntimeError')

    def test_cli_search_receipts_scope(self):
        with tempfile.TemporaryDirectory() as directory, LocalService() as service:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(['--garden-dir', directory, 'garden', 'init',
                                           '--scope', '127.0.0.1/32']), 0)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.main(['--garden-dir', directory, 'garden', 'search',
                                 '--scope', '127.0.0.1/32', '--port', str(service.port)])
            value = json.loads(out.getvalue())
            self.assertEqual(code, 0, value)
            self.assertEqual(value['result']['responsive'], 1)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli.main(['--garden-dir', directory, 'garden', 'receipts'])
            self.assertIn('garden_search', out.getvalue())
