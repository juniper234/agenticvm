"""Authenticated challenge/response ping: success, replay, expiry and errors."""
import contextlib
import io
import json
import secrets
import socket
import tempfile
import time
import unittest

from agenticvm import cli
from agenticvm.garden_ping import PingServer, challenge, ping, response, verify_challenge, verify_response

KEY = secrets.token_bytes(32)
GARDEN = 'g' * 32
MEMBER = 'm-0123456789abcdef'


class PingTests(unittest.TestCase):
    def server(self):
        server = PingServer(KEY, GARDEN, MEMBER)
        server.start()
        self.addCleanup(server.stop)
        return server

    def test_successful_response(self):
        server = self.server()
        result = ping('127.0.0.1', server.address[1], KEY, GARDEN, MEMBER)
        self.assertTrue(result['reachable'])
        self.assertTrue(result['garden_member'])
        self.assertEqual(len(server.events), 1)
        self.assertTrue(server.events[0]['ok'])

    def test_wrong_key_is_authentication_failure(self):
        server = self.server()
        result = ping('127.0.0.1', server.address[1], secrets.token_bytes(32), GARDEN, MEMBER)
        self.assertTrue(result['reachable'])
        self.assertFalse(result['garden_member'])
        self.assertIn('authentication', result['error'])

    def test_replay_is_rejected(self):
        server = self.server()
        request = challenge(KEY, GARDEN, MEMBER)
        for expected in (True, False):
            with socket.create_connection(('127.0.0.1', server.address[1]), timeout=2) as stream:
                stream.sendall((json.dumps(request) + '\n').encode())
                reply = json.loads(stream.recv(8192).split(b'\n', 1)[0])
            self.assertEqual(reply.get('schema') == 'agenticvm.garden-response.v1', expected)

    def test_expiry_and_correlation(self):
        expired = challenge(KEY, GARDEN, MEMBER, ttl=1, now=time.time() - 60)
        with self.assertRaises(ValueError):
            verify_challenge(expired, KEY)
        request = challenge(KEY, GARDEN, MEMBER)
        reply = response(request, KEY)
        verify_response(reply, request, KEY)
        changed = dict(reply, nonce='0' * 32)
        with self.assertRaises(ValueError):
            verify_response(changed, request, KEY)
        with self.assertRaises(ValueError):
            verify_challenge(request, KEY, member_id='m-ffffffffffffffff')

    def test_cli_ping_and_listen(self):
        with tempfile.TemporaryDirectory() as directory:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli.main(['--garden-dir', directory, 'garden', 'init', '--scope', '127.0.0.1/32'])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                added = cli.main(['--garden-dir', directory, 'garden', 'member', 'add',
                                  '--address', '127.0.0.1'])
            member = json.loads(out.getvalue())['result']['member']['id']
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli.main(['--garden-dir', directory, 'garden', 'member', 'activate', member])
            state = json.loads((__import__('pathlib').Path(directory) / 'garden.json').read_text())
            import agenticvm.garden_store as store_module
            key = store_module.GardenStore(__import__('pathlib').Path(directory)).ping_key()
            garden_id = __import__('agenticvm.garden_policy', fromlist=['GardenPolicy']).GardenPolicy.from_dict(state['policy']).digest()
            server = PingServer(key, garden_id, member)
            server.start()
            self.addCleanup(server.stop)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.main(['--garden-dir', directory, 'garden', 'ping', '127.0.0.1',
                                 '--member', member, '--port', str(server.address[1])])
            value = json.loads(out.getvalue())
            self.assertEqual(code, 0, value)
            self.assertTrue(value['result']['garden_member'])
