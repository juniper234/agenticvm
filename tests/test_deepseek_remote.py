"""Transport and lifetime checks with a real loopback HTTP fixture; no tunnel."""
import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('deepseek_remote', Path(__file__).resolve().parents[1] / 'scripts/deepseek-remote.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class RemoteTests(unittest.TestCase):
    def test_untrusted_origin_not_selected(self):
        self.assertIsNone(remote.cloudflare_origin('https://trycloudflare.com.evil.example/'))
        self.assertIsNone(remote.cloudflare_origin('https://example.trycloudflare.com.evil.example/'))
        self.assertEqual(remote.cloudflare_origin('URL: https://example-name.trycloudflare.com'),
                         'https://example-name.trycloudflare.com')

    def test_failed_mutation_not_replayed(self):
        with patch.object(remote, 'local_request', return_value=(503, {}, b'failed')) as request:
            with self.assertRaises(RuntimeError):
                remote.action(8099, 'fixture', {'action': 'sharing.pairing'})
            self.assertEqual(request.call_count, 1)

    def test_executable_hash_fails_before_network(self):
        with tempfile.TemporaryDirectory() as temp:
            exe = Path(temp) / 'untrusted.exe'; exe.write_bytes(b'untrusted')
            with patch.object(remote, 'EXE', exe), patch.object(remote, 'local_request') as request:
                with self.assertRaises(RuntimeError):
                    remote.check(8099)
                request.assert_not_called()

    def test_full_lifetime_using_loopback_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            private = Path(temp)
            fixture_token = 'fixture-only-not-a-real-credential-000000'
            old_origin = 'https://previous.example'
            settings = {'enabled': True, 'token': fixture_token, 'publicOrigin': old_origin}
            requests = []
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args): pass
                def do_GET(self):
                    authorized = self.headers.get('x-companion-token') == fixture_token
                    self.send_response(200 if authorized else 401); self.end_headers()
                    if not authorized: return
                    if self.path == '/': self.wfile.write(b'<html>fixture</html>')
                    else: self.wfile.write(json.dumps({'app': 'desktop', 'capabilities': {'sessions': True}}).encode())
                def do_POST(self):
                    self.assertions()
                    body = json.loads(self.rfile.read(int(self.headers['content-length'])))
                    requests.append(body)
                    settings['publicOrigin'] = body['publicUrl']
                    (private / 'companion.json').write_text(json.dumps(settings))
                    self.send_response(200); self.end_headers()
                    self.wfile.write(json.dumps({'ok': True, 'value': {'url': body['publicUrl'] + '/?k=' + fixture_token}}).encode())
                def assertions(self):
                    assert self.headers['x-companion-token'] == fixture_token
                    assert self.headers['x-dsh-remote-control'] == '1'
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            settings['port'] = server.server_port
            (private / 'companion.json').write_text(json.dumps(settings))
            exe = private / 'cloudflared.exe'; exe.write_bytes(b'fixture executable')
            class Child:
                pid = 123
                stdout = io.StringIO('https://fixture.trycloudflare.com\nRegistered tunnel connection\n')
                stopped = False
                def poll(self): return 0 if self.stopped else None
                def terminate(self): self.stopped = True
                def wait(self, timeout): return 0
            child = Child()
            original_save = remote.save
            captured = {}
            def save(path, value):
                original_save(path, value)
                if value.get('state') == 'ready':
                    captured['link'] = (private / 'link.txt').read_text(encoding='utf-8')
                    (private / 'stop').touch()
            try:
                with contextlib.ExitStack() as stack:
                    for name, value in {'PRIVATE': private, 'STATE': private/'state.json', 'STOP': private/'stop',
                        'LINK': private/'link.txt', 'EXE': exe, 'PIN': hashlib.sha256(exe.read_bytes()).hexdigest()}.items():
                        stack.enter_context(patch.object(remote, name, value))
                    stack.enter_context(patch.object(remote.subprocess, 'Popen', return_value=child))
                    stack.enter_context(patch.object(remote, 'own_child', return_value=lambda: None))
                    stack.enter_context(patch.object(remote, 'save', side_effect=save))
                    output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                    # An unusable proxy must not affect direct loopback transport.
                    stack.enter_context(patch.dict('os.environ', {'HTTP_PROXY': 'http://127.0.0.1:1'}))
                    remote.start(server.server_port)
                self.assertTrue(child.stopped)
                self.assertNotIn(fixture_token, output.getvalue())
                self.assertNotIn(fixture_token, (private/'state.json').read_text())
                self.assertIn('https://fixture.trycloudflare.com/?k=' + fixture_token, captured['link'])
                self.assertFalse((private/'link.txt').exists())
                self.assertEqual(settings['publicOrigin'], old_origin)
                self.assertEqual(len(requests), 2)
            finally:
                server.shutdown(); server.server_close(); thread.join()

    def test_windows_job_terminates_only_owned_child(self):
        import subprocess, sys, time
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(30)'],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            close = remote.own_child(child)
            close()
            child.wait(5)
            self.assertIsNotNone(child.poll())
        finally:
            if child.poll() is None:
                child.terminate(); child.wait(5)


if __name__ == '__main__':
    unittest.main()
