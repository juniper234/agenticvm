"""An untrusted ciphertext carrier: file copy, loopback relay, or HTTPS courier.

The relay has no endpoint identities, private keys, inboxes, or decryption API.
It deliberately cannot enumerate mail; delivery tickets are content hashes.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAGIC = b'AgenticVM-Sealed-v1\n'
MAX_ENVELOPE = 768*1024
MAX_STORE = 64*1024**2
MAX_OBJECTS = 128


def digest(content):
    return hashlib.sha256(content).hexdigest()


def check(content, expected=None):
    if not len(MAGIC)+48+64 <= len(content) <= MAX_ENVELOPE or not content.startswith(MAGIC):
        raise ValueError('Not a bounded sealed envelope')
    actual = digest(content)
    if expected is not None and (not re.fullmatch('[0-9a-f]{64}', expected) or actual != expected):
        raise ValueError('Envelope does not match its delivery ticket')
    return actual


class Store:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        for path in (self.directory, *self.directory.parents):
            if path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
                raise ValueError('Redirected relay directory refused')
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.directory/'ciphertext.sqlite'
        if path.is_symlink():
            raise ValueError('Redirected relay database refused')
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS envelopes (sha TEXT PRIMARY KEY, content BLOB NOT NULL)')

    def put(self, content, expected=None):
        ticket = check(content, expected)
        with closing(sqlite3.connect(self.directory/'ciphertext.sqlite')) as db, db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            prior = db.execute('SELECT content FROM envelopes WHERE sha=?', (ticket,)).fetchone()
            if prior:
                if prior[0] != content:
                    raise ValueError('Content hash collision')
                return ticket
            count, size = db.execute('SELECT COUNT(*),COALESCE(SUM(LENGTH(content)),0) FROM envelopes').fetchone()
            if count >= MAX_OBJECTS or size+len(content) > MAX_STORE:
                raise ValueError('Relay quota reached')
            db.execute('INSERT INTO envelopes VALUES (?,?)', (ticket, content))
        return ticket

    def get(self, ticket):
        if not isinstance(ticket, str) or not re.fullmatch('[0-9a-f]{64}', ticket):
            raise ValueError('Invalid delivery ticket')
        with closing(sqlite3.connect(self.directory/'ciphertext.sqlite')) as db:
            row = db.execute('SELECT content FROM envelopes WHERE sha=?', (ticket,)).fetchone()
        if row is None:
            raise KeyError('Envelope is not on this carrier')
        check(row[0], ticket)
        return row[0]


def server(store, port=0):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *args):
            pass

        def _handle(self, upload):
            match = re.fullmatch('/v1/envelopes/([0-9a-f]{64})', self.path)
            if not match:
                self.send_error(404)
                return
            try:
                if upload:
                    lengths = self.headers.get_all('Content-Length', [])
                    if len(lengths) != 1 or self.headers.get('Transfer-Encoding') or not lengths[0].isdigit():
                        raise ValueError('One fixed content length required')
                    size = int(lengths[0])
                    if not 1 <= size <= MAX_ENVELOPE:
                        raise ValueError('Request exceeds its bound')
                    content = self.rfile.read(size)
                    if len(content) != size:
                        raise ValueError('Truncated request')
                    store.put(content, match[1])
                    output = json.dumps({'sha256': match[1], 'bytes': len(content)}).encode('ascii')
                else:
                    output = store.get(match[1])
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(len(output)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(output)
            except KeyError:
                self.send_error(404)
            except (ValueError, TimeoutError):
                self.send_error(400)

        def do_PUT(self):
            self._handle(True)

        def do_GET(self):
            self._handle(False)

    return HTTPServer(('127.0.0.1', port), Handler)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Relay redirects are refused')


def address(base, ticket):
    parsed = urllib.parse.urlsplit(base)
    if not re.fullmatch('[0-9a-f]{64}', ticket):
        raise ValueError('Invalid delivery ticket')
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname or parsed.path not in ('', '/'):
        raise ValueError('Use a relay origin without credentials, paths or queries')
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'):
        raise ValueError('Remote relay must use HTTPS; HTTP is allowed only at literal 127.0.0.1')
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    return opener, base.rstrip('/')+'/v1/envelopes/'+ticket


def push(base, content):
    ticket = check(content)
    opener, url = address(base, ticket)
    request = urllib.request.Request(url, data=content, method='PUT', headers={'Content-Type': 'application/octet-stream'})
    with opener.open(request, timeout=10) as response:
        result = json.loads(response.read(2049))
    if result != {'sha256': ticket, 'bytes': len(content)}:
        raise ValueError('Relay returned an invalid upload receipt')
    return result


def pull(base, ticket):
    opener, url = address(base, ticket)
    with opener.open(url, timeout=10) as response:
        content = response.read(MAX_ENVELOPE+1)
    check(content, ticket)
    return content


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('serve', help='Loopback only; remote use requires an HTTPS gateway')
    serve.add_argument('--store', type=Path, required=True)
    serve.add_argument('--port', type=int, default=8744)
    send = commands.add_parser('push')
    send.add_argument('--relay', required=True)
    send.add_argument('envelope', type=Path)
    fetch = commands.add_parser('pull')
    fetch.add_argument('--relay', required=True)
    fetch.add_argument('--ticket', required=True)
    fetch.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'serve':
        service = server(Store(args.store), args.port)
        print(json.dumps({'listening': 'http://127.0.0.1:'+str(service.server_port), 'decrypts': False}), flush=True)
        try:
            service.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
        finally:
            service.server_close()
        return 0
    try:
        if args.command == 'push':
            with args.envelope.open('rb') as source:
                content = source.read(MAX_ENVELOPE+1)
            result = push(args.relay, content)
        else:
            content = pull(args.relay, args.ticket)
            with args.output.open('xb') as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            result = {'sha256': args.ticket, 'bytes': len(content)}
        print(json.dumps({'ok': True, 'result': result}))
        return 0
    except Exception as error:
        print(json.dumps({'ok': False, 'error': type(error).__name__, 'message': str(error)[:240]}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
