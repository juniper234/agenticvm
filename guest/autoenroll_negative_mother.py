"""Minimal denial-only mother for the C5 negative-control fixture lab.

It holds the owner policy and inventory, revokes the registered stale fixture at
startup, and answers only target-initiated TARGET_HELLO with denial. It has no
invite, torrent, package, management, credential or scan path.
"""
from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import ssl
import sys
import threading
import time

BASE = Path('/workspace/negative')
sys.path.insert(0, str(BASE))
from autoenroll_inventory import (  # noqa: E402
    AutoEnrollInventory, MotherAuthority, strict_json, verify_target_hello,
)

CONFIG = json.loads((BASE / 'mother_config.json').read_text())
POLICY = CONFIG['policy']
TARGET_UUID = CONFIG['target_uuid']
TARGET_MAC = CONFIG['target_mac']
TARGET_IP = CONFIG.get('target_ip', '192.0.2.4')
PORT = int(CONFIG.get('port', 8443))
CERT = (BASE / 'mother.pem').read_text()
KEY = BASE / 'mother.key'


def line(prefix, value):
    print(prefix + ' ' + json.dumps(value, sort_keys=True), flush=True)


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.mother = MotherAuthority(POLICY, KEY, CONFIG['mother_public_key'])
        self.inventory = AutoEnrollInventory(BASE / 'ledger.sqlite3', policy=POLICY,
                                             owner_public_key=CONFIG['owner_public_key'],
                                             mother=self.mother)
        for target_uuid in CONFIG.get('revoked_targets', []):
            self.inventory.revoke(target_uuid, reason='negative-control stale policy/revoked lease',
                                  mother=self.mother)
        os.sync()

    def hello(self, body, client_ip):
        if client_ip != TARGET_IP:
            line('AUTOENROLL_NEGATIVE_DENIAL', {'reason': 'unexpected source', 'client': client_ip})
            raise ValueError('Unexpected source address')
        hello = body
        verify_target_hello(hello)
        if hello['target_uuid'] != TARGET_UUID or hello['mac'] != TARGET_MAC:
            line('AUTOENROLL_NEGATIVE_DENIAL', {
                'reason': 'unregistered target', 'uuid': hello.get('target_uuid'),
                'mac': hello.get('mac')})
            raise ValueError('Unregistered target is not eligible')
        with self.lock:
            try:
                self.inventory.discover(TARGET_UUID, channel='target_hello',
                                        evidence={'source': 'target_hello', 'hello': hello},
                                        now=int(time.time()))
            except ValueError as error:
                line('AUTOENROLL_NEGATIVE_DENIAL', {
                    'reason': 'revoked/expired target', 'uuid': TARGET_UUID,
                    'error': type(error).__name__ + ': ' + str(error)})
                raise
            # A registered target must never receive an invite in this lab; even
            # an unexpected discovery result is a denial for the negative gate.
            line('AUTOENROLL_NEGATIVE_DENIAL', {'reason': 'unexpected eligible target', 'uuid': TARGET_UUID})
            raise ValueError('Unexpected eligible target in negative lab')


STATE = None


def handler_class(state):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                length = self.headers.get('Content-Length')
                if not length or not length.isdigit() or int(length) > 65536:
                    raise ValueError('Bounded request body required')
                body = strict_json(self.rfile.read(int(length)))
                if self.path != '/autoenroll/hello':
                    raise ValueError('Unknown negative endpoint')
                result = state.hello(body, self.client_address[0])
                raw = json.dumps(result, sort_keys=True).encode()
                self.send_response(200)
            except Exception as error:
                line('AUTOENROLL_NEGATIVE_ERROR', {
                    'path': self.path, 'client': self.client_address[0],
                    'error': type(error).__name__ + ': ' + str(error)})
                raw = json.dumps({'error': type(error).__name__ + ': ' + str(error)}).encode()
                self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    return Handler


def main():
    global STATE
    STATE = State()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(BASE / 'mother.pem'), str(KEY))
    httpd = http.server.ThreadingHTTPServer(('0.0.0.0', PORT), handler_class(STATE))
    httpd.daemon_threads = True
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    line('AUTOENROLL_NEGATIVE_MOTHER_READY', {
        'port': PORT, 'target_uuid': TARGET_UUID,
        'revoked_targets': CONFIG.get('revoked_targets', []),
        'policy_sha256': __import__('hashlib').sha256(
            json.dumps(POLICY, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
    })
    while True:
        time.sleep(5)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        line('AUTOENROLL_NEGATIVE_MOTHER_ERROR', {
            'error': type(error).__name__ + ': ' + str(error)})
        raise
