"""Courier-mode mother gate for the additive native C6 lab.

It imports the accepted C3 mother module, keeps its single-target inventory and
seeder, and adds only:
  * a courier mTLS enrollment gate,
  * a mother-signed scoped delivery grant for courier-1,
  * grant validation on start/receipt/certificate.
The C3 mother module and target bootstrap remain unmodified.
"""
from __future__ import annotations

import http.server
import json
import ssl
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, '/workspace/base')
sys.path.insert(0, '/workspace/autoenroll')
import autoenroll_mother as base  # noqa: E402
from autoenroll_inventory import (  # noqa: E402
    digest_json, verify_delivery_grant,
)

COURIER_ID = 'courier-1'
GRANT_SECONDS = 900


class CourierState(base.State):
    def __init__(self):
        super().__init__()
        self.grant = None

    def hello(self, body, client_ip):
        if not isinstance(body, dict) or set(body) != {'hello'}:
            raise ValueError('Courier hello envelope is malformed')
        result = super().hello(body['hello'], base.TARGET_IP)
        self.grant = self.mother.create_delivery_grant(
            result['invite'], sub_agent=COURIER_ID,
            expires_unix=int(time.time()) + GRANT_SECONDS)
        base.line('AUTOENROLL_COURIER_MOTHER_INVITE', {
            'invite_sha256': digest_json(result['invite']),
            'grant_sha256': digest_json(self.grant),
            'sub_agent': COURIER_ID,
        })
        return {**result, 'grant': self.grant}

    def _check_grant(self, grant, invite=None):
        invite = invite or self.invite
        if invite is None or grant is None:
            raise ValueError('Courier grant has no issued invite')
        if digest_json(grant) != digest_json(self.grant):
            raise ValueError('Courier grant is not the issued grant')
        verify_delivery_grant(grant, invite, base.POLICY, now=int(time.time()))
        if grant['sub_agent'] != COURIER_ID:
            raise ValueError('Courier grant belongs to another sub-agent')

    def start(self, body, client_ip):
        if not isinstance(body, dict) or 'grant' not in body:
            raise ValueError('Courier start requires a delivery grant')
        body = dict(body)
        grant = body.pop('grant')
        self._check_grant(grant)
        return super().start(body, base.TARGET_IP)

    def admit(self, body, client_ip):
        if not isinstance(body, dict) or 'grant' not in body:
            raise ValueError('Courier receipt requires a delivery grant')
        body = dict(body)
        grant = body.pop('grant')
        self._check_grant(grant, body.get('invite'))
        return super().admit(body, base.TARGET_IP)

    def certificate(self, body, client_ip):
        if not isinstance(body, dict) or 'grant' not in body:
            raise ValueError('Courier certificate requires a delivery grant')
        body = dict(body)
        grant = body.pop('grant')
        self._check_grant(grant)
        return super().certificate(body, base.TARGET_IP)


STATE = None


def read_body(handler):
    length = handler.headers.get('Content-Length')
    if not length or not length.isdigit() or int(length) > 65536:
        raise ValueError('Bounded courier body required')
    return base.strict_json(handler.rfile.read(int(length)))


def handler_class(state):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                certificate = self.connection.getpeercert() or {}
                subject = {key: value for pair in certificate.get('subject', []) for key, value in pair}
                if subject.get('commonName') != COURIER_ID:
                    raise ValueError('Courier client certificate identity mismatch')
                body = read_body(self)
                routes = {
                    '/courier/hello': state.hello,
                    '/courier/start': state.start,
                    '/courier/receipt': state.admit,
                    '/courier/certificate': state.certificate,
                }
                if self.path not in routes:
                    raise ValueError('Unknown courier endpoint')
                result = routes[self.path](body, self.client_address[0])
                raw = json.dumps(result, sort_keys=True).encode()
                self.send_response(200)
            except Exception as error:
                base.line('AUTOENROLL_COURIER_MOTHER_ERROR', {
                    'path': self.path, 'error': type(error).__name__ + ': ' + str(error)})
                raw = json.dumps({'error': type(error).__name__ + ': ' + str(error)}).encode()
                self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    return Handler


def server(port, context, state):
    httpd = http.server.ThreadingHTTPServer(('0.0.0.0', port), handler_class(state))
    httpd.daemon_threads = True
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main():
    global STATE
    STATE = CourierState()
    enroll = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    enroll.minimum_version = enroll.maximum_version = ssl.TLSVersion.TLSv1_3
    enroll.load_cert_chain(str(base.BASE / 'mother.pem'), str(base.MOTHER_KEY))
    enroll.load_verify_locations(cadata=base.MOTHER_CERT)
    enroll.verify_mode = ssl.CERT_REQUIRED
    status = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    status.minimum_version = status.maximum_version = ssl.TLSVersion.TLSv1_3
    status.load_cert_chain(str(base.BASE / 'mother.pem'), str(base.MOTHER_KEY))
    status.load_verify_locations(cadata=base.MOTHER_CERT)
    status.verify_mode = ssl.CERT_REQUIRED
    server(base.ENROLL_PORT, enroll, STATE)
    base.server(base.STATUS_PORT, status, STATE, status=True)
    base.line('AUTOENROLL_COURIER_MOTHER_READY', {
        'enroll_port': base.ENROLL_PORT, 'status_port': base.STATUS_PORT,
        'torrent_port': base.TORRENT_PORT, 'sub_agent': COURIER_ID,
        'policy_sha256': digest_json(base.POLICY),
    })
    while True:
        time.sleep(5)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        base.line('AUTOENROLL_COURIER_MOTHER_ERROR', {
            'error': type(error).__name__ + ': ' + str(error)})
        raise
