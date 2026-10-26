"""Three-target courier VM for the additive C6 pool lab.

Forwards target enrollment to the pool mother with per-target mother-issued
delivery grants. It cannot sign invites or admit members. After a receipt is
admitted it replays the same receipt once; the mother must stay idempotent.
"""
from __future__ import annotations

import http.client
import http.server
import json
import socket
import ssl
import threading
import time
from pathlib import Path

BASE = Path('/workspace/courier')
CONFIG = json.loads((BASE / 'courier-config.json').read_text())
COURIER_ID = CONFIG['sub_agent']
GRANTS = {}


def line(prefix, value):
    print(prefix + ' ' + json.dumps(value, sort_keys=True), flush=True)


def mother_connection():
    context = ssl.create_default_context(cadata=CONFIG['mother_certificate'])
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(BASE / 'courier.pem'), str(BASE / 'courier.key'))
    return http.client.HTTPSConnection(CONFIG['mother_host'], CONFIG['mother_port'],
                                       context=context, timeout=60)


def post_mother(path, body):
    connection = mother_connection()
    try:
        connection.request('POST', path, body=json.dumps(body),
                           headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read(65536)
        if response.status != 200:
            raise ValueError('Mother courier endpoint failed: ' + raw.decode(errors='replace')[:800])
        return json.loads(raw)
    finally:
        connection.close()


def read_body(handler):
    length = handler.headers.get('Content-Length')
    if not length or not length.isdigit() or int(length) > 65536:
        raise ValueError('Bounded target body required')
    return json.loads(handler.rfile.read(int(length)))


def handler_class():
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                body = read_body(self)
                if self.path == '/autoenroll/hello':
                    target_uuid = body['target_uuid']
                    result = post_mother('/courier/hello', {'hello': body})
                    GRANTS[target_uuid] = result.pop('grant')
                    line('AUTOENROLL_COURIER_POOL_DELIVERED', {
                        'target_uuid': target_uuid, 'sub_agent': COURIER_ID})
                    raw = json.dumps(result, sort_keys=True).encode()
                elif self.path in ('/autoenroll/start', '/autoenroll/receipt',
                                   '/autoenroll/certificate'):
                    target_uuid = body.get('target_uuid')
                    if self.path == '/autoenroll/receipt':
                        target_uuid = (body.get('invite') or {}).get('target_uuid')
                    grant = GRANTS.get(target_uuid)
                    if not grant:
                        raise ValueError('No delivery grant for target')
                    forwarded = dict(body)
                    forwarded['grant'] = grant
                    routes = {
                        '/autoenroll/start': '/courier/start',
                        '/autoenroll/receipt': '/courier/receipt',
                        '/autoenroll/certificate': '/courier/certificate',
                    }
                    result = post_mother(routes[self.path], forwarded)
                    line('AUTOENROLL_COURIER_POOL_FORWARDED', {
                        'path': self.path, 'target_uuid': target_uuid,
                        'sub_agent': COURIER_ID})
                    if self.path == '/autoenroll/receipt':
                        replay = post_mother('/courier/receipt', forwarded)
                        line('AUTOENROLL_COURIER_POOL_REPLAY', {
                            'target_uuid': target_uuid,
                            'admitted': replay.get('admitted') is True,
                            'sub_agent': COURIER_ID})
                    raw = json.dumps(result, sort_keys=True).encode()
                else:
                    raise ValueError('Unknown target endpoint')
                self.send_response(200)
            except Exception as error:
                line('AUTOENROLL_COURIER_POOL_ERROR', {
                    'path': self.path, 'error': type(error).__name__ + ': ' + str(error)})
                raw = json.dumps({'error': type(error).__name__ + ': ' + str(error)}).encode()
                self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    return Handler


def pipe(source, destination):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def status_proxy():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', CONFIG['status_port']))
    listener.listen(8)
    while True:
        client, _ = listener.accept()
        upstream = socket.create_connection((CONFIG['mother_host'], CONFIG['mother_status_port']))
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


def main():
    threading.Thread(target=status_proxy, daemon=True).start()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(BASE / 'courier.pem'), str(BASE / 'courier.key'))
    server = http.server.ThreadingHTTPServer(('0.0.0.0', CONFIG['listen_port']), handler_class())
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    line('AUTOENROLL_COURIER_POOL_READY', {
        'sub_agent': COURIER_ID, 'listen_port': CONFIG['listen_port'],
        'status_port': CONFIG['status_port'], 'mother': CONFIG['mother_host']})
    while True:
        time.sleep(5)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        line('AUTOENROLL_COURIER_POOL_ERROR', {'error': type(error).__name__ + ': ' + str(error)})
        raise
