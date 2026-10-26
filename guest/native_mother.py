"""Native-OS enrollment and post-cold-boot model proof on the isolated LAN."""
from __future__ import annotations
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import sys
import threading
import time
from uuid import UUID, uuid5

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lan_agent import Node, Handler, SecureServer, BASE, MEMBERS, ADDRESSES, save


class NativeHandler(Handler):
    def handle_request(self, body):
        node = self.server.node
        if self.server.control and self.path.startswith('/native/'):
            try:
                if not node.install_token or self.headers.get('Authorization') != 'Bearer ' + node.install_token:
                    raise ValueError('Wrong native provisioning token')
                if self.client_address[0] != '192.0.2.4' or node.enrollment is None or time.monotonic() > node.enrollment:
                    raise ValueError('Native provisioning is not open for this owned target')
                if self.path == '/native/config' and body is None:
                    cfg = {key: node.config[key] for key in ('garden', 'request_id', 'grant', 'manifest_sha256', 'mother_certificate')}
                    cfg.update(identity='sprout-4', mother='https://192.0.2.1:8443')
                    if node.config['test_case'] == 'wrong-grant':
                        cfg['grant'] = 'intentionally-invalid-native-lab-grant'
                    return self.output(cfg)
                if self.path in ('/native/installer', '/native/runtime') and body is None:
                    path = BASE / ('lab/lan_install.py' if self.path.endswith('installer') else 'lab/portable-python.tar.gz')
                    raw = path.read_bytes()
                    if self.path.endswith('installer') and node.config['test_case'] == 'bad-bootstrap':
                        raw += b'\n# deliberately changed native installer\n'
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                if self.path == '/native/receipt' and body is not None:
                    if set(body) != {'request_id', 'identity', 'grant', 'receipt'}:
                        raise ValueError('Unknown native receipt fields')
                    node.admit(self.client_address[0], {key: body[key] for key in ('request_id', 'identity', 'grant')})
                    with node.lock:
                        if node.install_receipt and node.install_receipt != body['receipt']:
                            raise ValueError('Changed native installation receipt')
                        node.install_receipt = body['receipt']
                    return self.output({'ok': True})
                raise ValueError('Unknown native provisioning endpoint')
            except Exception as error:
                return self.output({'error': type(error).__name__ + ': ' + str(error)}, 403)
        return super().handle_request(body)


class MetadataHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        node = self.server.node
        files = json.loads((BASE / 'lab/native-seeds.json').read_text())
        if (self.client_address[0] != '192.0.2.4' or self.path not in files
                or node.enrollment is None or time.monotonic() > node.enrollment):
            self.send_error(404)
            return
        raw = base64.b64decode(files[self.path], validate=True)
        self.send_response(200)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        with node.lock:
            node.metadata_transfers.append({'path': self.path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})


class NativeNode(Node):
    def __init__(self, config):
        super().__init__(config)
        self.install_receipt = None
        self.install_token = config.get('install_token')
        self.metadata_transfers = []
        self.bundle_initialized = False

    def update_bundle(self):
        deadline = time.monotonic() + 60
        while True:
            try:
                super().update_bundle()
                self.bundle_initialized = True
                return
            except OSError:
                if self.bundle_initialized or time.monotonic() > deadline:
                    raise
                time.sleep(.25)

    def start_server(self, port, control=False):
        server = SecureServer((ADDRESSES[self.identity], port), NativeHandler)
        server.node, server.control = self, control
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def run(self):
        if self.identity == 'mother' and self.config['test_case'] not in ('happy', 'resume'):
            # Refusal cases exercise actual native bootstrap and TLS/package
            # checks. No model execution or seed-to-seed traffic is needed to
            # prove that the new target never activates an agent or model.
            self.start_server(8443, True)
            self.enrollment = time.monotonic() + 900
            metadata = http.server.ThreadingHTTPServer(('192.0.2.1', 8080), MetadataHandler)
            metadata.node = self
            threading.Thread(target=metadata.serve_forever, daemon=True).start()
            print('NATIVE_MOTHER_READY', flush=True)
            while not self.stop.wait(1):
                pass
            return
        super().run()

    def all_statuses(self):
        values = {name: self.rpc(name, '/status')[0] for name in MEMBERS if name != 'mother'}
        values['mother'] = self.snapshot()
        return values

    def mother(self):
        self.wait_ready(('offshoot-1', 'offshoot-2'))
        baseline = [self.exchange(peer) for peer in ('offshoot-1', 'offshoot-2')]
        self.enrollment = time.monotonic() + 900
        metadata = http.server.ThreadingHTTPServer(('192.0.2.1', 8080), MetadataHandler)
        metadata.node = self
        threading.Thread(target=metadata.serve_forever, daemon=True).start()
        print('NATIVE_MOTHER_READY', flush=True)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            with self.lock:
                joined, receipt = 'sprout-4' in self.known, self.install_receipt
            if joined and receipt:
                try:
                    target = self.rpc('sprout-4', '/status', timeout=5)[0]
                    if target['ready']:
                        break
                    if target['error']:
                        raise ValueError('Native target model failed: ' + target['error'])
                except OSError:
                    pass
            time.sleep(.5)
        else:
            raise TimeoutError('Native target did not enroll and become model-ready')
        if (not receipt['ok'] or any(receipt['initial_absence'].values()) or receipt['ssh_used']
                or receipt['agent_service_user'] != 1000 or receipt['systemd_enabled'] != 'enabled'):
            raise ValueError('Native target prerequisites or activation receipt mismatch')
        joined_exchange = self.exchange('sprout-4')
        self.wait_ready(('sprout-4',))
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if len(self.rpc('sprout-4', '/status')[0]['delivered']) == 2:
                break
            time.sleep(.5)
        else:
            raise TimeoutError('Native target did not contact both offshoots')
        before = self.all_statuses()
        target = before['sprout-4']
        if target['uid'] != 1000 or target['native_boot_id'] != receipt['boot_id']:
            raise ValueError('Native agent does not match the installed OS/process user')
        print('NATIVE_READY_FOR_COLD_REBOOT', flush=True)
        deadline, outages = time.monotonic() + 360, 0
        while time.monotonic() < deadline:
            try:
                after = self.rpc('sprout-4', '/status', timeout=3)[0]
                if after['native_boot_id'] != target['native_boot_id'] and after['ready']:
                    break
            except OSError:
                outages += 1
            time.sleep(.5)
        else:
            raise TimeoutError('Native installed service did not return after cold reboot')
        if after['public_identity'] != target['public_identity'] or after['uid'] != 1000:
            raise ValueError('Native reboot changed enrolled identity or agent permissions')
        if [row['id'] for row in after['calls']] != [row['id'] for row in target['calls']]:
            raise ValueError('Native reboot replayed model tasks')
        ident = str(uuid5(UUID(self.config['garden']), 'native-post-reboot-challenge'))
        hello = self.message(ident, 'sprout-4', 'hello')
        reply, tls = self.rpc('sprout-4', '/hello', hello)
        self.validate_message(reply, 'sprout-4', 'reply')
        if reply['reply_to'] != ident:
            raise ValueError('Native post-reboot model reply correlation failed')
        with self.lock, self.db:
            self.db.execute('INSERT INTO delivered VALUES (?,?,?,?)',
                (ident, 'sprout-4', json.dumps(hello), json.dumps(reply)))
        final = self.all_statuses()
        save(BASE / 'lan-report.json', {'passed': True, 'garden': self.config['garden'], 'route': self.config['route'],
             'initial_statuses': before, 'final_statuses': final, 'baseline': baseline,
             'joined_exchange': joined_exchange, 'installed': receipt, 'metadata_transfers': self.metadata_transfers,
             'post_reboot_challenge': {'hello': hello, 'reply': reply, 'tls': tls},
             'cold_reboot_same_identity': True, 'cold_reboot_no_model_task_replay': True,
             'network_outages_observed': outages})
        os.sync()


def main():
    node = None
    try:
        node = NativeNode(json.loads((BASE / 'lan-config.json').read_text()))
        node.run()
    except Exception as error:
        save(BASE / 'lan-report.json', {'passed': False, 'error': type(error).__name__ + ': ' + str(error)})
        os.sync()
        import traceback
        traceback.print_exc()
        while True:
            time.sleep(30)


if __name__ == '__main__':
    main()
