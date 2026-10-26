"""Mother-side auto-enrollment authorizer on the isolated native lab LAN.

Runs inside the mother VM. It owns the policy/inventory ledger, signs invites,
serves the bounded private torrent, verifies the target receipt, admits the
member, and issues the target's client certificate. No scanning.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
from uuid import uuid4

BASE = Path('/workspace/autoenroll')
sys.path.insert(0, str(BASE))
from autoenroll_inventory import (  # noqa: E402
    AutoEnrollInventory, MotherAuthority, digest_json, strict_json,
    verify_target_hello,
)
from bounded_torrent import Seeder  # noqa: E402

CONFIG = json.loads((BASE / 'mother_config.json').read_text())
POLICY = CONFIG['policy']
MANIFEST = json.loads((BASE / 'manifest.json').read_text())
TARGET_UUID = CONFIG['target_uuid']
TARGET_MAC = CONFIG['target_mac']
TARGET_IP = '192.0.2.4'
MOTHER_IP = '192.0.2.1'
ENROLL_PORT = int(CONFIG.get('port', 8443))
STATUS_PORT = int(CONFIG.get('status_port', 9443))
TORRENT_PORT = int(CONFIG.get('torrent_port', 51413))
MOTHER_CERT = (BASE / 'mother.pem').read_text()
MOTHER_KEY = BASE / 'mother.key'
OPENSSL = '/usr/bin/openssl'


def line(prefix, value):
    print(prefix + ' ' + json.dumps(value, sort_keys=True), flush=True)


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.mother = MotherAuthority(POLICY, MOTHER_KEY, CONFIG['mother_public_key'])
        self.inventory = AutoEnrollInventory(BASE / 'ledger.sqlite3', policy=POLICY,
                                             owner_public_key=CONFIG['owner_public_key'],
                                             mother=self.mother)
        self.invite = None
        self.hello_nonce = None
        self.receipt = None
        self.member = None
        self.certificate_sha256 = None
        self.boots = []
        self.admitted = False
        self.reported = False
        self.seeder = Seeder(
            {name: (BASE / 'assets' / name, item) for name, item in MANIFEST['files'].items()},
            (MOTHER_IP, TORRENT_PORT), TARGET_IP)
        self.ready_at = time.time()

    def hello(self, body, client_ip):
        if client_ip != TARGET_IP:
            raise ValueError('Hello is not from the owned target address')
        hello = body
        verify_target_hello(hello)
        if hello['target_uuid'] != TARGET_UUID or hello['mac'] != TARGET_MAC:
            raise ValueError('Hello target binding mismatch')
        with self.lock:
            if self.invite is not None:
                if self.hello_nonce != hello['nonce']:
                    raise ValueError('A different hello already consumed this enrollment')
                return {'invite': self.invite, 'policy_sha256': digest_json(POLICY)}
            now = int(time.time())
            self.inventory.discover(TARGET_UUID, channel='target_hello',
                                    evidence={'source': 'target_hello', 'hello': hello}, now=now)
            request = self.inventory.request_lease(
                TARGET_UUID, sponsor='mother-direct', request_id=hello['nonce'], now=now)
            lease = self.inventory.grant_lease(
                request['request_id'], str(uuid4()), expires_unix=now + 900,
                mother=self.mother, now=now)
            invite = self.inventory.create_invite(
                lease['lease_id'], package_sha256=CONFIG['package_sha256'],
                model_sha256=CONFIG['model_sha256'], torrent_infohash=CONFIG['torrent_infohash'],
                nonce=str(uuid4()), expires_unix=now + 900, mother=self.mother, now=now)
            self.invite, self.hello_nonce = invite, hello['nonce']
            line('AUTOENROLL_MOTHER_INVITE', {'invite_sha256': digest_json(invite),
                                              'lease_id': lease['lease_id'],
                                              'policy_sha256': digest_json(POLICY)})
            return {'invite': invite, 'policy_sha256': digest_json(POLICY)}

    def start(self, body, client_ip):
        if client_ip != TARGET_IP:
            raise ValueError('Start is not from the owned target address')
        if set(body) != {'invite_sha256', 'request_id', 'target_uuid'}:
            raise ValueError('Unexpected start fields')
        with self.lock:
            if self.invite is None or digest_json(self.invite) != body['invite_sha256']:
                raise ValueError('Start does not match the issued invite')
            if body['request_id'] != self.invite['request_id'] or body['target_uuid'] != TARGET_UUID:
                raise ValueError('Start target binding mismatch')
            lease = self.inventory._lease(self.invite['lease_id'])
            if lease['state'] in ('active', 'invited'):
                self.inventory.mark_installing(
                    lease['lease_id'], evidence={'transport': 'mother-direct',
                                                 'invite_sha256': body['invite_sha256']},
                    mother=self.mother)
            elif lease['state'] != 'installing':
                raise ValueError('Start arrived in an invalid lease state')
            return {'manifest': MANIFEST, 'peer': MOTHER_IP, 'port': TORRENT_PORT}

    def admit(self, body, client_ip):
        if client_ip != TARGET_IP:
            raise ValueError('Receipt is not from the owned target address')
        if set(body) != {'invite', 'receipt'}:
            raise ValueError('Unexpected receipt fields')
        with self.lock:
            if self.invite is None or digest_json(self.invite) != digest_json(body['invite']):
                raise ValueError('Receipt invite does not match')
            joined = self.inventory.record_receipt(body['invite'], body['receipt'], mother=self.mother)
            member = self.inventory.admit(TARGET_UUID, mother=self.mother)
            self.receipt, self.member, self.admitted = body['receipt'], member, True
            line('AUTOENROLL_MOTHER_ADMITTED', {
                'status': joined['status'], 'target_uuid': TARGET_UUID,
                'identity_fingerprint': member['identity_fingerprint'],
                'receipt_sha256': digest_json(body['receipt'])})
            return {'admitted': True, 'target_uuid': TARGET_UUID,
                    'identity_fingerprint': member['identity_fingerprint']}

    def certificate(self, body, client_ip):
        if client_ip != TARGET_IP:
            raise ValueError('Certificate request is not from the owned target address')
        if set(body) != {'target_uuid', 'csr'} or body['target_uuid'] != TARGET_UUID:
            raise ValueError('Unexpected certificate request')
        csr = body['csr']
        if not isinstance(csr, str) or len(csr.encode()) > 16384 or not csr.startswith('-----BEGIN CERTIFICATE REQUEST-----'):
            raise ValueError('Malformed target CSR')
        with self.lock:
            if self.member is None:
                raise ValueError('Certificate requested before admission')
            csr_path = BASE / 'target.csr'
            cert_path = BASE / 'target-cert.pem'
            csr_path.write_text(csr)
            public = subprocess.run([OPENSSL, 'req', '-in', str(csr_path), '-pubkey', '-noout'],
                                    capture_output=True, text=True, timeout=15)
            if public.returncode:
                raise ValueError('Could not read the CSR public key')
            if public.stdout.strip() != self.member['target_public_key'].strip():
                raise ValueError('CSR public key does not match the receipt identity')
            ext = BASE / 'target-ext.cnf'
            ext.write_text('basicConstraints=critical,CA:FALSE\n'
                           'keyUsage=critical,digitalSignature\n'
                           'extendedKeyUsage=serverAuth,clientAuth\n'
                           f'subjectAltName=URI:urn:agenticvm:autoenroll:{TARGET_UUID},IP:{TARGET_IP}\n')
            result = subprocess.run([OPENSSL, 'x509', '-req', '-in', str(csr_path),
                                     '-CA', str(BASE / 'mother.pem'), '-CAkey', str(MOTHER_KEY),
                                     '-CAserial', str(BASE / 'mother.srl'), '-CAcreateserial',
                                     '-days', '1', '-sha256', '-extfile', str(ext),
                                     '-out', str(cert_path)], capture_output=True, text=True, timeout=15)
            if result.returncode:
                raise RuntimeError('Target certificate issuance failed: ' + result.stderr[-800:])
            certificate = cert_path.read_text()
            self.certificate_sha256 = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
            line('AUTOENROLL_MOTHER_CERTIFICATE', {'certificate_sha256': self.certificate_sha256,
                                                    'target_uuid': TARGET_UUID})
            return {'certificate': certificate, 'certificate_sha256': self.certificate_sha256}

    def status(self, body, peer_der):
        fields = {'schema', 'target_uuid', 'boot_id', 'identity_fingerprint', 'public_key',
                  'model', 'service', 'signed_unix', 'signature'}
        if set(body) != fields or body['schema'] != 'garden.autoenroll.agent-status.v1':
            raise ValueError('Unexpected target status')
        if body['target_uuid'] != TARGET_UUID:
            raise ValueError('Status target binding mismatch')
        with self.lock:
            if self.member is None or not self.admitted:
                raise ValueError('Status arrived before admission')
            cert_sha = hashlib.sha256(peer_der).hexdigest() if peer_der else None
            if cert_sha != self.certificate_sha256:
                raise ValueError('Status client certificate does not match the issued identity')
            if body['identity_fingerprint'] != self.member['identity_fingerprint']:
                raise ValueError('Status identity fingerprint mismatch')
            from autoenroll_inventory import sign_canonical, verify_canonical
            unsigned = {key: value for key, value in body.items() if key != 'signature'}
            verify_canonical(self.member['target_public_key'], unsigned, body['signature'],
                             label='target status')
            boot_id = body['boot_id']
            if boot_id not in [row['boot_id'] for row in self.boots]:
                self.boots.append({'boot_id': boot_id, 'at': time.time(), 'model': body['model'],
                                   'service': body['service'], 'signed_unix': body['signed_unix']})
            record = next(row for row in self.boots if row['boot_id'] == boot_id)
            record['model'] = body['model']
            record['service'] = body['service']
            line('AUTOENROLL_MOTHER_STATUS', {'boot_id': boot_id, 'boots': len(self.boots),
                                              'completions': body['model'].get('calls'),
                                              'service_active': body['service'].get('active')})
            self._maybe_report()
            return {'ok': True, 'boots': len(self.boots), 'target_uuid': TARGET_UUID}

    def _maybe_report(self):
        if self.reported or len(self.boots) < 2 or self.receipt is None:
            return
        if not all(row['service'].get('active') for row in self.boots):
            return
        if not all(row['model'].get('calls', 0) >= 2 for row in self.boots):
            return
        self.reported = True
        report = {
            'schema': 'garden.autoenroll.mother-report.v1',
            'target_uuid': TARGET_UUID,
            'policy_sha256': digest_json(POLICY),
            'invite': self.invite,
            'invite_sha256': digest_json(self.invite),
            'receipt': self.receipt,
            'receipt_sha256': digest_json(self.receipt),
            'member': self.member,
            'certificate_sha256': self.certificate_sha256,
            'events': self.inventory.events(),
            'torrent': self.seeder.stats,
            'boots': self.boots,
            'airgapped': True,
        }
        (BASE / 'mother-report.json').write_text(json.dumps(report, sort_keys=True) + '\n')
        line('AUTOENROLL_MOTHER_REPORT', report)


STATE = None


def read_body(handler):
    length = handler.headers.get('Content-Length')
    if not length or not length.isdigit() or int(length) > 65536:
        raise ValueError('Bounded request body required')
    raw = handler.rfile.read(int(length))
    return strict_json(raw)


class EnrollHandler:
    pass


def handler_class(state, status=False):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                body = read_body(self)
                client_ip = self.client_address[0]
                if status:
                    if self.path != '/autoenroll/status':
                        raise ValueError('Unknown status endpoint')
                    der = self.connection.getpeercert(binary_form=True)
                    result = state.status(body, der)
                elif self.path == '/autoenroll/hello':
                    result = state.hello(body, client_ip)
                elif self.path == '/autoenroll/start':
                    result = state.start(body, client_ip)
                elif self.path == '/autoenroll/receipt':
                    result = state.admit(body, client_ip)
                elif self.path == '/autoenroll/certificate':
                    result = state.certificate(body, client_ip)
                else:
                    raise ValueError('Unknown auto-enrollment endpoint')
                raw = json.dumps(result, sort_keys=True).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except Exception as error:
                line('AUTOENROLL_MOTHER_ERROR', {'path': self.path,
                                                 'client': self.client_address[0],
                                                 'error': type(error).__name__ + ': ' + str(error)})
                raw = json.dumps({'error': type(error).__name__ + ': ' + str(error)}).encode()
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
    return Handler


def server(port, context, state, status=False):
    httpd = http.server.ThreadingHTTPServer(('0.0.0.0', port), handler_class(state, status=status))
    httpd.daemon_threads = True
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def main():
    global STATE
    STATE = State()
    enroll_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    enroll_context.minimum_version = ssl.TLSVersion.TLSv1_3
    enroll_context.maximum_version = ssl.TLSVersion.TLSv1_3
    enroll_context.load_cert_chain(str(BASE / 'mother.pem'), str(MOTHER_KEY))
    status_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    status_context.minimum_version = ssl.TLSVersion.TLSv1_3
    status_context.maximum_version = ssl.TLSVersion.TLSv1_3
    status_context.load_cert_chain(str(BASE / 'mother.pem'), str(MOTHER_KEY))
    status_context.load_verify_locations(cadata=MOTHER_CERT)
    status_context.verify_mode = ssl.CERT_REQUIRED
    enroll = server(ENROLL_PORT, enroll_context, STATE)
    status = server(STATUS_PORT, status_context, STATE, status=True)
    line('AUTOENROLL_MOTHER_READY', {'enroll_port': ENROLL_PORT, 'status_port': STATUS_PORT,
                                     'torrent_port': TORRENT_PORT,
                                     'policy_sha256': digest_json(POLICY),
                                     'torrent_infohash': CONFIG['torrent_infohash']})
    while True:
        time.sleep(5)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        line('AUTOENROLL_MOTHER_ERROR', {'error': type(error).__name__ + ': ' + str(error)})
        raise
