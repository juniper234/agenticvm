"""Three-target courier mother for the additive C6 pool lab.

Reuses the accepted C3 mother module for inventory, seeder, manifest and CA
material. Adds per-target invite/grant/receipt/certificate sessions and a
courier mTLS gate. The target bootstrap stays unchanged.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, '/workspace/base')
sys.path.insert(0, '/workspace/autoenroll')
import autoenroll_mother as base  # noqa: E402
import bounded_torrent  # noqa: E402
from autoenroll_inventory import (  # noqa: E402
    digest_json, sign_canonical, verify_canonical, verify_delivery_grant,
)

COURIER_ID = 'courier-1'
TARGET_IP = base.TARGET_IP
GRANT_SECONDS = 900


class PoolSeeder(bounded_torrent.Seeder):
    """Seeder budget for the three-target pool (four copies plus one piece)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.budget = (sum(info[b'length'] for _, info in self.assets.values()) * 4
                       + bounded_torrent.PIECE)


base.Seeder = PoolSeeder


class PoolState(base.State):
    def __init__(self):
        super().__init__()
        self.sessions = {}
        self.reported = False

    def _target(self, target_uuid):
        target = next((row for row in base.POLICY['allowed_targets']
                       if row['uuid'] == target_uuid), None)
        if target is None:
            raise ValueError('Target is not in the owner policy')
        return target

    def hello(self, body, client_ip):
        if not isinstance(body, dict) or set(body) != {'hello'}:
            raise ValueError('Courier hello envelope is malformed')
        hello = body['hello']
        verify_target_hello = __import__('autoenroll_inventory').verify_target_hello
        verify_target_hello(hello)
        target = self._target(hello['target_uuid'])
        if hello['mac'] != target['mac']:
            raise ValueError('MAC binding mismatch')
        with self.lock:
            session = self.sessions.get(target['uuid'])
            if session:
                if session['hello_nonce'] != hello['nonce']:
                    raise ValueError('A different hello already consumed this target')
                return {'invite': session['invite'], 'policy_sha256': digest_json(base.POLICY)}
            now = int(time.time())
            self.inventory.discover(target['uuid'], channel='target_hello',
                                    evidence={'source': 'target_hello', 'hello': hello}, now=now)
            request = self.inventory.request_lease(
                target['uuid'], sponsor=COURIER_ID, request_id=hello['nonce'], now=now)
            lease = self.inventory.grant_lease(
                request['request_id'], str(__import__('uuid').uuid4()),
                expires_unix=now + 900, mother=self.mother, now=now)
            invite = self.inventory.create_invite(
                lease['lease_id'], package_sha256=base.CONFIG['package_sha256'],
                model_sha256=base.CONFIG['model_sha256'],
                torrent_infohash=base.CONFIG['torrent_infohash'],
                nonce=str(__import__('uuid').uuid4()), expires_unix=now + 900,
                mother=self.mother, now=now)
            grant = self.mother.create_delivery_grant(
                invite, sub_agent=COURIER_ID, expires_unix=now + GRANT_SECONDS)
            self.sessions[target['uuid']] = {
                'target_uuid': target['uuid'], 'invite': invite, 'grant': grant,
                'hello_nonce': hello['nonce'], 'receipt': None, 'member': None,
                'certificate_sha256': None, 'boots': [],
            }
            base.line('AUTOENROLL_COURIER_POOL_INVITE', {
                'target_uuid': target['uuid'], 'invite_sha256': digest_json(invite),
                'grant_sha256': digest_json(grant)})
            return {'invite': invite, 'policy_sha256': digest_json(base.POLICY),
                    'grant': grant}

    def _session(self, target_uuid):
        session = self.sessions.get(target_uuid)
        if session is None:
            raise ValueError('No courier session for target')
        return session

    def _check_grant(self, session, grant):
        if grant is None or digest_json(grant) != digest_json(session['grant']):
            raise ValueError('Courier grant is not the issued grant')
        verify_delivery_grant(grant, session['invite'], base.POLICY, now=int(time.time()))
        if grant['sub_agent'] != COURIER_ID:
            raise ValueError('Courier grant belongs to another sub-agent')

    def start(self, body, client_ip):
        if not isinstance(body, dict) or 'grant' not in body:
            raise ValueError('Courier start requires a delivery grant')
        target_uuid = body.get('target_uuid')
        session = self._session(target_uuid)
        self._check_grant(session, body['grant'])
        with self.lock:
            if digest_json(session['invite']) != body.get('invite_sha256'):
                raise ValueError('Start does not match the issued invite')
            if body.get('request_id') != session['invite']['request_id']:
                raise ValueError('Start request binding mismatch')
            lease = self.inventory._lease(session['invite']['lease_id'])
            if lease['state'] in ('active', 'invited'):
                self.inventory.mark_installing(
                    lease['lease_id'], evidence={'transport': 'sub-agent-courier',
                                                 'invite_sha256': body['invite_sha256']},
                    mother=self.mother)
            elif lease['state'] != 'installing':
                raise ValueError('Start arrived in an invalid lease state')
            return {'manifest': base.MANIFEST, 'peer': base.MOTHER_IP,
                    'port': base.TORRENT_PORT}

    def admit(self, body, client_ip):
        if not isinstance(body, dict) or 'grant' not in body:
            raise ValueError('Courier receipt requires a delivery grant')
        invite = body.get('invite') or {}
        target_uuid = invite.get('target_uuid')
        session = self._session(target_uuid)
        self._check_grant(session, body['grant'])
        with self.lock:
            if digest_json(session['invite']) != digest_json(invite):
                raise ValueError('Receipt invite does not match')
            joined = self.inventory.record_receipt(invite, body.get('receipt'), mother=self.mother)
            member = self.inventory.admit(target_uuid, mother=self.mother)
            session['receipt'] = body.get('receipt')
            session['member'] = member
            base.line('AUTOENROLL_COURIER_POOL_ADMITTED', {
                'target_uuid': target_uuid, 'status': joined['status'],
                'receipt_sha256': digest_json(body.get('receipt'))})
            return {'admitted': True, 'target_uuid': target_uuid,
                    'identity_fingerprint': member['identity_fingerprint']}

    def certificate(self, body, client_ip):
        if not isinstance(body, dict) or 'grant' not in body:
            raise ValueError('Courier certificate requires a delivery grant')
        target_uuid = body.get('target_uuid')
        session = self._session(target_uuid)
        self._check_grant(session, body['grant'])
        csr = body.get('csr')
        if not isinstance(csr, str) or len(csr.encode()) > 16384 or not csr.startswith(
                '-----BEGIN CERTIFICATE REQUEST-----'):
            raise ValueError('Malformed target CSR')
        with self.lock:
            if session['member'] is None:
                raise ValueError('Certificate requested before admission')
            csr_path = base.BASE / ('target-%s.csr' % target_uuid)
            cert_path = base.BASE / ('target-%s.pem' % target_uuid)
            ext = base.BASE / ('target-%s-ext.cnf' % target_uuid)
            csr_path.write_text(csr)
            public = subprocess.run([base.OPENSSL, 'req', '-in', str(csr_path), '-pubkey', '-noout'],
                                    capture_output=True, text=True, timeout=15)
            if public.returncode:
                raise ValueError('Could not read the CSR public key')
            if public.stdout.strip() != session['member']['target_public_key'].strip():
                raise ValueError('CSR public key does not match the receipt identity')
            ext.write_text('basicConstraints=critical,CA:FALSE\n'
                           'keyUsage=critical,digitalSignature\n'
                           'extendedKeyUsage=serverAuth,clientAuth\n'
                           f'subjectAltName=URI:urn:agenticvm:autoenroll:{target_uuid},IP:{TARGET_IP}\n')
            result = subprocess.run([base.OPENSSL, 'x509', '-req', '-in', str(csr_path),
                                     '-CA', str(base.BASE / 'mother.pem'),
                                     '-CAkey', str(base.MOTHER_KEY),
                                     '-CAserial', str(base.BASE / 'mother.srl'), '-CAcreateserial',
                                     '-days', '1', '-sha256', '-extfile', str(ext),
                                     '-out', str(cert_path)], capture_output=True, text=True, timeout=15)
            if result.returncode:
                raise RuntimeError('Target certificate issuance failed: ' + result.stderr[-800:])
            certificate = cert_path.read_text()
            session['certificate_sha256'] = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
            base.line('AUTOENROLL_COURIER_POOL_CERTIFICATE', {
                'target_uuid': target_uuid, 'certificate_sha256': session['certificate_sha256']})
            return {'certificate': certificate,
                    'certificate_sha256': session['certificate_sha256']}

    def status(self, body, peer_der):
        fields = {'schema', 'target_uuid', 'boot_id', 'identity_fingerprint', 'public_key',
                  'model', 'service', 'signed_unix', 'signature'}
        if set(body) != fields or body['schema'] != 'garden.autoenroll.agent-status.v1':
            raise ValueError('Unexpected target status')
        target_uuid = body['target_uuid']
        session = self._session(target_uuid)
        with self.lock:
            if session['member'] is None:
                raise ValueError('Status arrived before admission')
            cert_sha = hashlib.sha256(peer_der).hexdigest() if peer_der else None
            if cert_sha != session['certificate_sha256']:
                raise ValueError('Status client certificate does not match issued identity')
            if body['identity_fingerprint'] != session['member']['identity_fingerprint']:
                raise ValueError('Status identity fingerprint mismatch')
            unsigned = {key: value for key, value in body.items() if key != 'signature'}
            verify_canonical(session['member']['target_public_key'], unsigned,
                             body['signature'], label='target status')
            boot_id = body['boot_id']
            if boot_id not in [row['boot_id'] for row in session['boots']]:
                session['boots'].append({'boot_id': boot_id, 'at': time.time(),
                                         'model': body['model'], 'service': body['service'],
                                         'signed_unix': body['signed_unix']})
            record = next(row for row in session['boots'] if row['boot_id'] == boot_id)
            record['model'], record['service'] = body['model'], body['service']
            base.line('AUTOENROLL_COURIER_POOL_STATUS', {
                'target_uuid': target_uuid, 'boot_id': boot_id,
                'boots': len(session['boots']),
                'completions': body['model'].get('calls'),
                'service_active': body['service'].get('active')})
            self._maybe_report()
            return {'ok': True, 'boots': len(session['boots']), 'target_uuid': target_uuid}

    def _maybe_report(self):
        if self.reported or len(self.sessions) != 3:
            return
        if not all(session['member'] and session['receipt'] and session['certificate_sha256']
                   and session['boots'] for session in self.sessions.values()):
            return
        if sum(len(session['boots']) for session in self.sessions.values()) < 4:
            return
        if not all(row['service'].get('active') for session in self.sessions.values()
                   for row in session['boots']):
            return
        if not all(row['model'].get('calls', 0) >= 2 for session in self.sessions.values()
                   for row in session['boots']):
            return
        self.reported = True
        sessions = []
        for target_uuid, session in self.sessions.items():
            sessions.append({key: session[key] for key in
                             ('target_uuid', 'invite', 'receipt', 'member',
                              'certificate_sha256', 'boots')})
        report = {
            'schema': 'garden.autoenroll.courier-pool-report.v1',
            'policy_sha256': digest_json(base.POLICY),
            'members': self.inventory.members(),
            'targets': self.inventory.targets(),
            'sessions': sessions,
            'events': self.inventory.events(),
            'torrent': self.seeder.stats,
            'boot_count': sum(len(session['boots']) for session in self.sessions.values()),
        }
        (base.BASE / 'pool-report.json').write_text(json.dumps(report, sort_keys=True) + '\n')
        base.line('AUTOENROLL_COURIER_POOL_REPORT', report)


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
                base.line('AUTOENROLL_COURIER_POOL_ERROR', {
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
    STATE = PoolState()
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
    base.line('AUTOENROLL_COURIER_POOL_MOTHER_READY', {
        'enroll_port': base.ENROLL_PORT, 'status_port': base.STATUS_PORT,
        'torrent_port': base.TORRENT_PORT, 'sub_agent': COURIER_ID,
        'policy_sha256': digest_json(base.POLICY)})
    while True:
        time.sleep(5)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        base.line('AUTOENROLL_COURIER_POOL_ERROR', {
            'error': type(error).__name__ + ': ' + str(error)})
        raise
