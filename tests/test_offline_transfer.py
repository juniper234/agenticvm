"""Adversarial and restart tests; these are host tests, not physical-host proof."""
import json
from pathlib import Path
import sqlite3
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from uuid import uuid4
from unittest.mock import patch

from agenticvm.offline_transfer import (Endpoint, MAGIC, DOMAIN, MAX_PAYLOAD,
    SealedBox, PublicKey, PrivateKey, SigningKey, encoded, b64, unb64, sha, parsed)
from agenticvm import blind_transfer as carrier


class OfflineTransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.a = Endpoint.create(self.root/'a', 'orchestrator')
        self.b = Endpoint.create(self.root/'b', 'worker')
        self.c = Endpoint.create(self.root/'c', 'outsider')
        self.a.trust(self.b.public, self.b.fingerprint)
        self.b.trust(self.a.public, self.a.fingerprint)

    def tearDown(self):
        for endpoint in (self.a, self.b, self.c):
            endpoint.close()
        self.temp.cleanup()

    def send(self, payload=b'private task \xe4\xbd\xa0\xe5\xa5\xbd', **kwargs):
        sent = self.a.send(self.b.fingerprint, payload, **kwargs)
        return sent, self.a.export(sent['id'])

    def forge(self, envelope, **updates):
        signed = SealedBox(self.b.box).decrypt(envelope[len(MAGIC):])
        body = parsed(signed[64+len(DOMAIN):])
        body.update(updates)
        return MAGIC+SealedBox(self.b.box.public_key).encrypt(bytes(self.a.sign.sign(DOMAIN+encoded(body))))

    def test_binary_unicode_roundtrip_receipt_and_durable_replay(self):
        data = bytes(range(256))+b'\0\xe4\xbd\xa0\xe5\xa5\xbd'
        sent, envelope = self.send(data)
        result = self.b.receive(envelope)
        self.assertEqual(self.b.payload(sent['id']), data)
        self.b.close()
        self.b = Endpoint(self.root/'b')
        duplicate = self.b.receive(envelope)
        self.assertTrue(duplicate['duplicate'])
        self.assertEqual(duplicate['receipt'], result['receipt'])
        receipt = self.b.export(result['receipt'])
        self.a.receive(receipt)
        self.assertEqual(self.a.status()['mail'][0]['acked'], 1)
        self.a.close()
        self.a = Endpoint(self.root/'a')
        self.assertTrue(self.a.receive(receipt)['duplicate'])
        self.assertEqual(len(self.b.status()['mail']), 2)

    def test_carrier_sees_ciphertext_without_plaintext_or_contact_labels(self):
        _, envelope = self.send(b'UNIQUE-SECRET-PAYLOAD')
        for marker in (b'UNIQUE-SECRET-PAYLOAD', b'orchestrator', b'worker', self.a.fingerprint.encode(), self.b.fingerprint.encode()):
            self.assertNotIn(marker, envelope)
        with self.assertRaises(Exception):
            SealedBox(PrivateKey.generate()).decrypt(envelope[len(MAGIC):])

    def test_wrong_recipient_and_tampered_ciphertext_are_rejected_without_inbox_changes(self):
        _, envelope = self.send()
        with self.assertRaises(Exception):
            self.c.receive(envelope)
        altered = envelope[:-1]+bytes([envelope[-1]^1])
        with self.assertRaises(Exception):
            self.b.receive(altered)
        self.assertEqual(self.b.status()['mail'], [])

    def test_public_key_alone_cannot_forge_an_enrolled_sender(self):
        _, envelope = self.send()
        signed = SealedBox(self.b.box).decrypt(envelope[len(MAGIC):])
        forged = bytes(SigningKey.generate().sign(signed[64:]))
        with self.assertRaises(Exception):
            self.b.receive(MAGIC+SealedBox(self.b.box.public_key).encrypt(forged))
        self.assertEqual(self.b.status()['mail'], [])

    def test_unknown_signed_sender_is_not_auto_enrolled(self):
        self.c.trust(self.b.public, self.b.fingerprint)
        sent = self.c.send(self.b.fingerprint, b'outsider')
        with self.assertRaises(ValueError):
            self.b.receive(self.c.export(sent['id']))

    def test_changed_message_with_reused_id_is_rejected(self):
        sent, envelope = self.send()
        self.b.receive(envelope)
        with self.assertRaises(ValueError):
            self.b.receive(self.forge(envelope, payload=b64(b'changed')))
        self.assertNotEqual(self.b.payload(sent['id']), b'changed')

    def test_expiry_clock_skew_and_invalid_lifetimes_are_rejected(self):
        _, envelope = self.send(now=1000, ttl=10)
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.b.receive(envelope, now=1010)
        with self.assertRaisesRegex(ValueError, 'clock'):
            self.b.receive(envelope, now=699)
        with self.assertRaises(ValueError):
            self.b.receive(self.forge(envelope, expires=True), now=1000)

    def test_old_duplicate_remains_idempotent_after_expiry(self):
        _, envelope = self.send(now=1000, ttl=10)
        self.b.receive(envelope, now=1001)
        self.assertTrue(self.b.receive(envelope, now=2000)['duplicate'])

    def test_bound_recipient_protocol_kind_and_domain_cannot_be_substituted(self):
        _, envelope = self.send()
        for update in ({'recipient':self.c.fingerprint}, {'schema':'wrong'}, {'kind':'exec'}, {'extra':'bad'}):
            with self.assertRaises(ValueError):
                self.b.receive(self.forge(envelope, **update))
        signed = SealedBox(self.b.box).decrypt(envelope[len(MAGIC):])
        bad_domain = b'X'*len(DOMAIN)+signed[64+len(DOMAIN):]
        with self.assertRaises(ValueError):
            self.b.receive(MAGIC+SealedBox(self.b.box.public_key).encrypt(bytes(self.a.sign.sign(bad_domain))))

    def test_out_of_order_delivery_and_atomic_receipt_recovery(self):
        first, e1 = self.send(b'first')
        second, e2 = self.send(b'second')
        self.b.receive(e2)
        self.b.receive(e1)
        self.assertEqual(self.b.payload(first['id']), b'first')
        self.assertEqual(self.b.payload(second['id']), b'second')
        self.assertEqual(len(self.b.status()['mail']), 4)

    def test_wrong_receipt_cannot_acknowledge_an_outgoing_message(self):
        sent, envelope = self.send()
        receipt_id = self.b.receive(envelope)['receipt']
        signed = SealedBox(self.a.box).decrypt(self.b.export(receipt_id)[len(MAGIC):])
        body = parsed(signed[64+len(DOMAIN):])
        body['payload'] = b64(encoded({'message_id':sent['id'], 'envelope_sha256':'0'*64}))
        forged = MAGIC+SealedBox(self.a.box.public_key).encrypt(bytes(self.b.sign.sign(DOMAIN+encoded(body))))
        with self.assertRaises(ValueError):
            self.a.receive(forged)
        self.assertEqual(self.a.status()['mail'][0]['acked'], 0)

    def test_no_delivery_without_a_carrier_and_original_export_survives_restart(self):
        sent, envelope = self.send()
        self.assertEqual(self.b.status()['mail'], [])
        self.a.close()
        self.a = Endpoint(self.root/'a')
        self.assertEqual(self.a.export(sent['id']), envelope)
        self.b.receive(envelope)
        self.assertEqual(len(self.b.status()['mail']), 2)

    def test_public_cards_are_pinned_and_cannot_overwrite_existing_identity(self):
        with self.assertRaises(ValueError):
            self.a.trust(self.c.public, self.b.fingerprint)
        with self.assertRaises(FileExistsError):
            Endpoint.create(self.root/'a', 'replacement')
        self.assertNotIn('private', json.dumps(self.a.public))
        self.assertNotIn(b64(self.a.box).encode(), encoded(self.a.public))

    def test_limits_invalid_ids_duplicate_json_and_nonfinite_values_fail(self):
        with self.assertRaises(ValueError):
            self.send(b'x'*(MAX_PAYLOAD+1))
        with self.assertRaises(ValueError):
            self.a.send(self.b.fingerprint, b'x', kind='receipt')
        with self.assertRaises(ValueError):
            self.a.export('../identity.private.json')
        with self.assertRaises(ValueError):
            parsed(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            parsed(b'{"a":NaN}')

    def test_carrier_is_immutable_content_addressed_and_has_no_decrypt_operation(self):
        _, envelope = self.send()
        store = carrier.Store(self.root/'relay')
        ticket = store.put(envelope)
        self.assertEqual(store.put(envelope), ticket)
        self.assertEqual(carrier.Store(self.root/'relay').get(ticket), envelope)
        with self.assertRaises(ValueError):
            store.put(envelope, '0'*64)
        with self.assertRaises(ValueError):
            store.get('../a/identity.private.json')
        with self.assertRaises(KeyError):
            store.get('0'*64)
        self.assertFalse(hasattr(store, 'decrypt'))

    def test_real_loopback_http_carrier_roundtrip_and_missing_ticket(self):
        _, envelope = self.send()
        service = carrier.server(carrier.Store(self.root/'relay'))
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        try:
            origin = 'http://127.0.0.1:'+str(service.server_port)
            ticket = carrier.push(origin, envelope)['sha256']
            self.assertEqual(carrier.pull(origin, ticket), envelope)
            with self.assertRaises(Exception):
                carrier.pull(origin, '0'*64)
        finally:
            service.shutdown()
            service.server_close()
            thread.join(3)

    def test_remote_plain_http_credentials_and_redirect_locations_are_refused(self):
        for origin in ('http://example.com', 'http://localhost', 'https://u:p@example.com', 'https://example.com/path', 'https://example.com?x=1'):
            with self.assertRaises(ValueError):
                carrier.address(origin, 'a'*64)
        carrier.address('https://example.com', 'a'*64)
        with self.assertRaises(ValueError):
            carrier.NoRedirect().redirect_request(None, None, None, None, None, 'http://127.0.0.1')

    def test_abrupt_process_crash_before_inbox_commit_leaves_no_half_receipt(self):
        _, envelope = self.send()
        path = self.root/'task.sealed'
        path.write_bytes(envelope)
        script = """
import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from agenticvm.offline_transfer import Endpoint
endpoint=Endpoint(sys.argv[2])
original=endpoint._queue
def crash(*args,**kwargs):
    original(*args,**kwargs)
    os._exit(23)
endpoint._queue=crash
endpoint.receive(Path(sys.argv[3]).read_bytes())
"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script,
            str(Path(__file__).resolve().parents[1]/'src'), str(self.root/'b'), str(path)],
            capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(self.b.status()['mail'], [])
        result = self.b.receive(envelope)
        self.assertEqual(len(self.b.status()['mail']), 2)
        self.assertTrue(self.b.receive(envelope)['duplicate'])
        self.assertIsNotNone(result['receipt'])

    def test_truncation_size_bounds_and_relay_quotas_preserve_existing_mail(self):
        _, envelope = self.send()
        with self.assertRaises(Exception):
            self.b.receive(envelope[:-16])
        self.assertEqual(self.b.status()['mail'], [])
        store = carrier.Store(self.root/'relay')
        ticket = store.put(envelope)
        _, another = self.send(b'another')
        with patch.object(carrier, 'MAX_OBJECTS', 1):
            with self.assertRaisesRegex(ValueError, 'quota'):
                store.put(another)
            self.assertEqual(store.put(envelope), ticket)
        self.assertEqual(store.get(ticket), envelope)
        with self.assertRaises(ValueError):
            carrier.check(carrier.MAGIC+b'x'*carrier.MAX_ENVELOPE)

    def test_persisted_submission_id_returns_original_ciphertext_after_restart(self):
        message_id = str(uuid4())
        first, envelope = self.send(b'task', message_id=message_id, now=1000, ttl=20)
        self.a.close()
        self.a = Endpoint(self.root/'a')
        second, retried = self.send(b'task', message_id=message_id, now=5000, ttl=90)
        self.assertEqual(first, second)
        self.assertEqual(envelope, retried)
        self.assertEqual(len(self.a.status()['mail']), 1)
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.b.receive(retried, now=5000)

    def test_persisted_submission_id_cannot_be_rebound_to_other_contents_or_peer(self):
        message_id = str(uuid4())
        self.send(b'task', message_id=message_id)
        for payload, peer in ((b'changed', self.b.fingerprint), (b'task', self.c.fingerprint)):
            with self.assertRaisesRegex(ValueError, 'changed'):
                self.a.send(peer, payload, message_id=message_id)


class RealHTTPSCarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        openssl = shutil.which('openssl')
        fallback = Path(r'C:\Program Files\Git\usr\bin\openssl.exe')
        if not openssl and fallback.is_file():
            openssl = str(fallback)
        if not openssl:
            raise unittest.SkipTest('OpenSSL is needed to create the local HTTPS test certificate')
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.cert, cls.key = cls.root/'relay.pem', cls.root/'relay.key'
        result = subprocess.run([openssl,'req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
            '-noenc','-sha256','-days','1','-subj','/CN=local-transfer-test',
            '-addext','subjectAltName=IP:127.0.0.1', '-keyout',str(cls.key),'-out',str(cls.cert)],
            capture_output=True, timeout=15)
        if result.returncode:
            raise RuntimeError('Local HTTPS fixture certificate generation failed')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def exercise(self, tls12=False):
        service = carrier.server(carrier.Store(self.root/('tls12' if tls12 else 'tls13')))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        if tls12:
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        else:
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        service.socket = context.wrap_socket(service.socket, server_side=True)
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        return service, thread

    def test_actual_https_certificate_chain_hostname_and_ciphertext_roundtrip(self):
        service, thread = self.exercise()
        content = MAGIC+SealedBox(PrivateKey.generate().public_key).encrypt(b'opaque relay payload'*10)
        origin = 'https://127.0.0.1:'+str(service.server_port)
        try:
            with self.assertRaises(Exception) as rejection:
                carrier.push(origin, content)
            self.assertIsInstance(rejection.exception.reason, ssl.SSLCertVerificationError)
            trusted = ssl.create_default_context(cafile=str(self.cert))
            with patch.object(carrier.ssl,'create_default_context',return_value=trusted):
                ticket = carrier.push(origin, content)['sha256']
                self.assertEqual(carrier.pull(origin,ticket), content)
                self.assertEqual(trusted.minimum_version, ssl.TLSVersion.TLSv1_3)
                with self.assertRaises(Exception) as wrong_name:
                    carrier.pull('https://localhost:'+str(service.server_port),ticket)
                self.assertIsInstance(wrong_name.exception.reason, ssl.SSLCertVerificationError)
        finally:
            service.shutdown()
            service.server_close()
            thread.join(3)

    def test_actual_https_tls12_only_service_is_rejected(self):
        service, thread = self.exercise(tls12=True)
        trusted = ssl.create_default_context(cafile=str(self.cert))
        try:
            with patch.object(carrier.ssl,'create_default_context',return_value=trusted):
                with self.assertRaises(Exception) as rejection:
                    carrier.pull('https://127.0.0.1:'+str(service.server_port),'0'*64)
                self.assertIsInstance(rejection.exception.reason, ssl.SSLError)
        finally:
            service.shutdown()
            service.server_close()
            thread.join(3)


if __name__ == '__main__':
    unittest.main()
