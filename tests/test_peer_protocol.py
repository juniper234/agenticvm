"""Protocol rejection tests and actual OpenSSL-backed TLS socket/BIO exchange."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import uuid

from agenticvm.peer_protocol import (ALPN, BIOStream, MAX_BODY, MAX_FRAME, PeerError,
                                    PeerSession, PeerTLSConfig, TLSStream, execute)

RUN = "d601c3d1-10c0-4ae1-90fe-bcfe3b41e93a"
MESSAGE = "339335ea-0536-4439-8d29-2f73ac4576f3"


class BufferStream:
    info = {"tls": "test-only-parser"}

    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.written = []

    def read(self, size, timeout):
        result = bytes(self.incoming[:size])
        del self.incoming[:size]
        return result

    def write(self, data, timeout):
        self.written.append(data)


def frame(**changes):
    value = {"v": 1, "run": RUN, "sender": "guest-a", "recipient": "guest-b",
             "id": MESSAGE, "seq": 1, "kind": "request", "reply_to": None,
             "body": {"op": "echo", "text": "data $(id) caf\u00e9 \u4e2d\u6587 \U0001f680"}}
    value.update(changes)
    return json.dumps(value, ensure_ascii=False).encode("utf-8") + b"\n"


class ProtocolTests(unittest.TestCase):
    def session(self, data=b"", checkpoint=None):
        return PeerSession(BufferStream(data), RUN, "guest-b", "guest-a", checkpoint)

    def test_capabilities_are_data_and_have_no_execution_verb(self):
        text = "$(id); rm -rf /\n\u4e2d\u6587 \U0001f680"
        self.assertEqual(execute({"op": "echo", "text": text})["text"], text)
        self.assertEqual(execute({"op": "sha256", "text": text})["sha256"],
                         hashlib.sha256(text.encode()).hexdigest())
        for body in ({"op": "exec", "text": "id"}, {"op": "ping", "nonce": 1},
                     {"op": "hello", "command": "id"}, {"op": "echo", "text": {}, "x": 0}):
            with self.assertRaises(PeerError):
                execute(body)

    def test_authentication_identity_and_run_are_bound_to_envelope(self):
        for changes in ({"run": str(uuid.uuid4())}, {"recipient": "host"},
                        {"sender": "outsider"}, {"v": True}, {"v": 2},
                        {"id": "not-a-uuid"}, {"kind": "request", "reply_to": MESSAGE}):
            with self.subTest(changes=changes), self.assertRaises(PeerError):
                self.session(frame(**changes)).receive()

    def test_replayed_sequence_is_rejected(self):
        session = self.session(frame() + frame())
        session.receive()
        with self.assertRaisesRegex(PeerError, "Replayed"):
            session.receive()

    def test_duplicate_id_is_idempotent_but_changed_content_is_rejected(self):
        events = []
        session = self.session(frame() + frame(seq=2) + frame(seq=3, body={"op": "ping", "nonce": "changed"}), events.append)
        first = session.respond(session.receive())
        self.assertEqual(session.respond(session.receive()), first)
        self.assertEqual(sum(event["event"] == "duplicate" for event in events), 1)
        with self.assertRaisesRegex(PeerError, "changed its contents"):
            session.respond(session.receive())

    def test_oversize_frames_bodies_and_invalid_utf8_are_rejected(self):
        for data in (b"x" * MAX_FRAME, b"\xff\n", frame(body={"op": "echo", "text": "x" * MAX_BODY})):
            with self.subTest(length=len(data)), self.assertRaises(PeerError):
                self.session(data).receive()
        with self.assertRaises(PeerError):
            self.session().send("request", {"op": "echo", "text": "x" * MAX_BODY})

    def test_evicted_duplicate_id_cannot_execute_again(self):
        session = self.session()
        first = json.loads(frame())
        session.respond(first)
        for _ in range(128):
            next_request = {**first, "id": str(uuid.uuid4())}
            session.respond(next_request)
        with self.assertRaisesRegex(PeerError, "retained reply window"):
            session.respond(first)

    def test_response_body_limit_is_validated_before_request_dispatch(self):
        session = self.session()
        empty = len(json.dumps({"op": "echo", "text": ""}, separators=(",", ":")))
        with self.assertRaisesRegex(PeerError, "result would exceed"):
            session.request("echo", text="x" * (MAX_BODY - empty))
        self.assertEqual(session.stream.written, [])

    def test_duplicate_json_keys_constants_and_recursive_json_rejected(self):
        data = frame().replace(b'"v": 1', b'"v": 1, "v": 1')
        for invalid in (data, frame().replace(b'"seq": 1', b'"seq": NaN'), b"[" * 1000 + b"]" * 1000 + b"\n"):
            with self.assertRaises(PeerError):
                self.session(invalid).receive()

    def test_disconnect_and_wrong_reply_correlation_rejected(self):
        with self.assertRaisesRegex(PeerError, "closed"):
            self.session().receive()
        session = self.session(frame(kind="response", reply_to=MESSAGE, body={"op": "hello", "ok": True}))
        with self.assertRaisesRegex(PeerError, "outstanding"):
            session.request("hello")

    def test_checkpoints_do_not_contain_plaintext(self):
        events = []
        session = self.session(frame(), events.append)
        session.respond(session.receive())
        serialized = json.dumps(events)
        self.assertNotIn("data $(id)", serialized)
        self.assertIn("body_sha256", serialized)

    def test_pin_required_and_keylogging_not_implicitly_enabled(self):
        with self.assertRaises(PeerError):
            PeerTLSConfig("a", "b", "c", "bad").context(False)

    def test_memorybio_closes_owned_raw_transport_on_bad_local_configuration(self):
        from unittest.mock import Mock
        raw = Mock()
        with self.assertRaises(PeerError):
            BIOStream(raw, PeerTLSConfig("a", "b", "c", "bad"), server_side=False)
        raw.close.assert_called_once_with()


class RawSocket:
    def __init__(self, sock, capture):
        self.socket = sock
        self.capture = capture

    def read(self, size, timeout):
        self.socket.settimeout(timeout)
        return self.socket.recv(size)

    def write(self, data, timeout):
        self.socket.settimeout(timeout)
        self.capture.extend(data)
        self.socket.sendall(data)

    def close(self):
        self.socket.close()


class RealTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which("openssl")
        fallback = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
        if not cls.openssl and fallback.is_file():
            cls.openssl = str(fallback)
        if not cls.openssl:
            raise unittest.SkipTest("OpenSSL command unavailable; live guest runner verifies TLS separately")
        cls.temp = tempfile.TemporaryDirectory(prefix="agenticvm-peer-tls-")
        cls.root = Path(cls.temp.name)
        def command(*args):
            subprocess.run([cls.openssl, *args], cwd=cls.root, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
        for ca in ("ca", "wrong-ca"):
            command("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-keyout", ca + ".key", "-out", ca + ".pem", "-days", "1",
                    "-subj", "/CN=" + ca, "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for identity in ("host", "guest-a"):
            command("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", identity + ".key", "-out", identity + ".csr", "-subj", "/CN=" + identity)
            (cls.root / (identity + ".ext")).write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=URI:urn:agenticvm:peer:" + identity + "\n",
                encoding="ascii")
            command("x509", "-req", "-in", identity + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                    "-CAcreateserial", "-days", "1", "-out", identity + ".pem", "-extfile", identity + ".ext")
        cls.pins = {identity: hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            (cls.root / (identity + ".pem")).read_text(encoding="ascii"))).hexdigest()
                    for identity in ("host", "guest-a")}

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def config(self, identity, peer, **changes):
        args = {"certfile": str(self.root / (identity + ".pem")),
                "keyfile": str(self.root / (identity + ".key")),
                "cafile": str(self.root / "ca.pem"), "peer_sha256": self.pins[peer], "peer_identity": peer}
        args.update(changes)
        return PeerTLSConfig(**args)

    def pair(self, bio=False, client_config=None, server_config=None, exercise=True):
        # AF_INET ensures the native SSLSocket path really is TCP.
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        server_errors, client_errors, evidence = [], [], []
        capture = bytearray()
        def server():
            stream = None
            try:
                raw, _ = listener.accept()
                cfg = server_config or self.config("guest-a", "host")
                stream = BIOStream(RawSocket(raw, capture), cfg, server_side=True, timeout=2) if bio else TLSStream(raw, cfg, server_side=True, timeout=2)
                session = PeerSession(stream, RUN, "guest-a", "host", evidence.append)
                session.serve(8, 4)
            except (OSError, ValueError, TimeoutError) as error:
                server_errors.append(error)
            finally:
                if stream:
                    stream.close()
                listener.close()
        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        stream = None
        try:
            raw = socket.create_connection(listener.getsockname(), timeout=2)
            cfg = client_config or self.config("host", "guest-a")
            stream = BIOStream(RawSocket(raw, capture), cfg, server_side=False, timeout=2) if bio else TLSStream(raw, cfg, server_side=False, timeout=2)
            session = PeerSession(stream, RUN, "host", "guest-a", evidence.append)
            if exercise:
                session.request("hello", timeout=2)
                marker = "PRIVATE-MARKER-76afb45f cafe\u00e9 \u4e2d\u6587 \U0001f680 $(id)"
                self.assertEqual(session.request("echo", text=marker, timeout=2)["text"], marker)
                session.request("sha256", text=marker, timeout=2)
                session.request("close", timeout=2)
        except (OSError, ValueError, TimeoutError) as error:
            client_errors.append(error)
        finally:
            if stream:
                stream.close()
        thread.join(5)
        self.assertFalse(thread.is_alive(), "TLS server did not honor its deadline")
        return server_errors, client_errors, evidence, bytes(capture)

    def test_native_tcp_mutual_tls13_and_exact_identity(self):
        errors, failures, evidence, _ = self.pair()
        self.assertEqual(errors, [])
        self.assertEqual(failures, [])
        authenticated = [item for item in evidence if item["event"] == "authenticated"]
        self.assertEqual(len(authenticated), 2)
        self.assertTrue(all(item["tls"] == "TLSv1.3" and item["alpn"] == ALPN for item in authenticated))

    def test_live_alpn_negotiates_and_cannot_mix_with_earlier_peer_protocol(self):
        live = 'agenticvm-live/1'
        errors,failures,evidence,_ = self.pair(bio=True,
            client_config=self.config('host','guest-a',alpn=live),
            server_config=self.config('guest-a','host',alpn=live))
        self.assertEqual(errors,[])
        self.assertEqual(failures,[])
        self.assertTrue(all(item['alpn']==live for item in evidence if item['event']=='authenticated'))
        errors,failures,evidence,_ = self.pair(bio=True,
            client_config=self.config('host','guest-a',alpn=live),exercise=False)
        self.assertTrue(errors or failures)
        self.assertFalse(any(item['event']=='sent' for item in evidence))

    def test_memorybio_mutual_tls13_ciphertext_hides_payload(self):
        errors, failures, evidence, capture = self.pair(bio=True)
        self.assertEqual(errors, [])
        self.assertEqual(failures, [])
        self.assertGreater(len(capture), 1000)
        self.assertNotIn(b"PRIVATE-MARKER-76afb45f", capture)
        self.assertNotIn(b"PRIVATE KEY", capture)
        self.assertNotIn(b'"op":"echo"', capture)

    def test_wrong_pin_rejected_before_any_application_message(self):
        errors, failures, evidence, _ = self.pair(client_config=self.config("host", "guest-a", peer_sha256="0" * 64))
        self.assertTrue(failures)
        self.assertIn("pin mismatch", str(failures[0]))
        self.assertEqual(failures[0].code, "pin_mismatch")
        self.assertFalse(any(item["event"] in ("received", "sent") for item in evidence))

    def test_wrong_ca_and_wrong_san_rejected(self):
        for change in ({"cafile": str(self.root / "wrong-ca.pem")}, {"peer_identity": "outsider"}):
            with self.subTest(change=change):
                _, failures, evidence, _ = self.pair(client_config=self.config("host", "guest-a", **change))
                self.assertTrue(failures)
                self.assertFalse(any(item["event"] in ("received", "sent") for item in evidence))

    def test_server_rejects_wrong_client_pin(self):
        errors, _, evidence, _ = self.pair(server_config=self.config("guest-a", "host", peer_sha256="0" * 64))
        self.assertTrue(errors)
        self.assertIn("pin mismatch", str(errors[0]))
        self.assertFalse(any(item["event"] == "received" for item in evidence))

    def test_bio_identity_rejection_notifies_peer_without_transport_eof(self):
        # A guest closes its virtio FD while QEMU's host stream stays open.
        # Keep the backing socket physically open to reproduce that contract.
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()
        finished = threading.Event()
        errors = []
        class HeldRaw(RawSocket):
            def close(self):
                pass
        def server():
            raw = None
            try:
                raw, _ = listener.accept()
                BIOStream(HeldRaw(raw, bytearray()), self.config("guest-a", "host", peer_sha256="0" * 64),
                          server_side=True, timeout=2)
            except (OSError, ValueError) as error:
                errors.append(error)
            finally:
                finished.wait(2)
                if raw:
                    raw.close()
                listener.close()
        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        client = None
        try:
            client = BIOStream(RawSocket(socket.create_connection(port, timeout=1), bytearray()),
                               self.config("host", "guest-a"), server_side=False, timeout=1)
            with self.assertRaises((PeerError, ssl.SSLError)):
                PeerSession(client, RUN, "host", "guest-a").request("hello", timeout=0.25)
        finally:
            if client:
                client.close()
            finished.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIn("pin mismatch", str(errors[0]))

    def test_environment_cannot_enable_tls_key_log(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(self.root / "must-not-exist") } ):
            context = self.config("host", "guest-a").context(False)
            self.assertIsNone(context.keylog_filename)
        self.assertFalse((self.root / "must-not-exist").exists())


if __name__ == "__main__":
    unittest.main()
