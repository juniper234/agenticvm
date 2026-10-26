"""Small authenticated agent messages over TLS 1.3; no command execution.

This file uses only the standard library and is also copied unchanged into the
Linux image. TCP uses SSLSocket. Virtio serial uses the same OpenSSL state
machine through MemoryBIO, never a separate encryption implementation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import socket
import ssl
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable

ALPN = "agenticvm-peer/1"
MAX_BODY = 16 * 1024
MAX_FRAME = 20 * 1024
MAX_MESSAGES = 512
IDENTITY = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
OPERATIONS = ("hello", "ping", "echo", "sha256", "close")


class PeerError(ValueError):
    """Authentication, framing, state, or capability validation failed closed."""

    def __init__(self, message: str, code: str = "protocol_error"):
        super().__init__(message)
        self.code = code


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Peer operation deadline expired")
    return remaining


def _json_bytes(value) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise PeerError("Invalid JSON value") from exc


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise PeerError("Duplicate JSON object key")
        value[key] = item
    return value


def _canonical_uuid(value: str) -> str:
    if not isinstance(value, str):
        raise PeerError("Expected canonical UUID")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise PeerError("Expected canonical UUID") from exc
    return value


def _identity(value: str) -> str:
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise PeerError("Invalid peer identity")
    return value


@dataclass(frozen=True)
class PeerTLSConfig:
    certfile: str
    keyfile: str
    cafile: str
    peer_sha256: str
    peer_identity: str | None = None
    alpn: str = ALPN

    def context(self, server_side: bool) -> ssl.SSLContext:
        if not isinstance(self.peer_sha256, str) or not HEX_SHA256.fullmatch(self.peer_sha256):
            raise PeerError("A lowercase SHA256 peer certificate pin is required")
        if self.peer_identity is not None:
            _identity(self.peer_identity)
        if not isinstance(self.alpn, str) or not re.fullmatch(r'[a-z0-9][a-z0-9/.-]{0,63}', self.alpn):
            raise PeerError('Invalid application protocol identifier')
        # Construct explicitly: create_default_context honors SSLKEYLOGFILE.
        # Peer traffic must never enable TLS secret logging from the environment.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False  # Exact leaf pin + optional URI SAN below.
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=self.cafile)
        context.load_cert_chain(self.certfile, self.keyfile)
        context.set_alpn_protocols([self.alpn])
        context.options |= ssl.OP_NO_COMPRESSION
        if server_side:
            context.num_tickets = 0  # No resumed identity or 0-RTT path.
        return context

    def authenticate(self, tls) -> dict:
        if tls.version() != "TLSv1.3" or tls.selected_alpn_protocol() != self.alpn:
            raise PeerError("TLS version or application protocol mismatch", "tls_mismatch")
        certificate = tls.getpeercert(binary_form=True)
        fingerprint = hashlib.sha256(certificate).hexdigest()
        if not hmac.compare_digest(fingerprint, self.peer_sha256):
            raise PeerError("Peer certificate pin mismatch", "pin_mismatch")
        if self.peer_identity is not None:
            expected = "urn:agenticvm:peer:" + self.peer_identity
            names = tls.getpeercert().get("subjectAltName", ())
            if ("URI", expected) not in names:
                raise PeerError("Peer certificate identity mismatch", "identity_mismatch")
        cipher = tls.cipher()
        return {"tls": tls.version(), "cipher": cipher[0],
                "peer_cert_sha256": fingerprint, "alpn": self.alpn,
                "peer_subject": tls.getpeercert().get("subject", ()),
                "peer_subject_alt_names": tls.getpeercert().get("subjectAltName", ())}


class TLSStream:
    """Deadline-aware native TCP TLS stream with mutual authentication."""

    def __init__(self, sock: socket.socket, config: PeerTLSConfig,
                 *, server_side: bool, timeout: float = 10):
        self.socket = None
        try:
            sock.settimeout(timeout)
            self.socket = config.context(server_side).wrap_socket(
                sock, server_side=server_side, do_handshake_on_connect=False)
            self.socket.do_handshake()
            self.info = config.authenticate(self.socket)
        except BaseException:
            (self.socket or sock).close()
            raise

    def read(self, size: int, timeout: float) -> bytes:
        self.socket.settimeout(timeout)
        return self.socket.recv(size)

    def write(self, data: bytes, timeout: float):
        self.socket.settimeout(timeout)
        self.socket.sendall(data)

    def close(self):
        self.socket.close()


class BIOStream:
    """TLS over an owned raw read(size, timeout)/write(data, timeout) channel."""

    def __init__(self, raw, config: PeerTLSConfig, *, server_side: bool,
                 timeout: float = 10):
        self.raw = raw
        self.closed = False
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        try:
            self.tls = config.context(server_side).wrap_bio(
                self.incoming, self.outgoing, server_side=server_side)
            self._operate(self.tls.do_handshake, time.monotonic() + timeout)
            self.info = config.authenticate(self.tls)
        except BaseException:
            self.close()
            raise

    def _flush(self, deadline: float):
        while self.outgoing.pending:
            self.raw.write(self.outgoing.read(min(16384, self.outgoing.pending)),
                           _remaining(deadline))

    def _operate(self, operation, deadline: float):
        while True:
            _remaining(deadline)
            try:
                result = operation()
                self._flush(deadline)
                return result
            except ssl.SSLWantReadError:
                self._flush(deadline)
                data = self.raw.read(16384, _remaining(deadline))
                if not data:
                    raise PeerError("Encrypted channel closed before completion")
                self.incoming.write(data)
            except ssl.SSLWantWriteError:
                self._flush(deadline)

    def read(self, size: int, timeout: float) -> bytes:
        return self._operate(lambda: self.tls.read(size), time.monotonic() + timeout)

    def write(self, data: bytes, timeout: float):
        deadline = time.monotonic() + timeout
        view = memoryview(data)
        while view:
            count = self._operate(lambda: self.tls.write(view[:16384]), deadline)
            if count <= 0:
                raise PeerError("TLS write made no progress")
            view = view[count:]

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if hasattr(self, "tls"):
                try:
                    # In particular, closing a Linux virtio FD does not close
                    # QEMU's host socket. Send OpenSSL's encrypted close_notify
                    # after a Python pin/SAN rejection. A failed handshake may
                    # instead already have a fatal TLS alert pending; flush it.
                    # Do not wait for the peer's reciprocal close notification.
                    self._operate(self.tls.unwrap, time.monotonic() + 0.5)
                except (ssl.SSLError, ValueError):
                    pass
                self._flush(time.monotonic() + 0.5)
        except Exception:
            # Cleanup must preserve the original authentication/protocol error.
            pass
        finally:
            self.raw.close()


def execute(body: dict) -> dict:
    """Deliberately narrow deterministic capability set; messages are data."""
    if not isinstance(body, dict) or not isinstance(body.get("op"), str):
        raise PeerError("Request body requires an operation")
    op = body["op"]
    if op in ("hello", "close"):
        if set(body) != {"op"}:
            raise PeerError("Unexpected operation fields")
        return {"op": op, "ok": True, **({"capabilities": list(OPERATIONS)} if op == "hello" else {})}
    field = "nonce" if op == "ping" else "text"
    if op not in ("ping", "echo", "sha256") or set(body) != {"op", field}:
        raise PeerError("Unsupported capability or fields")
    if not isinstance(body[field], str):
        raise PeerError("Capability argument must be text")
    raw = body[field].encode("utf-8")
    if len(_json_bytes(body)) > MAX_BODY:
        raise PeerError("Message body exceeds 16 KiB")
    if op == "sha256":
        return {"op": op, "ok": True, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    result = {"op": op, "ok": True, field: body[field]}
    if len(_json_bytes(result)) > MAX_BODY:
        raise PeerError("Capability result would exceed 16 KiB")
    return result


class PeerSession:
    """One authenticated, bounded, ordered request/reply conversation.

    Duplicate request IDs are idempotent within this connection (128-entry
    cache); changed contents or replayed sequence numbers fail closed. Callers
    must create a fresh run UUID for a new independent conversation. This is
    not a durable exactly-once work queue.
    """

    def __init__(self, stream, run_id: str, identity: str, peer_identity: str,
                 checkpoint: Callable[[dict], None] | None = None):
        self.stream = stream
        self.run_id = _canonical_uuid(run_id)
        self.identity = _identity(identity)
        self.peer_identity = _identity(peer_identity)
        if self.identity == self.peer_identity:
            raise PeerError("Peers must have distinct identities")
        self.checkpoint = checkpoint
        self.send_sequence = 0
        self.receive_sequence = 0
        self.buffer = bytearray()
        self.cache = OrderedDict()
        self.retired_requests = set()
        self.record("authenticated", **stream.info)

    def record(self, event: str, **fields):
        if self.checkpoint:
            self.checkpoint({"event": event, "run_id": self.run_id,
                             "identity": self.identity, "peer": self.peer_identity,
                             "at_unix_ms": int(time.time() * 1000), **fields})

    def send(self, kind: str, body: dict, *, reply_to: str | None = None,
             message_id: str | None = None, timeout: float = 10) -> dict:
        if kind not in ("request", "response") or not isinstance(body, dict):
            raise PeerError("Invalid message kind or body")
        if (kind == "response") != (reply_to is not None):
            raise PeerError("Invalid reply correlation")
        if reply_to is not None:
            _canonical_uuid(reply_to)
        if len(_json_bytes(body)) > MAX_BODY:
            raise PeerError("Message body exceeds 16 KiB")
        if self.send_sequence >= MAX_MESSAGES:
            raise PeerError("Conversation message limit reached")
        message_id = _canonical_uuid(message_id) if message_id is not None else str(uuid.uuid4())
        envelope = {"v": 1, "run": self.run_id, "sender": self.identity,
                    "recipient": self.peer_identity, "id": message_id,
                    "seq": self.send_sequence + 1, "kind": kind,
                    "reply_to": reply_to, "body": body}
        data = _json_bytes(envelope) + b"\n"
        if len(data) > MAX_FRAME:
            raise PeerError("Message frame exceeds its size limit")
        self.stream.write(data, timeout)
        self.send_sequence += 1
        self.record("sent", message_id=message_id, seq=self.send_sequence,
                    kind=kind, reply_to=reply_to,
                    body_sha256=hashlib.sha256(_json_bytes(body)).hexdigest())
        return envelope

    def receive(self, timeout: float = 10) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            boundary = self.buffer.find(b"\n")
            if boundary >= 0:
                if boundary + 1 > MAX_FRAME:
                    raise PeerError("Message frame exceeds its size limit")
                data = bytes(self.buffer[:boundary])
                del self.buffer[:boundary + 1]
                break
            if len(self.buffer) >= MAX_FRAME:
                raise PeerError("Message frame exceeds its size limit")
            data = self.stream.read(min(4096, MAX_FRAME - len(self.buffer)), _remaining(deadline))
            if not data:
                raise PeerError("Encrypted channel closed before completion")
            self.buffer.extend(data)
        try:
            envelope = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                                  parse_constant=lambda _: (_ for _ in ()).throw(PeerError("Invalid JSON constant")))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise PeerError("Invalid JSON envelope") from exc
        required = {"v", "run", "sender", "recipient", "id", "seq", "kind", "reply_to", "body"}
        if not isinstance(envelope, dict) or set(envelope) != required:
            raise PeerError("Invalid envelope fields")
        if (type(envelope["v"]) is not int or envelope["v"] != 1
                or envelope["run"] != self.run_id
                or envelope["sender"] != self.peer_identity
                or envelope["recipient"] != self.identity):
            raise PeerError("Envelope version, run, or identity mismatch")
        if (type(envelope["seq"]) is not int or envelope["seq"] != self.receive_sequence + 1
                or envelope["seq"] > MAX_MESSAGES):
            raise PeerError("Replayed or out-of-order message")
        _canonical_uuid(envelope["id"])
        kind, reply = envelope["kind"], envelope["reply_to"]
        if kind not in ("request", "response") or (kind == "response") != (reply is not None):
            raise PeerError("Invalid reply correlation")
        if reply is not None:
            _canonical_uuid(reply)
        if not isinstance(envelope["body"], dict) or len(_json_bytes(envelope["body"])) > MAX_BODY:
            raise PeerError("Invalid or oversized message body")
        self.receive_sequence = envelope["seq"]
        self.record("received", message_id=envelope["id"], seq=envelope["seq"],
                    kind=kind, reply_to=reply,
                    body_sha256=hashlib.sha256(_json_bytes(envelope["body"])).hexdigest())
        return envelope

    def request(self, op: str, *, timeout: float = 10, **arguments) -> dict:
        body = {"op": op, **arguments}
        execute(body)  # Validate locally before sending.
        deadline = time.monotonic() + timeout
        sent = self.send("request", body, timeout=_remaining(deadline))
        response = self.receive(_remaining(deadline))
        if response["kind"] != "response" or response["reply_to"] != sent["id"]:
            raise PeerError("Response does not acknowledge the outstanding request")
        expected = execute(body)
        if response["body"] != expected:
            raise PeerError("Peer returned an invalid capability result")
        self.record("acknowledged", message_id=sent["id"], response_id=response["id"], op=op)
        return response["body"]

    def respond(self, request: dict, timeout: float = 10) -> dict:
        if request["kind"] != "request":
            raise PeerError("Server expected a request")
        key = request["id"]
        if key in self.retired_requests:
            raise PeerError("Duplicate request ID is outside the retained reply window")
        digest = hashlib.sha256(_json_bytes(request["body"])).digest()
        if key in self.cache:
            previous, result = self.cache[key]
            if not hmac.compare_digest(digest, previous):
                raise PeerError("Duplicate request ID changed its contents")
            self.record("duplicate", message_id=key)
        else:
            result = execute(request["body"])
            self.cache[key] = (digest, result)
            if len(self.cache) > 128:
                retired, _ = self.cache.popitem(last=False)
                self.retired_requests.add(retired)
        self.send("response", result, reply_to=key, timeout=timeout)
        return result

    def serve(self, max_requests: int = 64, deadline: float = 90) -> int:
        if type(max_requests) is not int or not 1 <= max_requests <= MAX_MESSAGES:
            raise PeerError("Invalid request limit")
        end = time.monotonic() + deadline
        for count in range(1, max_requests + 1):
            request = self.receive(min(15, _remaining(end)))
            result = self.respond(request, min(10, _remaining(end)))
            if result["op"] == "close":
                self.record("completed", requests=count)
                return count
        raise PeerError("Request limit reached before a close acknowledgement")
