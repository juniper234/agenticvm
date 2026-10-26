#!/usr/bin/env python3
"""Restricted guest peer. It exchanges typed messages and never executes them."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import stat
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from peer_protocol import BIOStream, PeerError, PeerSession, PeerTLSConfig, TLSStream


class FDTransport:
    """Linux virtio serial byte stream with a deadline on every read/write."""

    def __init__(self, path: str):
        if not path.startswith("/dev/virtio-ports/") or "/../" in path:
            raise PeerError("Expected a named virtio serial device")
        self.fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        self.seen_data = False

    def read(self, size: int, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Virtio read deadline expired")
            readable, _, _ = select.select([self.fd], [], [], remaining)
            if not readable:
                raise TimeoutError("Virtio read deadline expired")
            try:
                data = os.read(self.fd, size)
            except BlockingIOError:
                continue
            if data:
                self.seen_data = True
                return data
            if self.seen_data:
                return b""
            # Opening the guest daemon before its host connects is expected.
            time.sleep(min(0.025, max(0, deadline - time.monotonic())))

    def write(self, data: bytes, timeout: float):
        deadline = time.monotonic() + timeout
        view = memoryview(data)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Virtio write deadline expired")
            _, writable, _ = select.select([], [self.fd], [], remaining)
            if not writable:
                raise TimeoutError("Virtio write deadline expired")
            try:
                count = os.write(self.fd, view)
            except BlockingIOError:
                continue
            if count <= 0:
                raise PeerError("Virtio write made no progress")
            view = view[count:]

    def close(self):
        if self.fd is None:
            return
        try:
            # Closing this FD cannot close QEMU's host chardev socket. Drain
            # only the old session's ciphertext until that host disconnects,
            # so reciprocal TLS alerts cannot poison the next handshake.
            # Both time and discarded bytes are bounded, even for a bad peer.
            end, discarded = time.monotonic() + 0.75, 0
            while time.monotonic() < end and discarded < 65536:
                readable, _, _ = select.select([self.fd], [], [], min(0.05, end - time.monotonic()))
                if not readable:
                    continue
                try:
                    data = os.read(self.fd, min(4096, 65536 - discarded))
                except BlockingIOError:
                    continue
                if not data:
                    break
                discarded += len(data)
        except OSError:
            pass
        finally:
            os.close(self.fd)
            self.fd = None


class Evidence:
    """Append bounded checkpoint metadata, never private keys or message text."""

    def __init__(self, path: str, run_id: str, identity: str, peer: str):
        target = peer_path(path)
        if target.exists() and target.stat().st_size > 1024 * 1024:
            raise PeerError("Existing evidence exceeds its size limit")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o600)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise PeerError("Evidence must be a regular file")
        self.file = os.fdopen(descriptor, "a", encoding="utf-8")
        self.count = 0
        self.base = {"run_id": run_id, "identity": identity, "peer": peer}

    def __call__(self, event: dict):
        self.count += 1
        if self.count > 4096 or self.file.tell() > 1024 * 1024:
            raise PeerError("Checkpoint limit reached")
        value = {**self.base, "at_unix_ms": int(time.time() * 1000), **event}
        self.file.write(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n")
        self.file.flush()
        os.fsync(self.file.fileno())

    def close(self):
        self.file.close()


def peer_path(value: str, root: str | Path = "/workspace/peer") -> Path:
    """Require an existing real parent chain inside the exact peer directory."""
    target, base = Path(value), Path(root)
    if not target.is_absolute() or ".." in target.parts:
        raise PeerError("Peer output must be an absolute path without traversal")
    for parent in reversed((target.parent, *target.parent.parents)):
        if parent.is_symlink() or not parent.is_dir():
            raise PeerError("Peer output parent must be an existing real directory")
    if target.is_symlink():
        raise PeerError("Peer output cannot be a symbolic link")
    resolved_base = base.resolve(strict=True)
    resolved = target.resolve(strict=False)
    if not resolved.is_relative_to(resolved_base) or resolved == resolved_base:
        raise PeerError("Peer output belongs inside /workspace/peer")
    if target.exists() and not target.is_file():
        raise PeerError("Peer output must be a regular file")
    return resolved


def endpoint(value: str) -> tuple[str, int]:
    try:
        address, port = value.rsplit(":", 1)
        socket.inet_pton(socket.AF_INET, address)
        port = int(port)
        if not 1024 <= port <= 65535:
            raise ValueError
    except (ValueError, OSError) as exc:
        raise argparse.ArgumentTypeError("Expected an IPv4 address and port 1024..65535") from exc
    return address, port


def bounded_number(value: str) -> int:
    result = int(value)
    if not 1 <= result <= 512:
        raise argparse.ArgumentTypeError("Expected a value from 1 to 512")
    return result


def bounded_delay(value: str) -> float:
    result = float(value)
    if not 0 <= result <= 30:
        raise argparse.ArgumentTypeError("Expected seconds from 0 to 30")
    return result


def connect_tcp(address, deadline: float):
    # The other guest may still be booting; connection retries never change trust.
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Peer connect deadline expired")
        try:
            return socket.create_connection(address, timeout=min(2, remaining))
        except (ConnectionRefusedError, TimeoutError, OSError):
            time.sleep(min(0.2, remaining))


def exercise(session: PeerSession, rounds: int, deadline: float, interval: float = 0) -> int:
    operations = 0
    def request(op, **arguments):
        nonlocal operations
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Peer exercise deadline expired")
        result = session.request(op, timeout=min(15, remaining), **arguments)
        operations += 1
        return result
    request("hello")
    for index in range(rounds):
        nonce = str(uuid.uuid4())
        request("ping", nonce=nonce)
        text = "AgenticVM peer round " + str(index + 1) + ": caf\u00e9 \u4e2d\u6587 \U0001f680 $(id) " + nonce
        request("echo", text=text)
        result = request("sha256", text=text)
        if result["sha256"] != hashlib.sha256(text.encode("utf-8")).hexdigest():
            raise PeerError("Peer checksum result differs")
        session.record("round_completed", round=index + 1, requests=operations)
        if interval:
            if deadline - time.monotonic() <= interval:
                raise TimeoutError("Peer interval would exceed the deadline")
            time.sleep(interval)
    request("close")
    session.record("completed", requests=operations, rounds=rounds)
    return operations


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", choices=("tcp", "serial"), required=True)
    parser.add_argument("--role", choices=("server", "client"), required=True)
    parser.add_argument("--listen", type=endpoint, default=("192.0.2.2", 7443))
    parser.add_argument("--connect", type=endpoint, default=("192.0.2.2", 7443))
    parser.add_argument("--device", default="/dev/virtio-ports/org.agenticvm.peer")
    parser.add_argument("--identity", required=True)
    parser.add_argument("--peer-identity", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--cert", default="/workspace/peer/identity.pem")
    parser.add_argument("--key", default="/workspace/peer/key.pem")
    parser.add_argument("--ca", default="/workspace/peer/ca.pem")
    parser.add_argument("--peer-sha256", required=True)
    parser.add_argument("--rounds", type=bounded_number, default=3)
    parser.add_argument("--max-requests", type=bounded_number, default=64)
    parser.add_argument("--connections", "--max-connections", dest="connections", type=bounded_number, default=1,
                        help="Successful, close-acknowledged conversations before exit")
    parser.add_argument("--max-attempts", type=bounded_number, default=16)
    parser.add_argument("--deadline", type=bounded_number, default=90)
    parser.add_argument("--start-delay", type=bounded_delay, default=0)
    parser.add_argument("--interval", type=bounded_delay, default=0)
    parser.add_argument("--evidence", default="/workspace/peer/evidence.jsonl")
    parser.add_argument("--summary", default="/workspace/peer/summary.json")
    args = parser.parse_args(argv)
    summary = peer_path(args.summary)
    if Path(args.evidence).resolve(strict=False) == summary:
        raise PeerError("Summary and checkpoint outputs must be distinct")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise PeerError("The guest peer must run as an unprivileged user")
    key_stat = Path(args.key).stat()
    if os.name != "nt" and (not stat.S_ISREG(key_stat.st_mode) or key_stat.st_mode & 0o077
                            or key_stat.st_uid != os.geteuid()):
        raise PeerError("Private key must be a regular owner-only file owned by this user")
    if args.rounds * 3 + 2 > 512 or args.connections > args.max_attempts:
        raise PeerError("Conversation limits are inconsistent")
    config = PeerTLSConfig(args.cert, args.key, args.ca, args.peer_sha256, args.peer_identity)
    config.context(args.role == "server")  # Validate trust material before listen/connect.
    evidence = Evidence(args.evidence, args.run_id, args.identity, args.peer_identity)
    end = time.monotonic() + args.deadline
    listener = None
    completed = 0
    passed = False
    try:
        evidence({"event": "starting", "transport": args.transport, "role": args.role,
                  "uid": os.getuid() if hasattr(os, "getuid") else None,
                  "pid": os.getpid(), "deadline_seconds": args.deadline})
        if args.transport == "tcp" and args.role == "server":
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(args.listen)
            listener.listen(2)
            evidence({"event": "listening", "address": args.listen[0], "port": args.listen[1]})
        if args.start_delay:
            if end - time.monotonic() <= args.start_delay:
                raise PeerError("Start delay exceeds the deadline")
            evidence({"event": "delayed_start", "seconds": args.start_delay})
            time.sleep(args.start_delay)
        evidence({"event": "exchange_started"})
        for attempt in range(1, args.max_attempts + 1):
            stream = None
            try:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Peer daemon deadline expired")
                if args.transport == "serial":
                    stream = BIOStream(FDTransport(args.device), config,
                                       server_side=args.role == "server", timeout=min(15, remaining))
                else:
                    if listener:
                        listener.settimeout(remaining)
                        raw, _ = listener.accept()
                    else:
                        raw = connect_tcp(args.connect, end)
                    stream = TLSStream(raw, config, server_side=args.role == "server",
                                       timeout=min(10, end - time.monotonic()))
                session = PeerSession(stream, args.run_id, args.identity, args.peer_identity, evidence)
                if args.role == "server":
                    session.serve(args.max_requests, end - time.monotonic())
                else:
                    exercise(session, args.rounds, end, args.interval)
                completed += 1
                if completed >= args.connections:
                    evidence({"event": "daemon_completed", "connections": completed, "attempts": attempt})
                    passed = True
                    return 0
            except (OSError, ValueError, TimeoutError) as exc:
                # Error class only: OpenSSL/parser exceptions can contain peer input.
                evidence({"event": "rejected", "attempt": attempt, "error_class": type(exc).__name__,
                          "error_code": getattr(exc, "code", type(exc).__name__)})
                if args.role != "server" or end <= time.monotonic():
                    raise
                time.sleep(min(0.2, max(0, end - time.monotonic())))
            finally:
                if stream is not None:
                    stream.close()
        raise PeerError("Connection attempt limit reached")
    except (OSError, ValueError, TimeoutError) as exc:
        evidence({"event": "failed", "error_class": type(exc).__name__, "connections": completed,
                  "error_code": getattr(exc, "code", type(exc).__name__)})
        return 1
    finally:
        if listener is not None:
            listener.close()
        summary = peer_path(str(summary))
        value = {"passed": passed, "run_id": args.run_id, "identity": args.identity,
                 "peer": args.peer_identity, "transport": args.transport, "role": args.role,
                 "connections": completed, "rounds": args.rounds if args.role == "client" else None,
                 "peer_cert_sha256": args.peer_sha256,
                 "at_unix_ms": int(time.time() * 1000)}
        # Exclusive, no-follow creation prevents an existing .tmp symlink from
        # turning the atomic write into a write elsewhere in the guest.
        temporary = peer_path(str(summary.with_name(summary.name + "." + uuid.uuid4().hex + ".tmp")))
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as output:
                output.write(json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n")
                output.flush()
                os.fsync(output.fileno())
            peer_path(str(summary))
            temporary.replace(summary)
        finally:
            temporary.unlink(missing_ok=True)
        evidence.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TimeoutError) as error:
        print(json.dumps({"ok": False, "error_class": type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
