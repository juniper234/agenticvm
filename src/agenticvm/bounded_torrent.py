"""BEP 3 single-file transfer to one approved peer; no discovery or execution.

This deliberately small peer implements handshakes, bitfields, interest,
unchoking and pipelined 16 KiB blocks. The pinned HTTPS manifest is the trust
root; SHA-1 pieces alone never authorize an installation. All listeners and
destinations are supplied by the isolated lab, never by received metadata.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import threading
import time

PIECE = 256 * 1024
BLOCK = 16 * 1024
MAX_FILE = 250 * 1024**2
NAMES = {'model.gguf', 'llama.tar.gz', 'libgomp.so.1', 'agent.tar.gz'}
HEADER = b'\x13BitTorrent protocol' + bytes(8)


def bencode(value):
    if type(value) is int:
        return b'i' + str(value).encode() + b'e'
    if isinstance(value, bytes):
        return str(len(value)).encode() + b':' + value
    if isinstance(value, dict) and all(isinstance(k, bytes) for k in value):
        return b'd' + b''.join(bencode(k) + bencode(value[k]) for k in sorted(value)) + b'e'
    raise ValueError('Unsupported bounded torrent metadata')


def bdecode(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 128 * 1024:
        raise ValueError('Torrent metadata size limit')
    offset = 0

    def read(depth=0):
        nonlocal offset
        if depth > 4 or offset >= len(raw):
            raise ValueError('Invalid torrent metadata structure')
        start = offset
        tag = raw[offset:offset + 1]
        if tag == b'd':
            offset += 1
            result, previous = {}, None
            while raw[offset:offset + 1] != b'e':
                key = read(depth + 1)
                if not isinstance(key, bytes) or (previous is not None and key <= previous):
                    raise ValueError('Unsorted or duplicate torrent key')
                previous = key
                result[key] = read(depth + 1)
                if len(result) > 16:
                    raise ValueError('Torrent field limit')
            offset += 1
            return result
        delimiter = b'e' if tag == b'i' else b':'
        end = raw.find(delimiter, offset + (tag == b'i'))
        if end < 0 or end - start > 16:
            raise ValueError('Invalid torrent integer or length')
        token = raw[offset + (tag == b'i'):end]
        if not token.isdigit() or (len(token) > 1 and token.startswith(b'0')):
            raise ValueError('Noncanonical torrent integer')
        number = int(token)
        offset = end + 1
        if tag == b'i':
            return number
        if number > len(raw) - offset:
            raise ValueError('Truncated torrent string')
        result = raw[offset:offset + number]
        offset += number
        return result

    result = read()
    if offset != len(raw) or bencode(result) != raw:
        raise ValueError('Trailing or noncanonical torrent metadata')
    return result


def metadata(path, *, name=None):
    path = Path(path)
    name = path.name if name is None else name
    if name not in NAMES or not 0 < path.stat().st_size <= MAX_FILE:
        raise ValueError('Unapproved torrent asset')
    with path.open('rb') as source:
        pieces = b''.join(hashlib.sha1(chunk).digest() for chunk in iter(lambda: source.read(PIECE), b''))
    info = {b'length': path.stat().st_size, b'name': name.encode(),
            b'piece length': PIECE, b'pieces': pieces, b'private': 1}
    return base64.b64encode(bencode({b'info': info})).decode()


def parse(value, name, size):
    if name not in NAMES or type(size) is not int or not 0 < size <= MAX_FILE:
        raise ValueError('Unapproved torrent asset bound')
    if not isinstance(value, str) or len(value) > 180 * 1024:
        raise ValueError('Torrent metadata encoding limit')
    meta = bdecode(base64.b64decode(value, validate=True))
    if not isinstance(meta, dict) or set(meta) != {b'info'}:
        raise ValueError('Torrent discovery endpoints are forbidden')
    info = meta[b'info']
    if (not isinstance(info, dict) or set(info) != {b'length', b'name', b'piece length', b'pieces', b'private'}
            or info[b'name'] != name.encode() or info[b'length'] != size
            or info[b'piece length'] != PIECE or info[b'private'] != 1
            or not isinstance(info[b'pieces'], bytes)
            or len(info[b'pieces']) != ((size + PIECE - 1) // PIECE) * 20):
        raise ValueError('Torrent inventory mismatch')
    return info, hashlib.sha1(bencode(info)).digest()


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError('Torrent peer disconnected')
        data.extend(chunk)
    return bytes(data)


def send(sock, kind, payload=b''):
    sock.sendall(struct.pack('!I', len(payload) + 1) + bytes((kind,)) + payload)


def receive(sock):
    size = struct.unpack('!I', exact(sock, 4))[0]
    if size > BLOCK + 9:
        raise ValueError('Torrent wire message limit')
    if size == 0:
        return None, b''
    data = exact(sock, size)
    return data[0], data[1:]


def handshake(sock, info_hash):
    sock.sendall(HEADER + info_hash + b'-AV0002-' + os.urandom(12))
    incoming = exact(sock, 68)
    if incoming[:20] != HEADER[:20] or incoming[28:48] != info_hash:
        raise ValueError('Torrent handshake mismatch')


class Seeder:
    """One fixed seeder, one admitted address, finite connections and bytes."""

    def __init__(self, assets, address, allowed_peer, *, interrupt=False, interrupt_after_bytes=None):
        self.assets = {}
        self.allowed_peer, self.interrupt = allowed_peer, interrupt
        if interrupt_after_bytes is not None and (type(interrupt_after_bytes) is not int or interrupt_after_bytes <= 0):
            raise ValueError('Interrupt byte threshold must be a positive integer')
        self.interrupt_after_bytes = interrupt_after_bytes
        self.stop = threading.Event()
        self.stats = {'connections': 0, 'payload_bytes_sent': 0, 'injected_disconnects': 0}
        self.errors = []
        for name, (path, entry) in assets.items():
            path = Path(path)
            info, key = parse(entry['torrent'], name, entry['bytes'])
            with path.open('rb') as source:
                actual = hashlib.file_digest(source, 'sha256').hexdigest()
            if path.stat().st_size != entry['bytes'] or actual != entry['sha256']:
                raise ValueError('Seed asset integrity verification failed')
            self.assets[key] = (path, info)
        self.budget = sum(info[b'length'] for _, info in self.assets.values()) * 2 + PIECE
        self.listener = socket.socket()
        self.listener.bind(address)
        self.listener.listen(8)
        self.listener.settimeout(.5)
        self.address = self.listener.getsockname()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if address[0] != self.allowed_peer:
                conn.close()
                self.errors.append('ValueError: Unapproved torrent peer')
                continue
            self.stats['connections'] += 1
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        with conn:
            try:
                conn.settimeout(15)
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                raw = exact(conn, 68)
                if raw[:20] != HEADER[:20] or raw[28:48] not in self.assets:
                    raise ValueError('Torrent handshake mismatch')
                key = raw[28:48]
                path, info = self.assets[key]
                conn.sendall(HEADER + key + b'-AV0002-' + os.urandom(12))
                count = len(info[b'pieces']) // 20
                bits = bytearray((count + 7) // 8)
                for index in range(count):
                    bits[index // 8] |= 0x80 >> (index % 8)
                send(conn, 5, bytes(bits))
                interested, transferred = False, 0
                with path.open('rb') as source:
                    while not self.stop.is_set():
                        kind, payload = receive(conn)
                        if kind is None or (kind == 4 and len(payload) == 4):
                            continue
                        if kind == 2 and not payload:
                            interested = True
                            send(conn, 1)
                            continue
                        if kind == 3 and not payload:
                            break
                        if kind != 6 or len(payload) != 12 or not interested:
                            raise ValueError('Unsupported torrent request')
                        index, start, length = struct.unpack('!III', payload)
                        piece_size = min(PIECE, info[b'length'] - index * PIECE)
                        if index >= count or not 0 < length <= BLOCK or start + length > piece_size:
                            raise ValueError('Torrent block outside approved file')
                        if self.stats['payload_bytes_sent'] + length > self.budget:
                            raise ValueError('Torrent byte quota exhausted')
                        source.seek(index * PIECE + start)
                        send(conn, 7, struct.pack('!II', index, start) + source.read(length))
                        self.stats['payload_bytes_sent'] += length
                        transferred += length
                        if (self.interrupt_after_bytes is not None
                                and not self.stats['injected_disconnects']
                                and self.stats['payload_bytes_sent'] >= self.interrupt_after_bytes):
                            self.stats['injected_disconnects'] = 1
                            break
                        if self.interrupt and path.name == 'model.gguf' and not self.stats['injected_disconnects'] and transferred >= 2 * 1024**2:
                            self.stats['injected_disconnects'] = 1
                            break
            except (ConnectionError, OSError):
                pass
            except Exception as error:
                self.errors.append(type(error).__name__ + ': ' + str(error))

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(2)


def _swarm_worker(source, key, info, indices):
    sock = None
    try:
        sock = socket.create_connection(source, timeout=15)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        handshake(sock, key)
        send(sock, 2)
        for _ in range(16):
            kind, data = receive(sock)
            if kind == 1 and not data:
                break
            if kind not in (None, 4, 5):
                raise ValueError('Torrent peer did not unchoke')
        else:
            raise ValueError('Torrent unchoke message limit')
        downloaded = {}
        for index in indices:
            piece_size = min(PIECE, info[b'length'] - index * PIECE)
            blocks = {start: min(BLOCK, piece_size - start) for start in range(0, piece_size, BLOCK)}
            sock.sendall(b''.join(struct.pack('!IBIII', 13, 6, index, start, length)
                                  for start, length in blocks.items()))
            chunk = bytearray(piece_size)
            ancillary = 0
            while blocks:
                kind, data = receive(sock)
                if kind in (None, 4, 5) or (kind == 1 and not data):
                    ancillary += 1
                    if ancillary > 64:
                        raise ValueError('Torrent ancillary message limit')
                    continue
                if kind != 7 or len(data) < 9:
                    raise ValueError('Unexpected torrent piece message: ' + str(kind))
                actual_index, start = struct.unpack('!II', data[:8])
                if actual_index != index or start not in blocks or len(data) - 8 != blocks[start]:
                    raise ValueError('Unrequested torrent block')
                chunk[start:start + blocks.pop(start)] = data[8:]
            if hashlib.sha1(chunk).digest() != info[b'pieces'][index * 20:index * 20 + 20]:
                raise ValueError('Torrent piece integrity verification failed')
            downloaded[index] = bytes(chunk)
        send(sock, 3)
        return downloaded
    finally:
        if sock is not None:
            sock.close()


def download_swarm(value, destination, *, name, size, sha256, sources, timeout=240):
    """Download one file from multiple explicit private peers concurrently.

    Pieces are partitioned across peers. Every piece is SHA-1 checked and the
    complete file is SHA-256 checked before atomic activation. Metadata never
    supplies peers, trackers or DHT.
    """
    info, key = parse(value, name, size)
    if not isinstance(sha256, str) or len(sha256) != 64 or any(c not in '0123456789abcdef' for c in sha256):
        raise ValueError('Invalid torrent trust pin')
    if (not isinstance(sources, (list, tuple)) or not 1 <= len(sources) <= 4
            or any(not isinstance(source, tuple) or len(source) != 2
                   or not isinstance(source[0], str) or type(source[1]) is not int
                   or not 1 <= source[1] <= 65535 for source in sources)
            or len(set(sources)) != len(sources)):
        raise ValueError('Use one to four distinct explicit torrent peers')
    destination = Path(destination)
    if destination.exists():
        with destination.open('rb') as stream:
            valid = destination.stat().st_size == size and hashlib.file_digest(stream, 'sha256').hexdigest() == sha256
        if not valid:
            raise ValueError('Existing torrent asset integrity verification failed')
        return {'name': name, 'bytes': size, 'cached_verified': True, 'protocol': 'BitTorrent v1'}
    partial = destination.with_suffix(destination.suffix + '.partial')
    if partial.exists():
        raise ValueError('Swarm partial resume is not implemented')
    count = len(info[b'pieces']) // 20
    results = {source: {} for source in sources}
    failed_peers = []
    missing = list(range(count))
    active = list(sources)
    deadline = time.monotonic() + timeout
    while missing and active:
        assignments = {source: [] for source in active}
        for index in missing:
            assignments[active[index % len(active)]].append(index)
        round_results, round_errors = {}, {}
        lock = threading.Lock()

        def work(source, indices):
            try:
                pieces = _swarm_worker(source, key, info, indices)
                with lock:
                    round_results[source] = pieces
            except Exception as error:
                with lock:
                    round_errors[source] = type(error).__name__ + ': ' + str(error)[:200]

        threads = [threading.Thread(target=work, args=(source, indices), daemon=True)
                   for source, indices in assignments.items() if indices]
        for thread in threads:
            thread.start()
        for thread in threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Swarm transfer deadline exceeded')
            thread.join(remaining)
            if thread.is_alive():
                raise TimeoutError('Swarm transfer deadline exceeded')
        for source, pieces in round_results.items():
            results[source].update(pieces)
            missing = [index for index in missing if index not in pieces]
        for source in list(active):
            if source in round_errors:
                active.remove(source)
                failed_peers.append({'peer': list(source), 'error': round_errors[source]})
    if missing:
        raise ValueError('Swarm peer failure: ' + json.dumps(failed_peers, sort_keys=True))
    if sum(len(pieces) for pieces in results.values()) != count:
        raise ValueError('Swarm did not return every piece')
    with partial.open('wb') as output:
        output.truncate(size)
        for pieces in results.values():
            for index, data in pieces.items():
                output.seek(index * PIECE)
                output.write(data)
        output.flush()
        os.fsync(output.fileno())
    with partial.open('rb') as stream:
        if partial.stat().st_size != size or hashlib.file_digest(stream, 'sha256').hexdigest() != sha256:
            raise ValueError('Torrent asset integrity verification failed')
    partial.replace(destination)
    peer_bytes = {str(source): sum(len(data) for data in pieces.values())
                  for source, pieces in results.items() if pieces}
    return {'name': name, 'bytes': size, 'protocol': 'BitTorrent v1', 'sha256_verified': True,
            'info_hash': key.hex(), 'swarm': True, 'peer_count': len(sources),
            'peer_bytes': peer_bytes, 'pieces_per_peer': {str(source): len(pieces) for source, pieces in results.items() if pieces},
            'failed_peers': failed_peers, 'retries': len(failed_peers),
            'payload_downloaded_bytes': sum(peer_bytes.values()), 'dht': False, 'trackers': [],
            'peer_discovery': False}


def download(value, destination, *, name, size, sha256, source, attempts=3, timeout=240):
    """Resume only rehashed pieces; SHA-256 precedes atomic activation."""
    info, key = parse(value, name, size)
    if not isinstance(sha256, str) or len(sha256) != 64 or any(c not in '0123456789abcdef' for c in sha256):
        raise ValueError('Invalid torrent trust pin')
    destination = Path(destination)
    if destination.exists():
        with destination.open('rb') as stream:
            valid = destination.stat().st_size == size and hashlib.file_digest(stream, 'sha256').hexdigest() == sha256
        if not valid:
            raise ValueError('Existing torrent asset integrity verification failed')
        return {'name': name, 'bytes': size, 'cached_verified': True, 'resumed': False, 'protocol': 'BitTorrent v1'}
    partial = destination.with_suffix(destination.suffix + '.partial')
    deadline = time.monotonic() + timeout
    payload_bytes, resume_bytes, retries = 0, 0, 0
    for attempt in range(attempts):
        offset = 0
        if partial.exists():
            if partial.stat().st_size > size:
                raise ValueError('Oversized partial torrent asset')
            with partial.open('rb') as stream:
                while offset < size:
                    chunk = stream.read(min(PIECE, size - offset))
                    index = offset // PIECE
                    if len(chunk) != min(PIECE, size - offset) or hashlib.sha1(chunk).digest() != info[b'pieces'][index * 20:index * 20 + 20]:
                        break
                    offset += len(chunk)
            resume_bytes = max(resume_bytes, offset)
        if offset == size:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError('Torrent transfer deadline exceeded')
        try:
            with socket.create_connection(source, timeout=min(15, max(.1, deadline - time.monotonic()))) as sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                handshake(sock, key)
                send(sock, 2)
                for _ in range(16):
                    kind, data = receive(sock)
                    if kind == 1 and not data:
                        break
                    if kind not in (None, 5, 4):
                        raise ValueError('Torrent peer did not unchoke')
                else:
                    raise ValueError('Torrent unchoke message limit')
                with partial.open('r+b' if partial.exists() else 'w+b') as output:
                    output.truncate(offset)
                    output.seek(offset)
                    while offset < size:
                        if time.monotonic() >= deadline:
                            raise TimeoutError('Torrent transfer deadline exceeded')
                        index, piece_size = offset // PIECE, min(PIECE, size - offset)
                        blocks = {start: min(BLOCK, piece_size - start) for start in range(0, piece_size, BLOCK)}
                        sock.sendall(b''.join(struct.pack('!IBIII', 13, 6, index, start, length) for start, length in blocks.items()))
                        chunk = bytearray(piece_size)
                        ancillary = 0
                        while blocks:
                            kind, data = receive(sock)
                            if kind in (None, 4, 5) or (kind == 1 and not data):
                                ancillary += 1
                                if ancillary > 64:
                                    raise ValueError('Torrent ancillary message limit')
                                continue
                            if kind != 7 or len(data) < 9:
                                raise ValueError('Unexpected torrent piece message: ' + str(kind))
                            actual_index, start = struct.unpack('!II', data[:8])
                            if actual_index != index or start not in blocks or len(data) - 8 != blocks[start]:
                                raise ValueError('Unrequested torrent block')
                            chunk[start:start + blocks.pop(start)] = data[8:]
                            payload_bytes += len(data) - 8
                        if hashlib.sha1(chunk).digest() != info[b'pieces'][index * 20:index * 20 + 20]:
                            raise ValueError('Torrent piece integrity verification failed')
                        output.write(chunk)
                        output.flush()
                        offset += piece_size
                    os.fsync(output.fileno())
                send(sock, 3)
            break
        except (OSError, ConnectionError):
            retries += 1
            if attempt + 1 == attempts:
                raise
    with partial.open('rb') as stream:
        if partial.stat().st_size != size or hashlib.file_digest(stream, 'sha256').hexdigest() != sha256:
            raise ValueError('Torrent asset integrity verification failed')
    partial.replace(destination)
    return {'name': name, 'bytes': size, 'resumed': resume_bytes > 0, 'resume_verified_bytes': resume_bytes,
            'reconnections': retries, 'payload_downloaded_bytes': payload_bytes, 'protocol': 'BitTorrent v1',
            'sha256_verified': True, 'info_hash': key.hex(), 'peer': list(source),
            'dht': False, 'trackers': [], 'peer_discovery': False}
