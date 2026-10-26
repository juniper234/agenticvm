"""HMAC-authenticated liveness challenge; distinguishes host-up from member."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
import socket
import threading
import time
from uuid import uuid4

SCHEMA = 'agenticvm.garden-ping.v1'
MAX_MESSAGE = 8192
KEY_BYTES = 32


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _key(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
        raise ValueError('Ping key must be 32 bytes')


def _mac(key, value):
    _key(key)
    return hmac.new(bytes(key), canonical(value), hashlib.sha256).hexdigest()


def challenge(key, garden_id, member_id, *, ttl=30, now=None):
    if not isinstance(garden_id, str) or not 8 <= len(garden_id) <= 128:
        raise ValueError('Invalid garden identity')
    if not isinstance(member_id, str) or not member_id:
        raise ValueError('Invalid member identity')
    if type(ttl) is not int or not 1 <= ttl <= 300:
        raise ValueError('Ping TTL must be 1-300 seconds')
    issued = int(time.time() if now is None else now)
    payload = {'schema': 'agenticvm.garden-challenge.v1', 'id': str(uuid4()),
               'garden': garden_id, 'member': member_id,
               'nonce': secrets.token_hex(16), 'issued': issued, 'expires': issued + ttl}
    return dict(payload, mac=_mac(key, payload))


def verify_challenge(value, key, *, garden_id=None, member_id=None, now=None):
    fields = {'schema', 'id', 'garden', 'member', 'nonce', 'issued', 'expires', 'mac'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('Invalid ping challenge fields')
    if value['schema'] != 'agenticvm.garden-challenge.v1':
        raise ValueError('Invalid ping challenge schema')
    if garden_id is not None and value['garden'] != garden_id:
        raise ValueError('Ping challenge garden mismatch')
    if member_id is not None and value['member'] != member_id:
        raise ValueError('Ping challenge member mismatch')
    payload = {name: value[name] for name in fields if name != 'mac'}
    if not hmac.compare_digest(value['mac'], _mac(key, payload)):
        raise ValueError('Ping challenge authentication failed')
    current = time.time() if now is None else now
    if not value['issued'] - 5 <= current <= value['expires']:
        raise ValueError('Ping challenge expired or not yet valid')
    return payload


def response(value, key, *, now=None):
    result = {'schema': 'agenticvm.garden-response.v1', 'id': value['id'],
              'garden': value['garden'], 'member': value['member'],
              'nonce': value['nonce'], 'received': int(time.time() if now is None else now)}
    return dict(result, mac=_mac(key, result))


def verify_response(value, request, key, *, now=None):
    fields = {'schema', 'id', 'garden', 'member', 'nonce', 'received', 'mac'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('Invalid ping response fields')
    if value['schema'] != 'agenticvm.garden-response.v1':
        raise ValueError('Invalid ping response schema')
    for name in ('id', 'garden', 'member', 'nonce'):
        if value[name] != request[name]:
            raise ValueError('Ping response correlation failed')
    payload = {name: value[name] for name in fields if name != 'mac'}
    if not hmac.compare_digest(value['mac'], _mac(key, payload)):
        raise ValueError('Ping response authentication failed')
    if abs((time.time() if now is None else now) - value['received']) > 30:
        raise ValueError('Ping response is stale')
    return payload


class PingServer:
    """Small authenticated responder; sequential, bounded and stoppable."""

    def __init__(self, key, garden_id, member_id, *, host='127.0.0.1', port=0):
        _key(key)
        self.key, self.garden_id, self.member_id = bytes(key), garden_id, member_id
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen(8)
        self.socket.settimeout(0.2)
        self.address = self.socket.getsockname()
        self.used = set()
        self.events = []
        self.error = None
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, name='garden-ping', daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        while not self.stopped.is_set():
            try:
                connection, peer = self.socket.accept()
            except TimeoutError:
                continue
            except OSError as error:
                if not self.stopped.is_set():
                    self.error = str(error)
                break
            with connection:
                connection.settimeout(2)
                try:
                    raw = self._read_line(connection)
                    value = json.loads(raw)
                    request = verify_challenge(value, self.key, garden_id=self.garden_id,
                                               member_id=self.member_id)
                    if request['id'] in self.used:
                        raise ValueError('Ping challenge replay')
                    self.used.add(request['id'])
                    if len(self.used) > 128:
                        self.used = set(sorted(self.used)[-64:])
                    connection.sendall((json.dumps(response(value, self.key)) + '\n').encode())
                    self.events.append({'at': datetime.now(timezone.utc).isoformat(),
                                        'peer': peer[0], 'id': request['id'], 'ok': True})
                except Exception as error:
                    self.events.append({'at': datetime.now(timezone.utc).isoformat(),
                                        'peer': peer[0], 'ok': False, 'error': str(error)[:200]})
                    try:
                        connection.sendall((json.dumps({'schema': 'agenticvm.garden-ping-error.v1',
                                                        'error': str(error)[:200]}) + '\n').encode())
                    except OSError:
                        pass
        self.socket.close()

    @staticmethod
    def _read_line(connection):
        data = bytearray()
        while len(data) <= MAX_MESSAGE:
            chunk = connection.recv(1024)
            if not chunk:
                break
            data.extend(chunk)
            if b'\n' in chunk:
                return bytes(data).split(b'\n', 1)[0]
        raise ValueError('Ping message exceeded its limit or ended early')

    def stop(self):
        self.stopped.set()
        self.thread.join(2)
        try:
            self.socket.close()
        except OSError:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def ping(address, port, key, garden_id, member_id, *, timeout=2):
    _key(key)
    started = time.monotonic()
    request = challenge(key, garden_id, member_id)
    try:
        with socket.create_connection((address, port), timeout=timeout) as stream:
            stream.settimeout(timeout)
            stream.sendall((json.dumps(request) + '\n').encode())
            raw = PingServer._read_line(stream)
        value = json.loads(raw)
        if value.get('schema') == 'agenticvm.garden-ping-error.v1':
            return {'schema': SCHEMA, 'address': address, 'port': port, 'reachable': True,
                    'garden_member': False, 'error': value.get('error'),
                    'latency_ms': round((time.monotonic() - started) * 1000, 1)}
        verify_response(value, request, key)
        return {'schema': SCHEMA, 'address': address, 'port': port, 'reachable': True,
                'garden_member': True, 'member': member_id,
                'latency_ms': round((time.monotonic() - started) * 1000, 1)}
    except (OSError, TimeoutError) as error:
        return {'schema': SCHEMA, 'address': address, 'port': port, 'reachable': False,
                'garden_member': False, 'error': type(error).__name__,
                'latency_ms': round((time.monotonic() - started) * 1000, 1)}
    except ValueError as error:
        return {'schema': SCHEMA, 'address': address, 'port': port, 'reachable': True,
                'garden_member': False, 'error': str(error),
                'latency_ms': round((time.monotonic() - started) * 1000, 1)}
