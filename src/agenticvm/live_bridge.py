"""A continuous blind byte relay and owned-VM adapter. No HTTP, USB or keys.

The routing preface is public metadata, never an authentication credential.
Only end-to-end mutual TLS authenticates agents. A malicious relay can deny
service; it cannot authenticate as the pinned remote agent.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import select
import socket
import socketserver
import threading
import time
from uuid import UUID

READY = b'AGENTICVM-LIVE/1 READY\n'
BUFFER = 65536


def room_id(value):
    if not isinstance(value,str) or str(UUID(value)) != value:
        raise ValueError('Use a canonical public routing-room UUID')
    return value


def line(sock, limit=256, timeout=5):
    deadline, content = time.monotonic()+timeout, bytearray()
    while len(content) < limit:
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Relay preface deadline expired')
        sock.settimeout(remaining)
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError('Relay closed before preface completed')
        content.extend(byte)
        if byte == b'\n':
            return bytes(content)
    raise ValueError('Relay preface exceeds its limit')


def close_socket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def pump(left, right, stop, *, idle=12, observe=lambda direction,data:None):
    """Bounded bidirectional queues provide TCP backpressure to slow readers."""
    sockets = (left,right)
    pending = {left:bytearray(),right:bytearray()}
    totals, last = [0,0], time.monotonic()
    for sock in sockets:
        sock.setblocking(False)
    while not stop():
        if time.monotonic()-last > idle:
            raise TimeoutError('Blind relay idle deadline expired')
        readable = [sock for sock in sockets if len(pending[right if sock is left else left]) < BUFFER]
        writable = [sock for sock in sockets if pending[sock]]
        reads, writes, errors = select.select(readable,writable,sockets,0.1)
        if errors:
            raise ConnectionError('Relay socket failed')
        for sock in writes:
            try:
                count = sock.send(pending[sock])
            except BlockingIOError:
                continue
            if count <= 0:
                return totals
            del pending[sock][:count]
            last = time.monotonic()
        for sock in reads:
            other = right if sock is left else left
            try:
                data = sock.recv(min(16384,BUFFER-len(pending[other])))
            except BlockingIOError:
                continue
            if not data:
                return totals
            pending[other].extend(data)
            index = 0 if sock is left else 1
            totals[index] += len(data)
            observe(index,data)
            last = time.monotonic()
    return totals


class Pair:
    def __init__(self):
        self.sockets = {}
        self.ready, self.done = threading.Event(),threading.Event()


class Relay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, port=0, *, max_rooms=8, observe=lambda *args:None):
        self.rooms, self.lock = {},threading.Lock()
        self.closed = threading.Event()
        self.max_rooms, self.observe = max_rooms, observe
        self.slots = threading.BoundedSemaphore(max_rooms*2)
        self.connections, self.failures = 0,0
        relay = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                pair = room = side = None
                try:
                    header = json.loads(line(sock).decode('ascii'))
                    if not isinstance(header,dict) or set(header) != {'v','room','side'} or type(header['v']) is not int or header['v'] != 1 or header['side'] not in ('a','b'):
                        raise ValueError('Invalid public routing preface')
                    room, side = room_id(header['room']),header['side']
                    with relay.lock:
                        pair = relay.rooms.get(room)
                        if pair is None:
                            if len(relay.rooms) >= relay.max_rooms:
                                raise ValueError('Relay room quota reached')
                            pair = relay.rooms[room] = Pair()
                        if side in pair.sockets:
                            raise ValueError('This side already has a live connection')
                        pair.sockets[side] = sock
                        if len(pair.sockets) == 2:
                            pair.ready.set()
                    if not pair.ready.wait(8) or relay.closed.is_set() or pair.done.is_set():
                        raise TimeoutError('Other endpoint did not arrive')
                    if side == 'a':
                        for endpoint in pair.sockets.values():
                            endpoint.settimeout(5)
                            endpoint.sendall(READY)
                        relay.connections += 1
                        pump(pair.sockets['a'],pair.sockets['b'],
                            lambda:relay.closed.is_set() or pair.done.is_set(),
                            observe=lambda direction,data:relay.observe(room,direction,data))
                    else:
                        while not pair.done.wait(0.1) and not relay.closed.is_set():
                            pass
                except (OSError,ValueError,TimeoutError):
                    relay.failures += 1
                finally:
                    if pair is not None and side and pair.sockets.get(side) is sock:
                        pair.done.set()
                        for endpoint in tuple(pair.sockets.values()):
                            close_socket(endpoint)
                        with relay.lock:
                            if relay.rooms.get(room) is pair:
                                del relay.rooms[room]

        super().__init__(('127.0.0.1',port),Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request,client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request,client_address)
        finally:
            self.slots.release()

    def disconnect_all(self):
        with self.lock:
            pairs = tuple(self.rooms.values())
        for pair in pairs:
            pair.done.set()
            pair.ready.set()
            for sock in tuple(pair.sockets.values()):
                close_socket(sock)

    def stop(self):
        self.closed.set()
        self.disconnect_all()
        self.shutdown()
        self.server_close()


def join(host,port,room,side):
    room_id(room)
    if side not in ('a','b'):
        raise ValueError('Side must be a or b')
    sock = socket.create_connection((host,port),timeout=3)
    try:
        sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        sock.settimeout(5)
        sock.sendall(json.dumps({'v':1,'room':room,'side':side},separators=(',',':')).encode('ascii')+b'\n')
        if line(sock,timeout=10) != READY:
            raise ValueError('Invalid relay readiness response')
        return sock
    except BaseException:
        close_socket(sock)
        raise


class Adapter(threading.Thread):
    """Reconnect a VM's owned local byte socket to a public untrusted relay."""
    def __init__(self, connect_local, host, port, room, side):
        super().__init__(name='live-adapter-'+side,daemon=True)
        self.connect_local,self.host,self.port,self.room,self.side = connect_local,host,port,room_id(room),side
        self.stop_event = threading.Event()
        self.sockets, self.generations, self.failures = [],0,0

    def run(self):
        while not self.stop_event.is_set():
            local = remote = None
            try:
                remote = join(self.host,self.port,self.room,self.side)
                local = self.connect_local()
                self.sockets = [local,remote]
                self.generations += 1
                pump(local,remote,self.stop_event.is_set)
            except Exception as error:
                self.failures += 1
                self.last_error = {'class':type(error).__name__,'message':str(error)[:160]}
            finally:
                for sock in (local,remote):
                    if sock is not None:
                        close_socket(sock)
                self.sockets = []
            self.stop_event.wait(min(2,0.25*2**min(self.failures,3)))

    def stop(self):
        self.stop_event.set()
        for sock in tuple(self.sockets):
            close_socket(sock)
        self.join(timeout=12)
        if self.is_alive():
            raise RuntimeError('Adapter did not stop within its bounded handshake deadline')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command',required=True)
    relay = commands.add_parser('relay')
    relay.add_argument('--port',type=int,default=8745)
    attach = commands.add_parser('attach')
    attach.add_argument('--workspace',required=True)
    attach.add_argument('--relay-host',default='127.0.0.1')
    attach.add_argument('--relay-port',type=int,default=8745)
    attach.add_argument('--room',required=True)
    attach.add_argument('--side',choices=('a','b'),required=True)
    args = parser.parse_args(argv)
    if args.command == 'relay':
        service = Relay(args.port)
        print(json.dumps({'listening':'127.0.0.1:'+str(service.server_address[1]),'decrypts':False}),flush=True)
        try:
            service.serve_forever(poll_interval=0.1)
        except KeyboardInterrupt:
            service.closed.set()
            service.disconnect_all()
            service.server_close()
        return 0
    from .state import StateStore
    from .qemu import QemuBackend
    from .transport import SocketTransport
    store = StateStore(args.workspace)
    def connect():
        state = store.load()
        if not state.get('peer_socket'):
            raise ValueError('The owned VM needs a dedicated --peer-channel')
        backend = QemuBackend(store,Path(state['executable']))
        with backend._process(state) as process:
            if not process.alive():
                raise ConnectionError('Owned VM is stopped')
            return SocketTransport(state['peer_socket'],3).socket
    adapter = Adapter(connect,args.relay_host,args.relay_port,args.room,args.side)
    adapter.start()
    try:
        while adapter.is_alive():
            adapter.join(0.5)
    except KeyboardInterrupt:
        adapter.stop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
