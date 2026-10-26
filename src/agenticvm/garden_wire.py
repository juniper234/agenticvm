"""Bounded public routing for independent TLS streams on one virtio port.

The routing layer has no TLS keys. A channel number is routing metadata, never
an authenticated identity; PeerTLSConfig authenticates every logical stream.
"""
from __future__ import annotations
import struct
import threading
import time

HEADER = struct.Struct('!BI')
MAX_CHUNK = 16384
MAX_QUEUED = 131072
MAX_MEMBERS = 8
MEMBERS = tuple(range(1, MAX_MEMBERS + 1))


def packet(channel, data):
    if type(channel) is not int or channel not in MEMBERS or not 1 <= len(data) <= MAX_CHUNK:
        raise ValueError('Invalid garden routing frame')
    return HEADER.pack(channel, len(data))+data


class Decoder:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        if len(data) > MAX_CHUNK or len(self.buffer)+len(data) > MAX_CHUNK*2+HEADER.size:
            raise ValueError('Garden routing buffer exceeds its bound')
        self.buffer.extend(data)
        result = []
        while len(self.buffer) >= HEADER.size:
            channel,size = HEADER.unpack_from(self.buffer)
            if channel not in MEMBERS or not 1 <= size <= MAX_CHUNK:
                raise ValueError('Invalid garden routing header')
            if len(self.buffer) < HEADER.size+size:
                break
            result.append((channel,bytes(self.buffer[HEADER.size:HEADER.size+size])))
            del self.buffer[:HEADER.size+size]
        return result


class Multiplexer:
    """One byte-reader, serialized writers, bounded independent receive queues."""
    def __init__(self, raw, identity):
        if identity not in MEMBERS:
            raise ValueError('Unknown garden member')
        self.raw,self.identity = raw,identity
        self.condition,self.writer = threading.Condition(),threading.Lock()
        self.buffers = {i:bytearray() for i in MEMBERS if i != identity}
        self.stopped = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._read,name='garden-wire',daemon=True)
        self.thread.start()

    def _read(self):
        decoder = Decoder()
        try:
            while not self.stopped.is_set():
                try:
                    data = self.raw.read(MAX_CHUNK,.25)
                except TimeoutError:
                    continue
                if not data:
                    raise ConnectionError('Garden physical stream closed')
                for channel,content in decoder.feed(data):
                    with self.condition:
                        if channel not in self.buffers or len(self.buffers[channel])+len(content)>MAX_QUEUED:
                            raise ValueError('Invalid or congested garden channel')
                        self.buffers[channel].extend(content)
                        self.condition.notify_all()
        except Exception as error:
            self.error = str(error)[:200]
            self.stopped.set()
            with self.condition:
                self.condition.notify_all()

    def channel(self, peer):
        if peer not in self.buffers:
            raise ValueError('Invalid garden destination')
        owner = self
        class Channel:
            def read(self, size, timeout):
                deadline = time.monotonic()+timeout
                with owner.condition:
                    while not owner.buffers[peer]:
                        if owner.stopped.is_set():
                            raise ConnectionError(owner.error or 'Garden stopped')
                        remaining = deadline-time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError('Garden logical read deadline')
                        owner.condition.wait(remaining)
                    data = bytes(owner.buffers[peer][:size])
                    del owner.buffers[peer][:size]
                    return data

            def write(self, data, timeout):
                deadline = time.monotonic()+timeout
                for offset in range(0,len(data),MAX_CHUNK):
                    remaining = deadline-time.monotonic()
                    if remaining <= 0 or not owner.writer.acquire(timeout=max(0,remaining)):
                        raise TimeoutError('Garden logical write deadline')
                    try:
                        if owner.stopped.is_set():
                            raise ConnectionError(owner.error or 'Garden stopped')
                        owner.raw.write(packet(peer,data[offset:offset+MAX_CHUNK]),max(.001,deadline-time.monotonic()))
                    finally:
                        owner.writer.release()

            def close(self):
                # TLS close_notify belongs to this logical stream. A logical
                # stream never closes the shared port or another peer's TLS.
                pass
        return Channel()

    def close(self):
        self.stopped.set()
        with self.condition:
            self.condition.notify_all()
        self.thread.join(2)
        self.raw.close()
