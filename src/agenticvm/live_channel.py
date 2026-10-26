"""Continuous mutually authenticated agent data, with durable reconnect state.

TLS is supplied by peer_protocol. This module is copied unchanged into guests.
Messages are data only; application side effects require their own transaction.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import time
from uuid import UUID, uuid4

try:
    from .peer_protocol import _json_bytes, _unique_object, PeerError
except ImportError:
    from peer_protocol import _json_bytes, _unique_object, PeerError

MAX_BODY = 16384
MAX_FRAME = 20480
MAX_RECORDS = 4096
MAX_PENDING = 128
WINDOW = 8


class InvalidLiveFrame(ValueError):
    pass


def integer(value, minimum=0):
    if type(value) is not int or not minimum <= value <= 2**53:
        raise InvalidLiveFrame('Invalid sequence or counter')
    return value


def message_id(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise InvalidLiveFrame('Invalid message UUID')
    return value


def body_bytes(value):
    if not isinstance(value, dict):
        raise InvalidLiveFrame('Agent payload must be a JSON object')
    content = _json_bytes(value)
    if len(content) > MAX_BODY:
        raise InvalidLiveFrame('Agent payload exceeds 16 KiB')
    return content


def exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise InvalidLiveFrame('Unexpected frame fields')


class Mailbox:
    """FULL/WAL durable sequences and receipts, bounded by explicit disk quotas."""
    def __init__(self, path, run_id, identity, peer):
        message_id(run_id)
        self.path = Path(path)
        if self.path.is_symlink() or any(p.is_symlink() for p in self.path.parents):
            raise ValueError('Redirected mailbox refused')
        self.db = sqlite3.connect(self.path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS outgoing (seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL,
                payload BLOB NOT NULL, digest TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS incoming (seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL,
                payload BLOB NOT NULL, digest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS counters (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sent INTEGER NOT NULL, received INTEGER NOT NULL, acked INTEGER NOT NULL, consumed INTEGER NOT NULL);
        ''')
        expected = {'run':run_id, 'identity':identity, 'peer':peer}
        try:
            with self.db:
                stored = dict(self.db.execute('SELECT key,value FROM metadata').fetchall())
                if stored and stored != expected:
                    raise ValueError('Mailbox identity/run cannot be changed')
                self.db.executemany('INSERT OR IGNORE INTO metadata VALUES (?,?)', expected.items())
                if self.db.execute('SELECT COUNT(*) FROM counters').fetchone()[0] == 0:
                    sent,acked = self.db.execute('SELECT COALESCE(MAX(seq),0),COALESCE(MAX(CASE WHEN acknowledged=1 THEN seq ELSE 0 END),0) FROM outgoing').fetchone()
                    received = self.db.execute('SELECT COALESCE(MAX(seq),0) FROM incoming').fetchone()[0]
                    self.db.execute('INSERT INTO counters VALUES (1,?,?,?,0)',(sent,received,acked))
        except BaseException:
            self.db.close()
            raise
        self.run_id, self.identity, self.peer = run_id, identity, peer

    def state(self):
        row = self.db.execute('SELECT sent,received,acked FROM counters WHERE singleton=1').fetchone()
        return dict(row)

    def _records(self):
        return self.db.execute('SELECT (SELECT COUNT(*) FROM outgoing)+(SELECT COUNT(*) FROM incoming)').fetchone()[0]

    def enqueue(self, body, identifier=None):
        payload = body_bytes(body)
        identifier = message_id(identifier or str(uuid4()))
        digest = hashlib.sha256(payload).hexdigest()
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            previous = self.db.execute('SELECT * FROM outgoing WHERE id=?', (identifier,)).fetchone()
            if previous:
                if previous['digest'] != digest or previous['payload'] != payload:
                    raise InvalidLiveFrame('Submission UUID reused with changed data')
                return dict(previous)
            state = self.state()
            if state['sent']-state['acked'] >= MAX_PENDING or self._records() >= MAX_RECORDS:
                raise BufferError('Durable mailbox quota reached; producer must wait or apply an explicit retention policy')
            sequence = state['sent']+1
            self.db.execute('INSERT INTO outgoing (seq,id,payload,digest) VALUES (?,?,?,?)', (sequence,identifier,payload,digest))
            self.db.execute('UPDATE counters SET sent=? WHERE singleton=1',(sequence,))
            return {'seq':sequence,'id':identifier,'payload':payload,'digest':digest,'acknowledged':0}

    def acknowledge(self, sequence):
        integer(sequence)
        state = self.state()
        if sequence < state['acked'] or sequence > state['sent']:
            raise InvalidLiveFrame('Receipt is ahead of sent data or rolls back known delivery')
        with self.db:
            self.db.execute('UPDATE outgoing SET acknowledged=1 WHERE seq<=? AND acknowledged=0', (sequence,))
            self.db.execute('UPDATE counters SET acked=? WHERE singleton=1',(sequence,))

    def synchronize(self, remote):
        exact(remote, ('sent','received','acked'))
        for number in remote.values():
            integer(number)
        own = self.state()
        if remote['sent'] < own['received'] or remote['acked'] > own['received'] or remote['acked'] > remote['sent']:
            raise InvalidLiveFrame('Remote durable state is inconsistent or rolled back')
        self.acknowledge(remote['received'])

    def pending(self, after, limit=WINDOW):
        return [dict(row) for row in self.db.execute('SELECT * FROM outgoing WHERE seq>? AND acknowledged=0 ORDER BY seq LIMIT ?', (after,limit))]

    def accept(self, data):
        exact(data, ('seq','id','payload','digest'))
        sequence, identifier = integer(data['seq'],1), message_id(data['id'])
        payload = body_bytes(data['payload'])
        digest = hashlib.sha256(payload).hexdigest()
        if data['digest'] != digest:
            raise InvalidLiveFrame('Message digest mismatch')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            own = self.state()
            if sequence <= own['received']:
                old = self.db.execute('SELECT * FROM incoming WHERE seq=?', (sequence,)).fetchone()
                if old is not None and (old['id'] != identifier or old['digest'] != digest or old['payload'] != payload):
                    raise InvalidLiveFrame('Received sequence was reused with changed data')
                # A compacted sequence is already consumed and is never delivered
                # again, even though its old payload/UUID are no longer retained.
                return False
            if sequence != own['received']+1:
                raise InvalidLiveFrame('Received sequence has a gap')
            if self._records() >= MAX_RECORDS:
                raise BufferError('Durable inbox quota reached')
            self.db.execute('INSERT INTO incoming VALUES (?,?,?,?)', (sequence,identifier,payload,digest))
            self.db.execute('UPDATE counters SET received=? WHERE singleton=1',(sequence,))
            return True

    def incoming(self, limit=32):
        consumed = self.db.execute('SELECT consumed FROM counters WHERE singleton=1').fetchone()[0]
        return [dict(row) for row in self.db.execute('SELECT * FROM incoming WHERE seq>? ORDER BY seq LIMIT ?',(consumed,limit))]

    def consume(self, sequence):
        integer(sequence)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            consumed,received = self.db.execute('SELECT consumed,received FROM counters WHERE singleton=1').fetchone()
            if not consumed <= sequence <= received:
                raise InvalidLiveFrame('Invalid application consumption checkpoint')
            self.db.execute('UPDATE counters SET consumed=? WHERE singleton=1',(sequence,))

    def prune(self, keep=128):
        """Explicit retention: never remove unacknowledged or unconsumed data.

        Permanent sequence high-water marks survive compaction and reject stale
        delivery. UUID-based submission deduplication covers retained records;
        callers must keep business task IDs in their own application ledger.
        """
        if type(keep) is not int or not 1 <= keep <= 1024:
            raise ValueError('Keep one to 1024 recent records per direction')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            acked,consumed = self.db.execute('SELECT acked,consumed FROM counters WHERE singleton=1').fetchone()
            self.db.execute('DELETE FROM outgoing WHERE seq<=? AND acknowledged=1',(acked-keep,))
            self.db.execute('DELETE FROM incoming WHERE seq<=?',(consumed-keep,))

    def close(self):
        self.db.close()


class Frames:
    """Length-prefixed, bounded frames; partial reads survive idle timeouts."""
    def __init__(self, stream, mailbox):
        self.stream, self.mailbox = stream, mailbox
        self.buffer, self.tx, self.rx = bytearray(), 0, 0

    def send(self, kind, body):
        envelope = {'v':1,'run':self.mailbox.run_id,'sender':self.mailbox.identity,
                    'recipient':self.mailbox.peer,'wire':self.tx+1,'kind':kind,'body':body}
        content = _json_bytes(envelope)
        if len(content) > MAX_FRAME:
            raise InvalidLiveFrame('Live frame exceeds its bound')
        self.stream.write(struct.pack('!I',len(content))+content, 5)
        self.tx += 1

    def receive(self, timeout):
        deadline = time.monotonic()+timeout
        while True:
            if len(self.buffer) >= 4:
                size = struct.unpack('!I',self.buffer[:4])[0]
                if not 1 <= size <= MAX_FRAME:
                    raise InvalidLiveFrame('Invalid live frame size')
                if len(self.buffer) >= size+4:
                    content = bytes(self.buffer[4:size+4])
                    del self.buffer[:size+4]
                    value = json.loads(content.decode('utf-8','strict'), object_pairs_hook=_unique_object,
                        parse_constant=lambda _: (_ for _ in ()).throw(InvalidLiveFrame('Non-finite number')))
                    exact(value, ('v','run','sender','recipient','wire','kind','body'))
                    if type(value['v']) is not int or value['v'] != 1 or value['run'] != self.mailbox.run_id or value['sender'] != self.mailbox.peer or value['recipient'] != self.mailbox.identity:
                        raise InvalidLiveFrame('Wrong live protocol, run or identity')
                    if integer(value['wire'],1) != self.rx+1:
                        raise InvalidLiveFrame('Wire sequence was replayed or skipped')
                    self.rx += 1
                    return value
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Idle frame read')
            data = self.stream.read(min(4096,MAX_FRAME+4-len(self.buffer)),remaining)
            if not data:
                raise ConnectionError('Live peer disconnected')
            self.buffer.extend(data)


def conversation(stream, mailbox, *, deadline, produce, completed, event, heartbeat=1.0, dead_after=6.0):
    """One single-threaded TLS reactor; both ends may send independently."""
    frames = Frames(stream,mailbox)
    frames.send('sync',mailbox.state())
    initial = frames.receive(10)
    if initial['kind'] != 'sync':
        raise InvalidLiveFrame('First frame must synchronize durable mailboxes')
    mailbox.synchronize(initial['body'])
    last_sent = mailbox.state()['acked']
    last_tx = last_rx = time.monotonic()
    ping = None
    event('connected', tls=stream.info, state=mailbox.state())
    while time.monotonic() < deadline:
        now = time.monotonic()
        produce(mailbox,now)
        state = mailbox.state()
        for row in mailbox.pending(last_sent, max(0,WINDOW-(last_sent-state['acked']))):
            frames.send('data', {'seq':row['seq'],'id':row['id'],'payload':json.loads(row['payload']), 'digest':row['digest']})
            last_sent, last_tx = row['seq'], time.monotonic()
            event('data_sent',seq=row['seq'],message_id=row['id'],payload_sha256=row['digest'])
        if completed(mailbox):
            frames.send('close',mailbox.state())
            return True
        if now-last_rx > dead_after:
            raise TimeoutError('Heartbeat deadline expired')
        if now-last_tx >= heartbeat and ping is None:
            ping = str(uuid4())
            frames.send('ping',{'nonce':ping})
            last_tx = time.monotonic()
            event('heartbeat_sent')
        try:
            envelope = frames.receive(min(0.05,max(0.001,deadline-time.monotonic())))
        except TimeoutError:
            continue
        last_rx = time.monotonic()
        kind, body = envelope['kind'], envelope['body']
        if kind == 'data':
            fresh = mailbox.accept(body)
            frames.send('ack',{'received':mailbox.state()['received']})
            last_tx = time.monotonic()
            event('data_received',seq=body['seq'],message_id=body['id'],payload_sha256=body['digest'],duplicate=not fresh)
        elif kind == 'ack':
            exact(body, ('received',))
            if integer(body['received']) > last_sent:
                raise InvalidLiveFrame('Receipt acknowledges data not sent on this connection')
            old = mailbox.state()['acked']
            mailbox.acknowledge(body['received'])
            event('acknowledged',received=body['received'],previous=old)
        elif kind == 'ping':
            exact(body, ('nonce',))
            message_id(body['nonce'])
            frames.send('pong',body)
            last_tx = time.monotonic()
            event('heartbeat_received')
        elif kind == 'pong':
            exact(body, ('nonce',))
            if body['nonce'] != ping:
                raise InvalidLiveFrame('Heartbeat reply does not match challenge')
            ping = None
            event('heartbeat_acknowledged')
        elif kind == 'close':
            mailbox.synchronize(body)
            if not completed(mailbox):
                raise ConnectionError('Peer closed before local work finished')
            return True
        else:
            raise InvalidLiveFrame('Unknown live frame kind')
    return False


def serve(mailbox, connect, *, seconds=0, produce=lambda m,t:None, completed=lambda m:False,
          event=lambda *args,**kw:None, stop=lambda:False):
    """Keep the link alive until stopped. Reconnect with the same identity/ledger.

    A finite seconds argument is for tests. Zero keeps the daemon running.
    Invalid application framing is fatal; network/TLS failures never downgrade
    encryption, and use bounded exponential reconnect backoff.
    """
    deadline = time.monotonic()+seconds if seconds else float('inf')
    failures = 0
    while time.monotonic() < deadline and not stop():
        stream = None
        try:
            stream = connect()
            result = conversation(stream,mailbox,deadline=deadline,produce=produce,
                                  completed=lambda m: stop() or completed(m),event=event)
            return result
        except (InvalidLiveFrame, BufferError):
            raise
        except (OSError, PeerError, TimeoutError, ConnectionError) as error:
            failures += 1
            event('disconnected',error_class=type(error).__name__,reason=str(error)[:160],state=mailbox.state())
        finally:
            if stream:
                stream.close()
        # Continue producing during a short network outage, retaining bounded work.
        end = min(deadline,time.monotonic()+min(2,0.25*2**min(failures-1,3)))
        while time.monotonic() < end and not stop():
            produce(mailbox,time.monotonic())
            time.sleep(0.05)
    return False
