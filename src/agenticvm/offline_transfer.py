"""Signed, sealed messages with durable inboxes. No sockets or remote execution.

This file also runs standalone inside a Linux VM. Only public contact cards and
ciphertext envelopes cross the carrier; private identities are generated locally.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from uuid import UUID, uuid4

HERE = Path(__file__).resolve()
candidates = [HERE.parent/'transfer-libs']
if len(HERE.parents) > 2:
    candidates.append(HERE.parents[2]/'tools/transfer-runtime'/('windows' if os.name == 'nt' else 'linux'))
for candidate in candidates:
    if candidate.is_dir():
        sys.path.insert(0, str(candidate))

from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

MAGIC = b'AgenticVM-Sealed-v1\n'
DOMAIN = b'AgenticVM signed offline message v1\x00'
MAX_PAYLOAD = 512*1024
MAX_ENVELOPE = 768*1024
MAX_MESSAGES = 1024
MAX_TTL = 7*24*60*60
CARD_FIELDS = {'schema', 'name', 'box', 'sign'}
MESSAGE_FIELDS = {'schema', 'id', 'sender', 'recipient', 'created', 'expires', 'kind', 'reply_to', 'payload'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def parsed(raw, limit=MAX_ENVELOPE):
    if len(raw) > limit:
        raise ValueError('Input exceeds its size limit')
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON')))


def b64(data):
    return base64.b64encode(bytes(data)).decode('ascii')


def unb64(value, size=None):
    if not isinstance(value, str):
        raise ValueError('Expected base64 text')
    data = base64.b64decode(value, validate=True)
    if b64(data) != value or (size is not None and len(data) != size):
        raise ValueError('Invalid base64 encoding or length')
    return data


def identifier(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError('Expected a canonical message UUID')
    return value


def fingerprint(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('Expected a SHA-256 fingerprint')
    return value


def card(value):
    if not isinstance(value, dict) or set(value) != CARD_FIELDS or value['schema'] != 'agenticvm.contact.v1':
        raise ValueError('Invalid contact card')
    if not isinstance(value['name'], str) or not re.fullmatch('[a-z][a-z0-9-]{0,31}', value['name']):
        raise ValueError('Invalid contact name')
    unb64(value['box'], 32)
    unb64(value['sign'], 32)
    return sha(encoded(value))


def regular(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        if item.is_symlink() or getattr(item, 'is_junction', lambda: False)():
            raise ValueError('Redirected paths are refused')
    return path


def read_limited(path, limit=MAX_ENVELOPE):
    path = regular(path)
    with path.open('rb') as source:
        content = source.read(limit+1)
    if len(content) > limit:
        raise ValueError('File exceeds its size limit')
    return content


def write_new(path, content, *, private=False):
    path = regular(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, 'wb') as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


class Endpoint:
    def __init__(self, directory):
        self.directory = regular(directory)
        private = parsed(read_limited(self.directory/'identity.private.json', 4096))
        if set(private) != {'public', 'box_private', 'sign_private'}:
            raise ValueError('Invalid private identity')
        self.public = private['public']
        self.fingerprint = card(self.public)
        self.box = PrivateKey(unb64(private['box_private'], 32))
        self.sign = SigningKey(unb64(private['sign_private'], 32))
        if b64(self.box.public_key) != self.public['box'] or b64(self.sign.verify_key) != self.public['sign']:
            raise ValueError('Private identity does not match its public card')
        database = regular(self.directory/'mail.sqlite')
        if not database.is_file():
            raise ValueError('Endpoint ledger is absent')
        self.db = sqlite3.connect(database, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')

    @classmethod
    def create(cls, directory, name):
        directory = regular(directory)
        if not re.fullmatch('[a-z][a-z0-9-]{0,31}', name):
            raise ValueError('Use a short lowercase endpoint name')
        directory.mkdir(mode=0o700)
        box, sign = PrivateKey.generate(), SigningKey.generate()
        public = {'schema': 'agenticvm.contact.v1', 'name': name, 'box': b64(box.public_key), 'sign': b64(sign.verify_key)}
        write_new(directory/'identity.private.json', encoded({'public': public, 'box_private': b64(box), 'sign_private': b64(sign)}), private=True)
        write_new(directory/'contact.json', encoded(public))
        with closing(sqlite3.connect(directory/'mail.sqlite')) as db, db:
            db.executescript('''
                CREATE TABLE contacts (fingerprint TEXT PRIMARY KEY, card BLOB NOT NULL);
                CREATE TABLE mail (id TEXT PRIMARY KEY, direction TEXT NOT NULL,
                    peer TEXT NOT NULL, kind TEXT NOT NULL, reply_to TEXT,
                    envelope BLOB NOT NULL, digest TEXT NOT NULL, payload BLOB NOT NULL,
                    acked INTEGER NOT NULL DEFAULT 0, receipt TEXT);
            ''')
        return cls(directory)

    def close(self):
        self.db.close()

    def trust(self, public, expected):
        actual = card(public)
        if actual != fingerprint(expected) or actual == self.fingerprint:
            raise ValueError('Contact fingerprint does not match the independently checked value')
        with self.db:
            if self.db.execute('SELECT COUNT(*) FROM contacts').fetchone()[0] >= 16:
                raise ValueError('Contact limit reached')
            prior = self.db.execute('SELECT card FROM contacts WHERE fingerprint=?', (actual,)).fetchone()
            if prior and prior[0] != encoded(public):
                raise ValueError('Contact already exists with different contents')
            self.db.execute('INSERT OR IGNORE INTO contacts VALUES (?,?)', (actual, encoded(public)))
        return {'trusted': actual, 'name': public['name']}

    def _contact(self, peer):
        row = self.db.execute('SELECT card FROM contacts WHERE fingerprint=?', (fingerprint(peer),)).fetchone()
        if row is None:
            raise ValueError('Sender or recipient is not an enrolled contact')
        return parsed(row[0], 4096)

    def _room(self, count=1):
        if self.db.execute('SELECT COUNT(*) FROM mail').fetchone()[0]+count > MAX_MESSAGES:
            raise ValueError('Mailbox capacity reached; archive with an explicit retention policy')

    def _queue(self, peer, payload, kind, reply_to, ttl, now, message_id=None):
        contact = self._contact(peer)
        message_id = message_id or str(uuid4())
        message = {'schema': 'agenticvm.offline-message.v1', 'id': message_id,
                   'sender': self.fingerprint, 'recipient': peer, 'created': now, 'expires': now+ttl,
                   'kind': kind, 'reply_to': reply_to, 'payload': b64(payload)}
        signed = self.sign.sign(DOMAIN+encoded(message))
        envelope = MAGIC+SealedBox(PublicKey(unb64(contact['box'], 32))).encrypt(bytes(signed))
        self.db.execute('INSERT INTO mail (id,direction,peer,kind,reply_to,envelope,digest,payload) VALUES (?,?,?,?,?,?,?,?)',
                        (message_id, 'out', peer, kind, reply_to, envelope, sha(envelope), payload))
        return {'id': message_id, 'sha256': sha(envelope), 'bytes': len(envelope), 'kind': kind}

    def send(self, peer, payload, *, kind='message', reply_to=None, ttl=86400, now=None, message_id=None):
        if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD:
            raise ValueError('Message payload exceeds 512 KiB')
        if kind not in ('message', 'task', 'result') or type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
            raise ValueError('Invalid message kind or expiry')
        if reply_to is not None:
            identifier(reply_to)
        if message_id is not None:
            identifier(message_id)
        now = int(time.time()) if now is None else now
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if message_id:
                prior = self.db.execute('SELECT * FROM mail WHERE id=?', (message_id,)).fetchone()
                if prior:
                    if prior['direction'] != 'out' or (prior['peer'], prior['payload'], prior['kind'], prior['reply_to']) != (peer, payload, kind, reply_to):
                        raise ValueError('Outgoing message ID was reused with changed contents')
                    # Retain the original ciphertext and expiry, including after restart.
                    return {'id': message_id, 'sha256': prior['digest'], 'bytes': len(prior['envelope']), 'kind': kind}
            self._room()
            return self._queue(peer, payload, kind, reply_to, ttl, now, message_id)

    def export(self, message_id):
        row = self.db.execute("SELECT envelope FROM mail WHERE id=? AND direction='out'", (identifier(message_id),)).fetchone()
        if row is None:
            raise ValueError('No outgoing envelope with this ID')
        return row[0]

    def receive(self, envelope, *, now=None):
        if not isinstance(envelope, bytes) or not len(MAGIC)+48+64 <= len(envelope) <= MAX_ENVELOPE or not envelope.startswith(MAGIC):
            raise ValueError('Invalid sealed envelope')
        now = int(time.time()) if now is None else now
        signed = SealedBox(self.box).decrypt(envelope[len(MAGIC):])
        # Untrusted fields are used only to select an enrolled verification key.
        # No payload is stored or exposed before its entire signature verifies.
        message = parsed(signed[64+len(DOMAIN):])
        if not isinstance(message, dict) or set(message) != MESSAGE_FIELDS:
            raise ValueError('Invalid message fields')
        contact = self._contact(message['sender'])
        verified = VerifyKey(unb64(contact['sign'], 32)).verify(signed)
        if verified != DOMAIN+encoded(message):
            raise ValueError('Wrong signature domain or noncanonical message')
        identifier(message['id'])
        if message['reply_to'] is not None:
            identifier(message['reply_to'])
        if message['schema'] != 'agenticvm.offline-message.v1' or message['recipient'] != self.fingerprint:
            raise ValueError('Message belongs to another protocol or recipient')
        if message['kind'] not in ('message', 'task', 'result', 'receipt'):
            raise ValueError('Unknown message kind')
        created, expires = message['created'], message['expires']
        if type(created) is not int or type(expires) is not int or not 1 <= expires-created <= MAX_TTL:
            raise ValueError('Invalid message lifetime')
        payload = unb64(message['payload'])
        if len(payload) > MAX_PAYLOAD:
            raise ValueError('Decrypted payload exceeds its limit')
        digest = sha(envelope)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            prior = self.db.execute('SELECT * FROM mail WHERE id=?', (message['id'],)).fetchone()
            if prior:
                if prior['direction'] != 'in' or prior['digest'] != digest:
                    raise ValueError('Message ID was reused with different contents')
                return {'id': message['id'], 'duplicate': True, 'receipt': prior['receipt'], 'kind': prior['kind']}
            if created > now+300 or expires <= now:
                raise ValueError('Message expired or sender clock is too far ahead')
            self._room(1 if message['kind'] == 'receipt' else 2)
            if message['kind'] == 'receipt':
                receipt = parsed(payload, 2048)
                if not isinstance(receipt, dict) or set(receipt) != {'message_id', 'envelope_sha256'} or message['reply_to'] != receipt['message_id']:
                    raise ValueError('Invalid receipt')
                original = self.db.execute("SELECT * FROM mail WHERE id=? AND direction='out'", (identifier(receipt['message_id']),)).fetchone()
                if original is None or original['peer'] != message['sender'] or original['digest'] != receipt['envelope_sha256']:
                    raise ValueError('Receipt does not acknowledge an envelope sent to this peer')
                self.db.execute('UPDATE mail SET acked=1 WHERE id=?', (original['id'],))
                receipt_id = None
            else:
                receipt_payload = encoded({'message_id': message['id'], 'envelope_sha256': digest})
                receipt_id = self._queue(message['sender'], receipt_payload, 'receipt', message['id'], 86400, now)['id']
            self.db.execute('INSERT INTO mail (id,direction,peer,kind,reply_to,envelope,digest,payload,receipt) VALUES (?,?,?,?,?,?,?,?,?)',
                            (message['id'], 'in', message['sender'], message['kind'], message['reply_to'], envelope, digest, payload, receipt_id))
            return {'id': message['id'], 'duplicate': False, 'receipt': receipt_id, 'kind': message['kind'], 'payload_sha256': sha(payload)}

    def status(self):
        rows = self.db.execute('SELECT id,direction,peer,kind,reply_to,digest,acked,receipt FROM mail ORDER BY rowid').fetchall()
        return {'identity': self.fingerprint, 'name': self.public['name'], 'mail': [dict(row) for row in rows]}

    def payload(self, message_id):
        row = self.db.execute("SELECT payload FROM mail WHERE id=? AND direction='in'", (identifier(message_id),)).fetchone()
        if row is None:
            raise ValueError('No incoming message with this ID')
        return row[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('init')
    create.add_argument('--name', required=True)
    commands.add_parser('status')
    commands.add_parser('contact')
    trust = commands.add_parser('trust')
    trust.add_argument('card', type=Path)
    trust.add_argument('--fingerprint', required=True)
    send = commands.add_parser('send')
    send.add_argument('--peer', required=True)
    send.add_argument('--input', type=Path, required=True)
    send.add_argument('--kind', choices=('message', 'task', 'result'), default='message')
    send.add_argument('--reply-to')
    send.add_argument('--ttl', type=int, default=86400)
    send.add_argument('--message-id', help='Persist a UUID before submission; retrying it returns the same envelope and original expiry')
    for name in ('export', 'read'):
        command = commands.add_parser(name)
        command.add_argument('id')
        command.add_argument('--output', type=Path, required=True)
    receive = commands.add_parser('receive')
    receive.add_argument('envelope', type=Path)
    args = parser.parse_args(argv)
    endpoint = None
    try:
        endpoint = Endpoint.create(args.home, args.name) if args.command == 'init' else Endpoint(args.home)
        if args.command in ('init', 'contact'):
            result = {'contact': endpoint.public, 'fingerprint': endpoint.fingerprint}
        elif args.command == 'status':
            result = endpoint.status()
        elif args.command == 'trust':
            result = endpoint.trust(parsed(read_limited(args.card, 4096)), args.fingerprint)
        elif args.command == 'send':
            result = endpoint.send(args.peer, read_limited(args.input, MAX_PAYLOAD), kind=args.kind, reply_to=args.reply_to, ttl=args.ttl, message_id=args.message_id)
        elif args.command in ('export', 'read'):
            content = endpoint.export(args.id) if args.command == 'export' else endpoint.payload(args.id)
            write_new(args.output, content, private=args.command == 'read')
            result = {'sha256': sha(content), 'bytes': len(content)}
        else:
            result = endpoint.receive(read_limited(args.envelope))
        print(json.dumps({'ok': True, 'result': result}))
        return 0
    except Exception as error:
        print(json.dumps({'ok': False, 'error': type(error).__name__, 'message': str(error)[:240]}))
        return 1
    finally:
        if endpoint:
            endpoint.close()


if __name__ == '__main__':
    raise SystemExit(main())
