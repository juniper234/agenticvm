"""Durable host-side garden state and hash-chained receipts; no VM execution."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
from uuid import uuid4

from .garden_membership import Member, Membership
from .garden_policy import GardenPolicy

SCHEMA = 'agenticvm.garden-state.v1'
MAX_STATE = 65536
MAX_RECEIPTS = 512


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Garden state contains a duplicate JSON key')
        value[key] = item
    return value


class GardenState:
    def __init__(self, revision, policy, membership, created_utc):
        self.revision = revision
        self.policy = policy
        self.membership = membership
        self.created_utc = created_utc

    @classmethod
    def create(cls, policy):
        return cls(1, policy, Membership.create(policy), utc())

    @classmethod
    def from_dict(cls, value):
        fields = {'schema', 'revision', 'policy', 'members', 'created_utc'}
        if not isinstance(value, dict) or set(value) != fields or value.get('schema') != SCHEMA:
            raise ValueError('Invalid garden state schema or fields')
        if type(value['revision']) is not int or value['revision'] < 1:
            raise ValueError('Invalid garden state revision')
        if not isinstance(value['members'], list):
            raise ValueError('Garden members must be an array')
        policy = GardenPolicy.from_dict(value['policy'])
        membership = Membership(policy, [Member.from_dict(item) for item in value['members']])
        try:
            datetime.fromisoformat(value['created_utc'])
        except ValueError as error:
            raise ValueError('Invalid garden creation timestamp') from error
        return cls(value['revision'], policy, membership, value['created_utc'])

    def to_dict(self):
        return {'schema': SCHEMA, 'revision': self.revision, 'policy': self.policy.to_dict(),
                'members': [member.to_dict() for member in self.membership.members.values()],
                'created_utc': self.created_utc}

    def status(self):
        return {'schema': SCHEMA, 'revision': self.revision,
                'policy': self.policy.to_dict(), 'policy_sha256': self.policy.digest(),
                'wire_map_sha256': self.membership.wire_map().digest(),
                'garden': self.membership.status(), 'created_utc': self.created_utc}


class GardenStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.state_path = self.root / 'garden.json'
        self.receipts_path = self.root / 'receipts.jsonl'
        self.secret_path = self.root / 'ping.key'

    def exists(self):
        return self.state_path.is_file()

    def init(self, policy, *, force=False):
        if self.exists() and not force:
            raise ValueError('Garden already exists')
        self.root.mkdir(parents=True, exist_ok=True)
        self.secret_path.write_text(secrets.token_hex(32) + '\n', encoding='ascii')
        state = GardenState.create(policy)
        self.save(state)
        self.receipt('garden_initialized', name=policy.name, scope=list(policy.scope),
                     policy_sha256=policy.digest())
        return state

    def ping_key(self):
        if not self.secret_path.is_file():
            self.root.mkdir(parents=True, exist_ok=True)
            self.secret_path.write_text(secrets.token_hex(32) + '\n', encoding='ascii')
        value = self.secret_path.read_text(encoding='ascii').strip()
        if len(value) != 64 or any(char not in '0123456789abcdef' for char in value):
            raise ValueError('Garden ping key is malformed')
        return bytes.fromhex(value)

    def load(self):
        if not self.exists():
            raise ValueError('No garden exists at ' + str(self.root))
        raw = self.state_path.read_bytes()
        if len(raw) > MAX_STATE:
            raise ValueError('Garden state exceeds its size limit')
        try:
            value = json.loads(raw, object_pairs_hook=_no_duplicates)
        except json.JSONDecodeError as error:
            raise ValueError('Garden state is not valid JSON') from error
        return GardenState.from_dict(value)

    def save(self, state):
        self.root.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(state.to_dict(), indent=2, sort_keys=True, ensure_ascii=True) + '\n'
        temporary = self.state_path.with_name('.garden-' + uuid4().hex + '.tmp')
        with temporary.open('w', encoding='ascii', newline='\n') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.state_path)

    def receipt(self, event, **fields):
        if not isinstance(event, str) or not event:
            raise ValueError('Receipt event is required')
        previous = '0' * 64
        if self.receipts_path.exists():
            raw = self.receipts_path.read_bytes()
            lines = raw.splitlines()
            if len(lines) > MAX_RECEIPTS:
                lines = lines[-MAX_RECEIPTS:]
                self.receipts_path.write_bytes(b'\n'.join(lines) + b'\n')
            if lines:
                previous = json.loads(lines[-1])['digest']
        body = {'seq': self._next_seq(), 'at': utc(), 'event': event,
                'fields': fields, 'previous': previous}
        body['digest'] = hashlib.sha256(canonical(body)).hexdigest()
        with self.receipts_path.open('a', encoding='ascii', newline='\n') as stream:
            stream.write(json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        return body

    def receipts(self, limit=20):
        if not self.receipts_path.exists():
            return []
        lines = self.receipts_path.read_text(encoding='ascii').splitlines()[-limit:]
        return [json.loads(line) for line in lines]

    def _next_seq(self):
        if not self.receipts_path.exists():
            return 1
        lines = self.receipts_path.read_text(encoding='ascii').splitlines()
        return json.loads(lines[-1])['seq'] + 1 if lines else 1
