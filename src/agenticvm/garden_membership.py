"""Dynamic garden members and wire-channel allocation; no VM or network I/O."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from uuid import uuid4

from .garden_policy import GardenPolicy
from .garden_wire import MAX_MEMBERS

ID = re.compile(r'^m-[0-9a-f]{16}$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')
ROLES = ('mother', 'offshoot')
STATES = ('candidate', 'active', 'revoked')
MOTHER_ADDRESS = None


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def member_id():
    return 'm-' + uuid4().hex[:16]


@dataclass
class Member:
    id: str
    channel: int
    role: str
    generation: int
    state: str
    label: str | None
    address: str | None
    parent: str | None
    public_key_sha256: str | None
    created_utc: str
    updated_utc: str

    def to_dict(self):
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, value):
        fields = {'id', 'channel', 'role', 'generation', 'state', 'label', 'address',
                  'parent', 'public_key_sha256', 'created_utc', 'updated_utc'}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError('Invalid garden member fields')
        member = cls(**value)
        member.validate()
        return member

    def validate(self):
        if not isinstance(self.id, str) or not ID.fullmatch(self.id):
            raise ValueError('Invalid garden member ID')
        if type(self.channel) is not int or not 1 <= self.channel <= MAX_MEMBERS:
            raise ValueError('Invalid garden wire channel')
        if self.role not in ROLES or self.state not in STATES:
            raise ValueError('Invalid garden member role or state')
        if type(self.generation) is not int or not 0 <= self.generation <= 6:
            raise ValueError('Invalid garden generation')
        if self.label is not None and (not isinstance(self.label, str) or not 1 <= len(self.label) <= 32):
            raise ValueError('Member label must be 1-32 characters')
        if self.address is not None:
            try:
                import ipaddress
                ipaddress.IPv4Address(self.address)
            except (ValueError, ipaddress.AddressValueError) as error:
                raise ValueError('Invalid member IPv4 address') from error
        if self.parent is not None and not ID.fullmatch(self.parent):
            raise ValueError('Invalid parent member ID')
        if self.public_key_sha256 is not None and not SHA256.fullmatch(self.public_key_sha256):
            raise ValueError('Invalid member public-key SHA-256')
        for field in (self.created_utc, self.updated_utc):
            try:
                datetime.fromisoformat(field)
            except ValueError as error:
                raise ValueError('Invalid member timestamp') from error


class Membership:
    """One mother, at most seven descendants, stable channel per member."""

    def __init__(self, policy: GardenPolicy, members=()):
        self.policy = policy
        values = [Member.from_dict(member) if isinstance(member, dict) else member for member in members]
        if len({member.id for member in values}) != len(values):
            raise ValueError('Garden member IDs collide')
        self.members = {member.id: member for member in values}
        self.validate()

    @classmethod
    def create(cls, policy: GardenPolicy):
        now = utc()
        mother = Member(member_id(), 1, 'mother', 0, 'active', 'mother', MOTHER_ADDRESS,
                        None, None, now, now)
        return cls(policy, (mother,))

    def validate(self):
        if not self.members:
            raise ValueError('A garden requires a mother member')
        if len({member.id for member in self.members.values()}) != len(self.members):
            raise ValueError('Garden member IDs collide')
        mothers = [member for member in self.members.values() if member.role == 'mother']
        if len(mothers) != 1 or mothers[0].generation != 0:
            raise ValueError('A garden requires exactly one generation-zero mother')
        if len(self.members) > min(MAX_MEMBERS, self.policy.max_total):
            raise ValueError('Garden exceeds its member limit')
        channels = [member.channel for member in self.members.values()]
        if len(set(channels)) != len(channels):
            raise ValueError('Garden wire channels collide')
        addresses = [member.address for member in self.members.values() if member.address]
        if len(set(addresses)) != len(addresses):
            raise ValueError('Garden member addresses collide')
        for member in self.members.values():
            if member.role == 'mother' and member.parent is not None:
                raise ValueError('Mother cannot have a parent')
            if member.role == 'offshoot':
                if member.generation < 1 or member.generation > self.policy.max_depth:
                    raise ValueError('Offshoot generation is outside policy')
                if member.parent is not None:
                    parent = self.members.get(member.parent)
                    if parent is None or parent.generation + 1 != member.generation:
                        raise ValueError('Offshoot parent/generation mismatch')
            if member.address and not self.policy.within(member.address):
                raise ValueError('Member address is outside policy scope')

    def get(self, identifier):
        if not isinstance(identifier, str) or identifier not in self.members:
            raise ValueError('Unknown garden member')
        return self.members[identifier]

    def add(self, *, role='offshoot', generation=1, address=None, parent=None,
            public_key_sha256=None, label=None):
        if role not in ROLES:
            raise ValueError('Unknown member role')
        if len(self.members) >= min(MAX_MEMBERS, self.policy.max_total):
            raise ValueError('Garden member limit reached')
        if role == 'mother':
            if any(member.role == 'mother' for member in self.members.values()):
                raise ValueError('Garden already has a mother')
            generation, parent = 0, None
        else:
            if type(generation) is not int:
                raise ValueError('Generation must be an integer')
            if parent is not None:
                parent_member = self.get(parent)
                if parent_member.generation + 1 != generation:
                    raise ValueError('Parent/generation mismatch')
            if generation > self.policy.max_depth:
                raise ValueError('Generation exceeds policy depth')
        if address is not None and not self.policy.within(address):
            raise ValueError('Address is outside policy scope')
        if address and any(member.address == address for member in self.members.values()):
            raise ValueError('Address already belongs to a member')
        if public_key_sha256 is not None and not SHA256.fullmatch(public_key_sha256):
            raise ValueError('Invalid public-key SHA-256')
        used = {member.channel for member in self.members.values()}
        channel = next((value for value in range(1, MAX_MEMBERS + 1) if value not in used), None)
        if channel is None:
            raise ValueError('No garden wire channel is free')
        now = utc()
        member = Member(member_id(), channel, role, generation, 'candidate',
                        label, address, parent, public_key_sha256, now, now)
        member.validate()
        self.members[member.id] = member
        self.validate()
        return member

    def transition(self, identifier, value):
        member = self.get(identifier)
        allowed = {'candidate': {'active', 'revoked'}, 'active': {'revoked'}, 'revoked': set()}
        if member.role == 'mother' and value == 'revoked':
            raise ValueError('Revoke the mother by replacement, not in place')
        if value not in allowed[member.state]:
            raise ValueError('Invalid member state transition')
        member.state = value
        member.updated_utc = utc()
        self.validate()
        return member

    def wire_map(self):
        return WireMap({member.id: member.channel for member in self.members.values()})

    def status(self):
        return {'mother': next(member.id for member in self.members.values() if member.role == 'mother'),
                'count': len(self.members), 'active': sum(member.state == 'active' for member in self.members.values()),
                'max_total': self.policy.max_total, 'members': [member.to_dict() for member in self.members.values()]}


class WireMap:
    """Stable member-ID to integer framing channel map."""

    def __init__(self, values):
        if not isinstance(values, dict) or not values:
            raise ValueError('A non-empty wire map is required')
        channels = list(values.values())
        if len(set(channels)) != len(channels) or any(type(c) is not int or not 1 <= c <= MAX_MEMBERS for c in channels):
            raise ValueError('Invalid wire channel map')
        self.by_member = dict(values)
        self.by_channel = {channel: member for member, channel in values.items()}

    def channel(self, member):
        if member not in self.by_member:
            raise ValueError('Member has no wire channel')
        return self.by_member[member]

    def member(self, channel):
        if channel not in self.by_channel:
            raise ValueError('Channel has no member')
        return self.by_channel[channel]

    def digest(self):
        import json
        return hashlib.sha256(json.dumps(self.by_member, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
