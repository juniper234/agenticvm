"""Signed-scope-ready garden policy for the red-team lab; parsing is host-only."""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re

SCHEMA = 'agenticvm.garden-policy.v1'
NAME = re.compile(r'^[a-z0-9][a-z0-9-]{0,31}$')
METHODS = ('inventory', 'icmp', 'tcp', 'ssh', 'agent')


def _utc():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


@dataclass(frozen=True)
class GardenPolicy:
    name: str
    scope: tuple[str, ...]
    methods: tuple[str, ...] = ('inventory', 'icmp', 'tcp', 'ssh')
    max_total: int = 8
    max_depth: int = 3
    max_active: int = 2
    children_per_agent: int = 1
    created_utc: str = ''

    def __post_init__(self):
        if not isinstance(self.name, str) or not NAME.fullmatch(self.name):
            raise ValueError('Garden name must be 1-32 lowercase letters, digits or hyphens')
        if not 1 <= len(self.scope) <= 8:
            raise ValueError('Use one to eight IPv4 scopes')
        networks = []
        for value in self.scope:
            if not isinstance(value, str) or '/' not in value:
                raise ValueError('Every scope must be an IPv4 CIDR')
            try:
                network = ipaddress.IPv4Network(value, strict=False)
            except (ValueError, ipaddress.AddressValueError) as error:
                raise ValueError('Invalid IPv4 scope: ' + value) from error
            if any(network.overlaps(other) for other in networks):
                raise ValueError('Garden scopes must not overlap')
            networks.append(network)
        if not 1 <= len(self.methods) <= len(METHODS) or any(method not in METHODS for method in self.methods):
            raise ValueError('Unknown discovery method')
        if tuple(dict.fromkeys(self.methods)) != self.methods:
            raise ValueError('Duplicate discovery method')
        if type(self.max_total) is not int or not 2 <= self.max_total <= 8:
            raise ValueError('max_total must be between 2 and 8')
        if type(self.max_depth) is not int or not 1 <= self.max_depth <= 6:
            raise ValueError('max_depth must be between 1 and 6')
        if type(self.max_active) is not int or not 1 <= self.max_active <= self.max_total - 1:
            raise ValueError('max_active must be between 1 and max_total - 1')
        if type(self.children_per_agent) is not int or self.children_per_agent != 1:
            raise ValueError('R0 supports exactly one child per agent')
        if self.created_utc:
            try:
                datetime.fromisoformat(self.created_utc)
            except ValueError as error:
                raise ValueError('created_utc is not an ISO timestamp') from error

    @property
    def networks(self):
        return tuple(ipaddress.IPv4Network(value, strict=False) for value in self.scope)

    @classmethod
    def create(cls, name, scope, methods=('inventory', 'icmp', 'tcp', 'ssh'),
               max_total=8, max_depth=3, max_active=2):
        return cls(name, tuple(scope), tuple(methods), max_total, max_depth,
                   max_active, 1, _utc())

    def within(self, address):
        try:
            parsed = ipaddress.IPv4Address(address)
        except (ValueError, ipaddress.AddressValueError):
            return False
        return any(parsed in network for network in self.networks)

    def to_dict(self):
        return {
            'schema': SCHEMA, 'name': self.name, 'scope': list(self.scope),
            'methods': list(self.methods), 'max_total': self.max_total,
            'max_depth': self.max_depth, 'max_active': self.max_active,
            'children_per_agent': self.children_per_agent,
            'created_utc': self.created_utc or _utc(),
        }

    @classmethod
    def from_dict(cls, value):
        expected = {'schema', 'name', 'scope', 'methods', 'max_total', 'max_depth',
                    'max_active', 'children_per_agent', 'created_utc'}
        if not isinstance(value, dict) or set(value) != expected or value.get('schema') != SCHEMA:
            raise ValueError('Invalid garden policy schema or fields')
        if not isinstance(value['scope'], list) or not isinstance(value['methods'], list):
            raise ValueError('Policy scope and methods must be arrays')
        return cls(value['name'], tuple(value['scope']), tuple(value['methods']),
                   value['max_total'], value['max_depth'], value['max_active'],
                   value['children_per_agent'], value['created_utc'])

    def with_changes(self, **changes):
        return replace(self, **changes)

    def digest(self):
        return hashlib.sha256(canonical(self.to_dict())).hexdigest()
