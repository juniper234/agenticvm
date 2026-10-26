"""Bounded, read-only discovery over an explicit IPv4 scope; no authorization."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import socket
import time

SCHEMA = 'agenticvm.garden-search.v1'
MAX_HOSTS = 256
MAX_PORTS = 8
DEFAULT_PORTS = (22, 7443)


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


@dataclass(frozen=True)
class SearchRequest:
    scope: str
    ports: tuple[int, ...] = DEFAULT_PORTS
    max_hosts: int = MAX_HOSTS
    timeout_ms: int = 300

    def __post_init__(self):
        try:
            network = ipaddress.IPv4Network(self.scope, strict=False)
        except (ValueError, ipaddress.AddressValueError) as error:
            raise ValueError('Search scope must be an IPv4 CIDR') from error
        if network.num_addresses > self.max_hosts:
            raise ValueError('Scope exceeds the host budget; narrow the CIDR or raise --max-hosts')
        if not 1 <= len(self.ports) <= MAX_PORTS:
            raise ValueError('Use one to eight TCP ports')
        if len(set(self.ports)) != len(self.ports) or any(type(port) is not int or not 1 <= port <= 65535 for port in self.ports):
            raise ValueError('Ports must be unique integers 1-65535')
        if type(self.max_hosts) is not int or not 1 <= self.max_hosts <= MAX_HOSTS:
            raise ValueError('Host budget must be 1-256')
        if type(self.timeout_ms) is not int or not 50 <= self.timeout_ms <= 5000:
            raise ValueError('Probe timeout must be 50-5000 ms')

    @property
    def network(self):
        return ipaddress.IPv4Network(self.scope, strict=False)

    def targets(self):
        return sorted((str(address) for address in self.network.hosts()), key=ipaddress.IPv4Address)


def probe_tcp(address, port, timeout):
    started = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=timeout) as stream:
            latency = round((time.monotonic() - started) * 1000, 1)
            banner = b''
            try:
                stream.settimeout(min(0.15, timeout))
                banner = stream.recv(128)
            except (OSError, TimeoutError):
                pass
            return {'method': 'tcp', 'port': port, 'reachable': True,
                    'latency_ms': latency,
                    'banner_sha256': hashlib.sha256(banner).hexdigest() if banner else None,
                    'banner_bytes': len(banner)}
    except (OSError, TimeoutError) as error:
        return {'method': 'tcp', 'port': port, 'reachable': False,
                'latency_ms': round((time.monotonic() - started) * 1000, 1),
                'error': type(error).__name__}


def search(request: SearchRequest, *, inventory=(), passive=(), connect=probe_tcp, concurrency=16):
    if not 1 <= concurrency <= 32:
        raise ValueError('Concurrency must be 1-32')
    started, start_clock = utc(), time.monotonic()
    targets = request.targets()
    allowed = set(targets)
    candidates = {}

    def candidate(address):
        return candidates.setdefault(address, {'address': address, 'state': 'silent', 'observations': []})

    for address in inventory:
        if address in allowed:
            item = candidate(address)
            item['state'] = 'inventory'
            item['observations'].append({'method': 'inventory'})
    for observation in passive:
        address = observation.get('address') if isinstance(observation, dict) else None
        if address in allowed:
            item = candidate(address)
            if item['state'] == 'silent':
                item['state'] = 'observed'
            item['observations'].append({'method': 'passive',
                                         'source': observation.get('source', 'unknown')})

    work = [(address, port) for address in targets for port in request.ports]
    with ThreadPoolExecutor(max_workers=min(concurrency, max(1, len(work)))) as pool:
        futures = {pool.submit(connect, address, port, request.timeout_ms / 1000): (address, port)
                   for address, port in work}
        for future in as_completed(futures):
            address, port = futures[future]
            try:
                result = future.result()
            except Exception as error:  # adapter-specific probe failure
                result = {'method': 'tcp', 'port': port, 'reachable': False,
                          'error': type(error).__name__}
            item = candidate(address)
            item['observations'].append(result)
            if result.get('reachable') and item['state'] not in {'inventory'}:
                item['state'] = 'responsive'
            elif result.get('reachable') and item['state'] == 'inventory':
                item['state'] = 'inventory_responsive'

    ordered = [candidates[address] for address in sorted(candidates, key=ipaddress.IPv4Address)]
    return {'schema': SCHEMA, 'scope': str(request.network), 'started_utc': started,
            'elapsed_ms': round((time.monotonic() - start_clock) * 1000, 1),
            'methods': ['inventory', 'passive', 'tcp'], 'ports': list(request.ports),
            'targets': len(targets), 'candidates': ordered,
            'responsive': sum(item['state'] in {'responsive', 'inventory_responsive'} for item in ordered),
            'truncated': False}
