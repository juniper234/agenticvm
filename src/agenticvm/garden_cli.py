"""JSON `garden` command surface; R0 is state-only and launches no VM."""
from __future__ import annotations

from pathlib import Path
import ipaddress
import time

from .errors import AgenticVMError
from .garden_ping import PingServer, ping
from .garden_policy import GardenPolicy
from .garden_search import SearchRequest, search
from .garden_store import GardenStore


def _store(args):
    root = args.garden_dir or (Path(args.workspace) / 'garden')
    return GardenStore(Path(root))


def _save(store, state):
    state.revision += 1
    state.membership.validate()
    store.save(state)


def execute(args):
    try:
        return _execute(args)
    except ValueError as error:
        raise AgenticVMError(str(error), 'garden_invalid') from error


def _execute(args):
    store = _store(args)
    command = args.garden_command
    if command == 'init':
        if store.exists() and not args.force:
            raise ValueError('Garden already exists; use --force to replace state')
        scope = args.scope or ['10.66.0.0/24']
        methods = args.methods or ['inventory', 'icmp', 'tcp', 'ssh']
        policy = GardenPolicy.create(args.name, scope, methods, args.max_total,
                                     args.max_depth, args.max_active)
        state = store.init(policy, force=args.force)
        return {'created': True, 'status': state.status()}

    state = store.load()
    if command == 'status':
        return state.status()

    if command == 'member':
        action = args.member_command
        if action == 'list':
            return state.membership.status()
        if action == 'add':
            member = state.membership.add(role=args.role, generation=args.generation,
                                          address=args.address, parent=args.parent,
                                          public_key_sha256=args.public_key_sha256,
                                          label=args.label)
            _save(store, state)
            store.receipt('member_added', member=member.to_dict())
            return {'member': member.to_dict(), 'revision': state.revision}
        member = state.membership.transition(args.member_id, {'activate': 'active', 'revoke': 'revoked'}[action])
        _save(store, state)
        store.receipt('member_' + member.state, member=member.id)
        return {'member': member.to_dict(), 'revision': state.revision}

    if command == 'policy':
        action = args.policy_command
        if action == 'show':
            return {'policy': state.policy.to_dict(), 'sha256': state.policy.digest()}
        changes = {}
        if args.scope is not None:
            changes['scope'] = tuple(args.scope)
        if args.methods is not None:
            changes['methods'] = tuple(args.methods)
        for name in ('max_total', 'max_depth', 'max_active'):
            value = getattr(args, name)
            if value is not None:
                changes[name] = value
        if not changes:
            raise ValueError('No policy changes supplied')
        policy = state.policy.with_changes(**changes)
        state.policy = policy
        state.membership.policy = policy
        _save(store, state)
        store.receipt('policy_changed', policy_sha256=policy.digest(), changes=changes)
        return {'policy': policy.to_dict(), 'sha256': policy.digest(), 'revision': state.revision}

    if command == 'receipts':
        limit = max(1, min(args.limit, 100))
        return {'receipts': store.receipts(limit)}

    if command == 'search':
        scope = args.scope or (state.policy.scope[0] if len(state.policy.scope) == 1
                               else None)
        if scope is None:
            raise ValueError('Supply --scope; the garden has more than one scope')
        network = ipaddress.IPv4Network(scope, strict=False)
        if not any(network.subnet_of(policy_net) for policy_net in state.policy.networks):
            raise ValueError('Search scope is outside the garden policy')
        request = SearchRequest(str(network), tuple(args.port or (22, 7443)),
                                args.max_hosts, args.timeout_ms)
        result = search(request, inventory=[member.address for member in state.membership.members.values()
                                            if member.address])
        store.receipt('garden_search', scope=result['scope'], targets=result['targets'],
                      responsive=result['responsive'], elapsed_ms=result['elapsed_ms'])
        return result

    if command == 'ping':
        member = state.membership.get(args.member or state.membership.status()['mother'])
        key = store.ping_key()
        garden_id = state.policy.digest()
        if args.listen:
            server = PingServer(key, garden_id, member.id, host=args.host, port=args.port)
            server.start()
            started = time.monotonic()
            try:
                while args.duration == 0 or time.monotonic() - started < args.duration:
                    time.sleep(0.1)
            finally:
                server.stop()
            store.receipt('garden_ping_listen', member=member.id, events=len(server.events))
            return {'schema': 'agenticvm.garden-ping-listen.v1', 'address': server.address,
                    'member': member.id, 'events': server.events}
        if not args.address:
            raise ValueError('Supply an address or use --listen')
        result = ping(args.address, args.port, key, garden_id, member.id,
                      timeout=max(0.05, args.timeout_ms / 1000))
        store.receipt('garden_ping', address=args.address, port=args.port,
                      member=member.id, garden_member=result['garden_member'],
                      reachable=result['reachable'])
        return result
    raise ValueError('Unknown garden command')
