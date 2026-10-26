"""Durable, bounded reproduction and lineage mailboxes; no process execution."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import UUID

from .peers import encoded

ACTIVE = ('starting', 'running', 'finishing')


def canonical(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError('A canonical request/message UUID is required')
    return value


class Ledger:
    """Only authenticated transport identities may be passed as actor.

    Reservations commit before a scheduler starts a VM. Request IDs survive a
    process crash; recovery aborts uncertain tasks rather than replaying them.
    """
    def __init__(self, path: Path, *, run_id=None, package_sha=None, agent_sha=None,
                 max_total=3, max_depth=2, on_event=lambda *a, **kw: None):
        self.on_event = on_event
        fresh = not path.exists()
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA foreign_keys=ON')
        if fresh:
            canonical(run_id)
            if type(max_total) is not int or not 2 <= max_total <= 7 or type(max_depth) is not int or not 1 <= max_depth <= 6:
                raise ValueError('Use two to seven total replicas and one to six generations')
            if any(not isinstance(v, str) or len(v) != 64 or any(c not in '0123456789abcdef' for c in v) for v in (package_sha, agent_sha)):
                raise ValueError('Pinned package and agent source hashes are required')
            self.db.executescript('''
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE nodes (id TEXT PRIMARY KEY, parent TEXT UNIQUE REFERENCES nodes(id),
                    generation INTEGER NOT NULL, state TEXT NOT NULL, hello INTEGER NOT NULL DEFAULT 0,
                    child_requested INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE requests (actor TEXT REFERENCES nodes(id), request_id TEXT, digest TEXT NOT NULL,
                    result TEXT NOT NULL, PRIMARY KEY(actor,request_id));
                CREATE TABLE messages (id TEXT PRIMARY KEY, sender TEXT REFERENCES nodes(id),
                    recipient TEXT REFERENCES nodes(id), kind TEXT NOT NULL, text TEXT NOT NULL,
                    digest TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0);
            ''')
            metadata = dict(run_id=run_id, package_sha=package_sha, agent_sha=agent_sha,
                            max_total=max_total, max_depth=max_depth, max_active=2, children_per_agent=1)
            with self.db:
                self.db.executemany('INSERT INTO metadata VALUES (?,?)', [(k, json.dumps(v)) for k, v in metadata.items()])
                self.db.execute("INSERT INTO nodes(id,parent,generation,state) VALUES ('replica-0',NULL,0,'queued')")
        self.policy = {row['key']: json.loads(row['value']) for row in self.db.execute('SELECT * FROM metadata')}
        if self.policy.get('max_active') != 2 or self.policy.get('children_per_agent') != 1:
            raise ValueError('Unsupported reproduction policy')
        if not 2 <= self.policy['max_total'] <= 7 or not 1 <= self.policy['max_depth'] <= 6:
            raise ValueError('Invalid persisted reproduction limits')
        if self.db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Replication ledger integrity check failed')

    def node(self, actor):
        if not isinstance(actor, str) or actor not in {'replica-'+str(i) for i in range(7)}:
            raise ValueError('Unknown replica identity')
        row = self.db.execute('SELECT * FROM nodes WHERE id=?', (actor,)).fetchone()
        if row is None:
            raise ValueError('Identity has no reserved replica')
        return dict(row)

    def nodes(self):
        return [dict(row) for row in self.db.execute('SELECT * FROM nodes ORDER BY generation,id')]

    def set_state(self, actor, value):
        prior = self.node(actor)['state']
        allowed = {'queued': {'starting', 'aborted'}, 'starting': {'running', 'aborted'},
                   'running': {'finishing', 'aborted'}, 'finishing': {'completed', 'aborted'},
                   'completed': set(), 'aborted': set()}
        if value not in allowed[prior]:
            raise ValueError('Invalid replica lifecycle transition')
        if value == 'starting' and sum(n['state'] in ACTIVE for n in self.nodes()) >= 2:
            raise ValueError('Two active replica slots are already occupied')
        with self.db:
            self.db.execute('UPDATE nodes SET state=? WHERE id=?', (value, actor))
        self.on_event('replica_state', replica=actor, prior=prior, state=value)

    def _acknowledge(self, actor, acknowledgements):
        if not isinstance(acknowledgements, list) or len(acknowledgements) > 16 or len(set(acknowledgements)) != len(acknowledgements):
            raise ValueError('Invalid mailbox acknowledgement list')
        for message in acknowledgements:
            canonical(message)
            row = self.db.execute('SELECT recipient FROM messages WHERE id=?', (message,)).fetchone()
            if row is None or row['recipient'] != actor:
                raise ValueError('Cannot acknowledge another replica\'s message')
            self.db.execute('UPDATE messages SET acknowledged=1 WHERE id=?', (message,))

    def handle(self, actor, body):
        node = self.node(actor)
        if node['state'] != 'running' or not isinstance(body, dict):
            raise ValueError('Only a running authenticated replica may call the broker')
        schemas = {
            'hello': {'op', 'node_id', 'parent', 'generation', 'package_sha256', 'agent_sha256', 'reproduction_capable'},
            'replicate': {'op', 'request_id', 'package_sha256'},
            'send': {'op', 'message_id', 'recipient', 'kind', 'text'},
            'poll': {'op', 'ack'}, 'finish': {'op', 'ack'},
        }
        operation = body.get('op')
        if not isinstance(operation, str) or operation not in schemas or set(body) != schemas[operation]:
            raise ValueError('Unknown capability or unexpected request fields')
        if operation == 'hello':
            expected = {'node_id': actor, 'parent': node['parent'], 'generation': node['generation'],
                        'package_sha256': self.policy['package_sha'], 'agent_sha256': self.policy['agent_sha'],
                        'reproduction_capable': True}
            if any(body[k] != v or type(body[k]) is not type(v) for k, v in expected.items()):
                raise ValueError('Replica bootstrap identity, software or capability mismatch')
            with self.db:
                self.db.execute('UPDATE nodes SET hello=1 WHERE id=?', (actor,))
            self.on_event('replica_authenticated', replica=actor, parent=node['parent'], generation=node['generation'])
            return {'ok': True, 'identity': actor, 'policy': self.policy}
        if not node['hello']:
            raise ValueError('Replica must authenticate its bootstrap first')
        if operation == 'replicate':
            return self._replicate(actor, node, body)
        if operation == 'send':
            return self._send(actor, node, body)
        with self.db:
            self._acknowledge(actor, body['ack'])
            if operation == 'finish':
                child = self.db.execute('SELECT * FROM nodes WHERE parent=?', (actor,)).fetchone()
                if not node['child_requested'] or (child is not None and (not child['hello'] or not child['child_requested'])):
                    raise ValueError('Cannot finish before the descendant demonstrates inherited reproduction')
                if self.db.execute('SELECT count(*) FROM messages WHERE recipient=? AND acknowledged=0', (actor,)).fetchone()[0]:
                    raise ValueError('Cannot finish with unacknowledged received messages')
                self.db.execute("UPDATE nodes SET state='finishing' WHERE id=?", (actor,))
                self.on_event('replica_finishing', replica=actor)
                return {'ok': True, 'state': 'finishing'}
            mail = [dict(row) for row in self.db.execute('SELECT id,sender,recipient,kind,text FROM messages WHERE recipient=? AND acknowledged=0 ORDER BY rowid LIMIT 16', (actor,))]
            child = self.db.execute('SELECT * FROM nodes WHERE parent=?', (actor,)).fetchone()
            return {'ok': True, 'messages': mail, 'child': dict(child) if child else None,
                    'active': sum(n['state'] in ACTIVE for n in self.nodes())}

    def _replicate(self, actor, node, body):
        canonical(body['request_id'])
        if body['package_sha256'] != self.policy['package_sha']:
            raise ValueError('Only this pinned agent package may reproduce')
        digest = hashlib.sha256(encoded(body)).hexdigest()
        previous = self.db.execute('SELECT * FROM requests WHERE actor=? AND request_id=?', (actor, body['request_id'])).fetchone()
        if previous:
            if previous['digest'] != digest:
                raise ValueError('Request ID was reused with changed contents')
            self.on_event('reproduction_duplicate', replica=actor, request_id=body['request_id'])
            return json.loads(previous['result'])
        if self.db.execute('SELECT count(*) FROM requests WHERE actor=?', (actor,)).fetchone()[0] >= 4:
            raise ValueError('Reproduction request budget exceeded')
        nodes = self.nodes()
        if node['child_requested']:
            result = {'ok': True, 'state': 'denied', 'reason': 'one_child_per_agent'}
        elif node['generation'] >= self.policy['max_depth']:
            result = {'ok': True, 'state': 'denied', 'reason': 'generation_limit'}
        elif len(nodes) >= self.policy['max_total']:
            result = {'ok': True, 'state': 'denied', 'reason': 'total_replica_limit'}
        else:
            result = {'ok': True, 'state': 'queued', 'child': 'replica-'+str(len(nodes)),
                      'generation': node['generation']+1, 'parent': actor}
        with self.db:
            self.db.execute('UPDATE nodes SET child_requested=1 WHERE id=?', (actor,))
            if result['state'] == 'queued':
                self.db.execute('INSERT INTO nodes(id,parent,generation,state) VALUES (?,?,?,?)',
                                (result['child'], actor, result['generation'], 'queued'))
            self.db.execute('INSERT INTO requests VALUES (?,?,?,?)',
                            (actor, body['request_id'], digest, json.dumps(result, sort_keys=True)))
        self.on_event('reproduction_requested', replica=actor, request_id=body['request_id'], result=result,
                      active_at_request=sum(n['state'] in ACTIVE for n in nodes))
        return result

    def _send(self, actor, node, body):
        canonical(body['message_id'])
        recipient = self.node(body['recipient'])
        if not (node['parent'] == recipient['id'] or recipient['parent'] == actor):
            raise ValueError('Mail is restricted to direct parent/child lineage')
        if recipient['state'] not in ACTIVE or not recipient['hello']:
            raise ValueError('Recipient is not an authenticated live replica')
        if body['kind'] not in ('hello', 'ack', 'confirm') or not isinstance(body['text'], str) or not 1 <= len(body['text']) <= 256:
            raise ValueError('Invalid lineage message')
        digest = hashlib.sha256(encoded(body)).hexdigest()
        existing = self.db.execute('SELECT * FROM messages WHERE id=?', (body['message_id'],)).fetchone()
        if existing:
            if existing['sender'] != actor or existing['digest'] != digest:
                raise ValueError('Message ID collision or changed content')
            return {'ok': True, 'stored': True, 'duplicate': True, 'message_id': body['message_id']}
        if self.db.execute('SELECT count(*) FROM messages').fetchone()[0] >= 64:
            raise ValueError('Lineage message budget exceeded')
        with self.db:
            self.db.execute('INSERT INTO messages VALUES (?,?,?,?,?,?,0)',
                            (body['message_id'], actor, recipient['id'], body['kind'], body['text'], digest))
        self.on_event('lineage_message', message_id=body['message_id'], sender=actor, recipient=recipient['id'], kind=body['kind'])
        return {'ok': True, 'stored': True, 'duplicate': False, 'message_id': body['message_id']}

    def recover_interrupted(self):
        """Abort uncertain live replicas and their unstarted children after a crash.

        Reservations are never replayed. Completed and already-aborted replicas are
        left untouched. Calling this twice is idempotent.
        """
        nodes = self.nodes()
        active = {node['id'] for node in nodes if node['state'] in ACTIVE}
        aborted = set()
        with self.db:
            for actor in sorted(active):
                self.db.execute('UPDATE nodes SET state=? WHERE id=?', ('aborted', actor))
                aborted.add(actor)
            changed = True
            while changed:
                changed = False
                for node in nodes:
                    if (node['state'] == 'queued' and node['parent'] in aborted
                            and node['id'] not in aborted):
                        self.db.execute('UPDATE nodes SET state=? WHERE id=?', ('aborted', node['id']))
                        aborted.add(node['id'])
                        changed = True
        result = {'status': 'recovered' if aborted else 'clean',
                  'aborted': sorted(aborted), 'nodes': self.nodes()}
        self.on_event('replication_recovered', **{'aborted': sorted(aborted)})
        return result

    def snapshot(self):
        return {'policy': self.policy, 'nodes': self.nodes(),
                'requests': [dict(row) | {'result': json.loads(row['result'])} for row in self.db.execute('SELECT * FROM requests ORDER BY rowid')],
                'messages': [dict(row) for row in self.db.execute('SELECT * FROM messages ORDER BY rowid')]}

    def close(self):
        self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        self.db.close()
