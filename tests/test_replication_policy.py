"""Reproduction authorization, finite capacity, durable reservations and mail."""
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from agenticvm.replication_policy import Ledger


class ReproductionPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'ledger.sqlite'
        self.events = []
        self.ledger = Ledger(self.path, run_id=str(uuid4()), package_sha='a'*64, agent_sha='b'*64,
                             on_event=lambda event, **fields: self.events.append((event, fields)))
        self.addCleanup(lambda: self.ledger.close() if self.ledger else None)

    def hello(self, actor):
        node = self.ledger.node(actor)
        return {'op': 'hello', 'node_id': actor, 'parent': node['parent'], 'generation': node['generation'],
                'package_sha256': 'a'*64, 'agent_sha256': 'b'*64, 'reproduction_capable': True}

    def activate(self, actor):
        self.ledger.set_state(actor, 'starting')
        self.ledger.set_state(actor, 'running')
        self.ledger.handle(actor, self.hello(actor))

    def request(self):
        return {'op': 'replicate', 'request_id': str(uuid4()), 'package_sha256': 'a'*64}

    def create_child(self, actor):
        return self.ledger.handle(actor, self.request())['child']

    def message(self, to, kind='hello'):
        return {'op': 'send', 'message_id': str(uuid4()), 'recipient': to, 'kind': kind, 'text': 'hello'}

    def test_only_seed_is_reserved_without_an_agent_request(self):
        self.assertEqual([n['id'] for n in self.ledger.nodes()], ['replica-0'])
        self.assertIsNone(self.ledger.nodes()[0]['parent'])

    def test_running_unintroduced_agent_cannot_reproduce(self):
        self.ledger.set_state('replica-0', 'starting')
        self.ledger.set_state('replica-0', 'running')
        with self.assertRaises(ValueError):
            self.ledger.handle('replica-0', self.request())

    def test_bootstrap_cannot_forge_identity_software_or_ancestry(self):
        self.ledger.set_state('replica-0', 'starting')
        self.ledger.set_state('replica-0', 'running')
        for key, value in [('node_id', 'replica-1'), ('generation', True), ('parent', 'replica-1'),
                           ('package_sha256', 'c'*64), ('agent_sha256', 'c'*64), ('reproduction_capable', False)]:
            body = self.hello('replica-0')
            body[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.ledger.handle('replica-0', body)
        self.assertEqual(len(self.ledger.nodes()), 1)

    def test_unknown_actors_and_host_paths_are_rejected(self):
        self.activate('replica-0')
        for actor in ('replica-1', '../outside', 'host', 'replica-9'):
            with self.subTest(actor=actor), self.assertRaises(ValueError):
                self.ledger.handle(actor, self.request())
        request = self.request() | {'workspace': 'C:/outside'}
        with self.assertRaises(ValueError):
            self.ledger.handle('replica-0', request)

    def test_same_request_reserves_only_one_child_even_after_reopening(self):
        self.activate('replica-0')
        request = self.request()
        first = self.ledger.handle('replica-0', request)
        self.ledger.close()
        self.ledger = Ledger(self.path)
        self.assertEqual(self.ledger.handle('replica-0', request), first)
        self.assertEqual(len(self.ledger.nodes()), 2)

    def test_changed_package_cannot_use_an_existing_request_id(self):
        self.activate('replica-0')
        request = self.request()
        self.ledger.handle('replica-0', request)
        with self.assertRaises(ValueError):
            self.ledger.handle('replica-0', request | {'package_sha256': 'd'*64})
        self.assertEqual(len(self.ledger.nodes()), 2)

    def test_each_child_inherits_reproduction_and_third_waits_at_capacity(self):
        self.activate('replica-0')
        self.assertEqual(self.create_child('replica-0'), 'replica-1')
        self.activate('replica-1')
        self.assertEqual(self.create_child('replica-1'), 'replica-2')
        self.assertEqual(self.ledger.node('replica-2')['state'], 'queued')
        with self.assertRaises(ValueError):
            self.ledger.set_state('replica-2', 'starting')
        self.ledger.handle('replica-0', {'op': 'finish', 'ack': []})
        self.ledger.set_state('replica-0', 'completed')
        self.activate('replica-2')
        denied = self.ledger.handle('replica-2', self.request())
        self.assertEqual(denied['reason'], 'generation_limit')
        self.assertEqual(len(self.ledger.nodes()), 3)

    def test_one_child_per_agent_applies_to_new_request_ids(self):
        self.activate('replica-0')
        self.create_child('replica-0')
        denied = self.ledger.handle('replica-0', self.request())
        self.assertEqual(denied['reason'], 'one_child_per_agent')
        self.assertEqual(len(self.ledger.nodes()), 2)

    def test_total_limit_is_separate_from_generation_limit(self):
        self.ledger.db.execute('UPDATE metadata SET value=? WHERE key=?', (json.dumps(6), 'max_depth'))
        self.ledger.db.commit()
        self.ledger.policy['max_depth'] = 6
        self.activate('replica-0')
        self.create_child('replica-0')
        self.activate('replica-1')
        self.create_child('replica-1')
        self.ledger.handle('replica-0', {'op': 'finish', 'ack': []})
        self.ledger.set_state('replica-0', 'completed')
        self.activate('replica-2')
        self.assertEqual(self.ledger.handle('replica-2', self.request())['reason'], 'total_replica_limit')

    def test_lineage_mail_is_retained_until_acknowledged_and_deduplicated(self):
        self.activate('replica-0')
        self.create_child('replica-0')
        self.activate('replica-1')
        body = self.message('replica-0')
        self.ledger.handle('replica-1', body)
        self.assertTrue(self.ledger.handle('replica-1', body)['duplicate'])
        first = self.ledger.handle('replica-0', {'op': 'poll', 'ack': []})
        second = self.ledger.handle('replica-0', {'op': 'poll', 'ack': []})
        self.assertEqual(first['messages'], second['messages'])
        self.assertEqual(first['messages'][0]['sender'], 'replica-1')
        final = self.ledger.handle('replica-0', {'op': 'poll', 'ack': [body['message_id']]})
        self.assertFalse(final['messages'])

    def test_child_cannot_acknowledge_parent_owned_mail(self):
        self.activate('replica-0')
        self.create_child('replica-0')
        self.activate('replica-1')
        body = self.message('replica-0')
        self.ledger.handle('replica-1', body)
        with self.assertRaises(ValueError):
            self.ledger.handle('replica-1', {'op': 'poll', 'ack': [body['message_id']]})

    def test_grandparent_and_unrelated_messages_are_denied(self):
        self.activate('replica-0')
        self.create_child('replica-0')
        self.activate('replica-1')
        self.create_child('replica-1')
        self.ledger.handle('replica-0', {'op': 'finish', 'ack': []})
        self.ledger.set_state('replica-0', 'completed')
        self.activate('replica-2')
        with self.assertRaises(ValueError):
            self.ledger.handle('replica-2', self.message('replica-0'))

    def test_message_uuid_cannot_be_reused_with_changed_text(self):
        self.activate('replica-0')
        self.create_child('replica-0')
        self.activate('replica-1')
        body = self.message('replica-0')
        self.ledger.handle('replica-1', body)
        with self.assertRaises(ValueError):
            self.ledger.handle('replica-1', body | {'text': 'changed'})

    def test_finish_waits_for_inherited_reproduction_request(self):
        self.activate('replica-0')
        self.create_child('replica-0')
        self.activate('replica-1')
        with self.assertRaises(ValueError):
            self.ledger.handle('replica-0', {'op': 'finish', 'ack': []})
        self.create_child('replica-1')
        self.assertTrue(self.ledger.handle('replica-0', {'op': 'finish', 'ack': []})['ok'])

    def test_unknown_capability_and_unbounded_creation_parameters_are_denied(self):
        self.activate('replica-0')
        for body in ({'op': 'exec', 'argv': ['powershell']}, self.request() | {'count': 500},
                     self.request() | {'package_url': 'https://example.invalid/agent'}, {'op': 'poll', 'ack': [], 'sender': 'replica-1'}):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.ledger.handle('replica-0', body)
        self.assertEqual(len(self.ledger.nodes()), 1)

    def test_aborted_reservations_never_restart(self):
        self.activate('replica-0')
        self.create_child('replica-0')
        self.ledger.set_state('replica-1', 'aborted')
        with self.assertRaises(ValueError):
            self.ledger.set_state('replica-1', 'starting')


if __name__ == '__main__':
    unittest.main()
