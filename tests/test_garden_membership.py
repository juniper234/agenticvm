"""Dynamic membership, policy boundaries and wire-member mapping; host only."""
import json
from pathlib import Path
import tempfile
import unittest

from agenticvm.garden_membership import Membership, WireMap
from agenticvm.garden_policy import GardenPolicy
from agenticvm.garden_store import GardenStore
from agenticvm.garden_wire import MEMBERS, Decoder, packet


class GardenPolicyTests(unittest.TestCase):
    def policy(self, **changes):
        values = dict(name='lab', scope=['10.66.0.0/24'], max_total=8, max_depth=3, max_active=2)
        values.update(changes)
        return GardenPolicy.create(**values)

    def test_scope_and_digest_are_stable(self):
        policy = self.policy()
        self.assertTrue(policy.within('10.66.0.77'))
        self.assertFalse(policy.within('192.168.1.1'))
        self.assertFalse(policy.within('not-an-ip'))
        self.assertEqual(policy.digest(), self.policy().digest())

    def test_policy_bounds_and_overlap(self):
        for changes in ({'scope': ['10.66.0.0/24', '10.66.0.0/25']},
                        {'scope': ['2001:db8::/64']},
                        {'max_total': 1}, {'max_total': 9}, {'max_depth': 0},
                        {'max_active': 0}, {'max_active': 8}, {'methods': ['tcp', 'tcp']},
                        {'methods': ['dns']}, {'name': 'Bad Name'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.policy(**changes)

    def test_extra_fields_are_rejected(self):
        value = self.policy().to_dict()
        value['extra'] = 1
        with self.assertRaises(ValueError):
            GardenPolicy.from_dict(value)


class MembershipTests(unittest.TestCase):
    def policy(self, **changes):
        values = dict(name='lab', scope=['10.66.0.0/24'], max_total=8, max_depth=3, max_active=2)
        values.update(changes)
        return GardenPolicy.create(**values)

    def test_eight_members_get_unique_channels_and_roundtrip(self):
        membership = Membership.create(self.policy())
        mother = next(iter(membership.members.values()))
        self.assertEqual((mother.role, mother.channel, mother.generation), ('mother', 1, 0))
        for index in range(2, 9):
            member = membership.add(generation=1, address='10.66.0.%d' % (10 + index),
                                    label='offshoot-%d' % index)
            self.assertEqual(member.channel, index)
            membership.transition(member.id, 'active')
        self.assertEqual([m.channel for m in membership.members.values()], list(range(1, 9)))
        mapping = membership.wire_map()
        self.assertEqual(mapping.channel(mother.id), 1)
        self.assertEqual(mapping.member(8), next(member.id for member in membership.members.values() if member.channel == 8))
        with self.assertRaises(ValueError):
            membership.add(generation=1, address='10.66.0.99')
        rebuilt = Membership(membership.policy, [json.loads(json.dumps(m.to_dict())) for m in membership.members.values()])
        self.assertEqual(rebuilt.wire_map().digest(), mapping.digest())

    def test_second_mother_duplicate_address_and_outside_scope(self):
        membership = Membership.create(self.policy())
        mother = next(iter(membership.members.values()))
        with self.assertRaises(ValueError):
            membership.add(role='mother')
        first = membership.add(generation=1, address='10.66.0.20')
        with self.assertRaises(ValueError):
            membership.add(generation=1, address='10.66.0.20')
        with self.assertRaises(ValueError):
            membership.add(generation=1, address='192.168.1.5')
        child = membership.add(generation=2, parent=first.id, address='10.66.0.21')
        self.assertEqual(child.parent, first.id)
        with self.assertRaises(ValueError):
            membership.add(generation=4, parent=child.id)
        with self.assertRaises(ValueError):
            membership.add(generation=1, parent=first.id)

    def test_lifecycle_and_mother_revocation(self):
        membership = Membership.create(self.policy())
        mother = next(iter(membership.members.values()))
        member = membership.add(generation=1, address='10.66.0.30')
        membership.transition(member.id, 'active')
        membership.transition(member.id, 'revoked')
        with self.assertRaises(ValueError):
            membership.transition(member.id, 'active')
        with self.assertRaises(ValueError):
            membership.transition(mother.id, 'revoked')

    def test_limit_follows_policy_not_just_wire_space(self):
        membership = Membership.create(self.policy(max_total=4))
        for index in range(3):
            membership.add(generation=1, address='10.66.0.%d' % (40 + index))
        self.assertEqual(len(membership.members), 4)
        with self.assertRaises(ValueError):
            membership.add(generation=1, address='10.66.0.50')

    def test_wire_map_rejects_duplicate_and_out_of_range(self):
        for values in ({'a': 1, 'b': 1}, {'a': 0}, {'a': 9}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                WireMap(values)

    def test_decoder_can_frame_every_member_channel(self):
        decoder = Decoder()
        frames = b''.join(packet(channel, bytes([channel])) for channel in MEMBERS)
        self.assertEqual(decoder.feed(frames), [(channel, bytes([channel])) for channel in MEMBERS])


class GardenStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'garden'
        self.store = GardenStore(self.root)

    def test_roundtrip_and_hash_chained_receipts(self):
        policy = GardenPolicy.create('lab', ['10.66.0.0/24'])
        state = self.store.init(policy)
        loaded = self.store.load()
        self.assertEqual(loaded.policy.digest(), policy.digest())
        self.assertEqual(self.store.receipt('one', value=1)['seq'], 2)
        second = self.store.receipt('two', value=2)
        self.assertEqual(second['seq'], 3)
        first = self.store.receipts(2)[0]
        self.assertEqual(second['previous'], first['digest'])
        self.assertEqual(len(second['digest']), 64)

    def test_corruption_and_duplicate_member_ids(self):
        policy = GardenPolicy.create('lab', ['10.66.0.0/24'])
        self.store.init(policy)
        value = json.loads((self.root / 'garden.json').read_text())
        value['members'].append(value['members'][0])
        (self.root / 'garden.json').write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            self.store.load()

    def test_duplicate_json_keys_are_rejected(self):
        self.store.init(GardenPolicy.create('lab', ['10.66.0.0/24']))
        path = self.root / 'garden.json'
        raw = path.read_text()
        path.write_text(raw.replace('"revision": 1,', '"revision": 1, "revision": 1,', 1))
        with self.assertRaises(ValueError):
            self.store.load()

    def test_init_needs_force_to_replace(self):
        self.store.init(GardenPolicy.create('lab', ['10.66.0.0/24']))
        with self.assertRaises(ValueError):
            self.store.init(GardenPolicy.create('other', ['10.66.0.0/24']))
        state = self.store.init(GardenPolicy.create('other', ['10.66.0.0/24']), force=True)
        self.assertEqual(state.policy.name, 'other')
