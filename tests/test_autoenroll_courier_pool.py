"""Three-target courier pool contract tests over the host inventory/transport."""
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from uuid import uuid4

from autoenroll_support import (
    allowed_targets, generate_cert_identity, generate_key, make_inventory,
    make_mother, make_receipt, resign_policy, signed_policy, target_row,
)
from agenticvm.autoenroll_inventory import digest_json, verify_delivery_grant, verify_invite
from agenticvm.autoenroll_transport import SubAgentCourierTransport


class CourierPoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        folder = Path(cls.temp.name)
        cls.owner_key, cls.owner_public = generate_key(folder, "owner")
        cls.mother_key, cls.mother_public, cls.mother_cert = generate_cert_identity(folder, "mother")
        cls.target_key, cls.target_public = generate_key(folder, "target")
        cls.targets = allowed_targets(3)
        cls.now = int(time.time())
        cls.policy = signed_policy(cls.owner_key, cls.owner_public, cls.mother_public,
                                   cls.mother_cert, cls.targets, now=cls.now,
                                   max_generation=1, max_targets=3)
        cls.mother = make_mother(cls.policy, cls.mother_key, cls.mother_public)
        cls.package = hashlib.sha256(b"package").hexdigest()
        cls.model = hashlib.sha256(b"model").hexdigest()
        cls.infohash = hashlib.sha256(b"torrent").hexdigest()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.inv = make_inventory(self.temp.name, self.policy, self.owner_public, self.mother)
        self.addCleanup(self.inv.close)
        self.now = int(time.time())

    def prepare(self, index, sponsor="courier-1"):
        target = target_row(self.policy, index)
        self.inv.discover(target["uuid"], channel="inventory",
                          evidence={"source": "inventory", "mac": target["mac"]}, now=self.now)
        request = self.inv.request_lease(target["uuid"], sponsor=sponsor,
                                         request_id=str(uuid4()), now=self.now)
        lease = self.inv.grant_lease(request["request_id"], str(uuid4()),
                                     expires_unix=self.now + 600, mother=self.mother, now=self.now)
        invite = self.inv.create_invite(
            lease["lease_id"], package_sha256=self.package, model_sha256=self.model,
            torrent_infohash=self.infohash, nonce=str(uuid4()),
            expires_unix=self.now + 300, mother=self.mother, now=self.now)
        grant = self.mother.create_delivery_grant(
            invite, sub_agent=sponsor, expires_unix=self.now + 300, now=self.now)
        return target, invite, grant

    def transport(self, *, sub_agent="courier-1", mutate=False):
        def deliver(invite, target, grant):
            return {"delivered": True,
                    "invite_sha256": ("0" * 64 if mutate else digest_json(invite))}

        def collect(request_id):
            return {"request_id": request_id, "receipt": {"ok": True}}

        return SubAgentCourierTransport(sub_agent=sub_agent, policy=self.policy,
                                        deliver=deliver, collect=collect,
                                        now=lambda: self.now)

    def test_three_target_pool_sequential_courier_admission(self):
        courier = self.transport()
        for index in range(3):
            target, invite, grant = self.prepare(index)
            courier.deliver(invite, target=target, grant=grant)
            receipt = make_receipt(invite, self.target_key, self.target_public, now=self.now)
            self.inv.record_receipt(invite, receipt, mother=self.mother, now=self.now)
            self.inv.admit(target["uuid"], mother=self.mother, now=self.now)
        self.assertEqual(len(self.inv.members()), 3)
        self.assertEqual(sum(1 for row in self.inv.targets() if row["state"] == "verified"), 3)
        self.assertTrue(all(row["verified"] == 1 for row in self.inv.members()))
        self.assertEqual(self.inv.policy["max_targets"], 3)

    def test_active_pool_and_target_caps(self):
        target0, invite0, grant0 = self.prepare(0, sponsor="courier-1")
        target1, invite1, grant1 = self.prepare(1, sponsor="courier-2")
        target2 = target_row(self.policy, 2)
        self.inv.discover(target2["uuid"], channel="inventory",
                          evidence={"source": "inventory", "mac": target2["mac"]}, now=self.now)
        with self.assertRaisesRegex(ValueError, "Active enrollment cap"):
            self.inv.request_lease(target2["uuid"], sponsor="courier-3",
                                   request_id=str(uuid4()), now=self.now)
        # One-child-per-agent is exercised by the focused C2 inventory tests;
        # this pool test owns the active-cap and three-target-bound assertions.
        self.assertEqual(len(self.policy["allowed_targets"]), 3)
        self.assertEqual(self.policy["max_active"], 2)

    def test_courier_grant_scope_tamper_and_wrong_agent(self):
        target, invite, grant = self.prepare(0)
        verify_delivery_grant(grant, invite, self.policy, now=self.now)
        for change in ({"expires_unix": self.now - 1}, {"invite_sha256": "0" * 64},
                       {"target_uuid": target_row(self.policy, 1)["uuid"]},
                       {"actions": ["deliver-invite"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_delivery_grant({**grant, **change}, invite, self.policy, now=self.now)
        with self.assertRaises(ValueError):
            self.transport(mutate=True).deliver(invite, target=target, grant=grant)
        with self.assertRaisesRegex(ValueError, "another sub-agent"):
            self.transport(sub_agent="courier-2").deliver(invite, target=target, grant=grant)
        with self.assertRaisesRegex(ValueError, "target UUID"):
            verify_invite(invite, self.policy, target_uuid=target_row(self.policy, 1)["uuid"],
                          now=self.now)

    def test_replayed_invite_and_duplicate_receipt(self):
        target, invite, grant = self.prepare(0)
        other = target_row(self.policy, 1)
        with self.assertRaisesRegex(ValueError, "target UUID"):
            verify_invite(invite, self.policy, target_uuid=other["uuid"], now=self.now)
        receipt = make_receipt(invite, self.target_key, self.target_public, now=self.now)
        first = self.inv.record_receipt(invite, receipt, mother=self.mother, now=self.now)
        self.assertEqual(self.inv.record_receipt(invite, receipt, mother=self.mother, now=self.now), first)
        self.inv.admit(target["uuid"], mother=self.mother, now=self.now)
        changed = make_receipt(invite, self.target_key, self.target_public, now=self.now,
                               boot_id=str(uuid4()))
        with self.assertRaisesRegex(ValueError, "changed contents"):
            self.inv.record_receipt(invite, changed, mother=self.mother, now=self.now)
        self.assertEqual(len(self.inv.members()), 1)


if __name__ == "__main__":
    unittest.main()
