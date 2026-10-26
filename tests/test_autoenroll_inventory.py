"""Durable inventory, lease, invite, receipt and admission host tests."""
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from uuid import uuid4

from autoenroll_support import (
    allowed_targets, generate_cert_identity, generate_key, make_hello,
    make_inventory, make_mother, make_receipt, make_standalone_invite,
    resign_policy, signed_policy, target_row,
)
from agenticvm.autoenroll_inventory import digest_json, verify_invite


class InventoryTests(unittest.TestCase):
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
                                   cls.mother_cert, cls.targets, now=cls.now)
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

    def discover(self, index):
        target = target_row(self.policy, index)
        self.inv.discover(target["uuid"], channel="inventory",
                          evidence={"source": "inventory", "mac": target["mac"]}, now=self.now)
        return target

    def prepare(self, index=0, sponsor="offshoot-1"):
        target = self.discover(index)
        request = self.inv.request_lease(target["uuid"], sponsor=sponsor, request_id=str(uuid4()), now=self.now)
        lease = self.inv.grant_lease(request["request_id"], str(uuid4()), expires_unix=self.now + 600,
                                     mother=self.mother, now=self.now)
        invite = self.inv.create_invite(
            lease["lease_id"], package_sha256=self.package, model_sha256=self.model,
            torrent_infohash=self.infohash, nonce=str(uuid4()), expires_unix=self.now + 300,
            mother=self.mother, now=self.now)
        return target, request, lease, invite

    def join(self, index=0, sponsor="offshoot-1"):
        target, request, lease, invite = self.prepare(index, sponsor)
        receipt = make_receipt(invite, self.target_key, self.target_public, now=self.now)
        joined = self.inv.record_receipt(invite, receipt, mother=self.mother, now=self.now)
        return target, invite, receipt, joined

    def test_happy_path_discovers_leases_invites_joins_and_admits(self):
        target, request, lease, invite = self.prepare()
        self.assertEqual(target_row(self.policy)["uuid"], target["uuid"])
        self.assertTrue(verify_invite(invite, self.policy, target_uuid=target["uuid"],
                                      target_mac=target["mac"], now=self.now))
        self.assertEqual([row["state"] for row in self.inv.targets() if row["uuid"] == target["uuid"]], ["invited"])
        receipt = make_receipt(invite, self.target_key, self.target_public, now=self.now)
        joined = self.inv.record_receipt(invite, receipt, mother=self.mother, now=self.now)
        self.assertEqual(joined["status"], "joined")
        states = {row["uuid"]: row["state"] for row in self.inv.targets()}
        self.assertEqual(states[target["uuid"]], "joined")
        self.assertEqual(len(self.inv.members()), 1)
        self.assertEqual(self.inv.members()[0]["verified"], 0)
        member = self.inv.admit(target["uuid"], mother=self.mother, now=self.now)
        self.assertEqual(member["verified"], 1)
        states = {row["uuid"]: row["state"] for row in self.inv.targets()}
        self.assertEqual(states[target["uuid"]], "verified")
        self.assertEqual(self.inv.leases()[0]["state"], "completed")
        kinds = [event["kind"] for event in self.inv.events()]
        self.assertIn("discovered", kinds)
        self.assertIn("lease_requested", kinds)
        self.assertIn("lease_granted", kinds)
        self.assertIn("invite_signed", kinds)
        self.assertIn("receipt_verified", kinds)
        self.assertIn("member_admitted", kinds)

    def test_reopen_preserves_state_and_rejects_policy_change(self):
        target, invite, receipt, _ = self.join()
        self.inv.admit(target["uuid"], mother=self.mother, now=self.now)
        self.inv.close()
        reopened = make_inventory(self.temp.name, self.policy, self.owner_public, self.mother)
        self.addCleanup(reopened.close)
        states = {row["uuid"]: row["state"] for row in reopened.targets()}
        self.assertEqual(states[target["uuid"]], "verified")
        self.assertEqual(len(reopened.members()), 1)
        reopened.close()
        changed = resign_policy({**self.policy, "max_targets": 4}, self.owner_key)
        with self.assertRaisesRegex(ValueError, "policy changed"):
            make_inventory(self.temp.name, changed, self.owner_public, self.mother)

    def test_unregistered_target_and_bad_discovery_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unregistered"):
            self.inv.discover(str(uuid4()), channel="inventory",
                              evidence={"source": "inventory", "mac": "52:54:00:4c:41:01"}, now=self.now)
        target = target_row(self.policy, 0)
        with self.assertRaisesRegex(ValueError, "channel"):
            self.inv.discover(target["uuid"], channel="scan",
                              evidence={"source": "scan", "mac": target["mac"]}, now=self.now)
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.inv.discover(target["uuid"], channel="inventory",
                              evidence={"source": "dhcp", "mac": target["mac"]}, now=self.now)
        with self.assertRaisesRegex(ValueError, "MAC"):
            self.inv.discover(target["uuid"], channel="inventory",
                              evidence={"source": "inventory", "mac": "52:54:00:4c:41:99"}, now=self.now)
        with self.assertRaisesRegex(ValueError, "future"):
            self.inv.discover(target["uuid"], channel="dhcp",
                              evidence={"source": "dhcp", "mac": target["mac"], "lease_unix": self.now + 10},
                              now=self.now)
        target1 = target_row(self.policy, 1)
        hello = make_hello(target1, self.target_key, self.target_public, now=self.now)
        self.inv.discover(target1["uuid"], channel="target_hello",
                          evidence={"source": "target_hello", "hello": hello}, now=self.now)
        self.assertEqual([row["state"] for row in self.inv.targets() if row["uuid"] == target1["uuid"]], ["discovered"])
        tampered = {**hello, "nonce": str(uuid4())}
        with self.assertRaisesRegex(ValueError, "signature"):
            self.inv.discover(target["uuid"], channel="target_hello",
                              evidence={"source": "target_hello", "hello": tampered}, now=self.now)

    def test_lease_limits_one_child_and_active_cap(self):
        target0 = self.discover(0)
        request0 = self.inv.request_lease(target0["uuid"], sponsor="offshoot-1", request_id=str(uuid4()), now=self.now)
        self.inv.grant_lease(request0["request_id"], str(uuid4()), expires_unix=self.now + 600,
                             mother=self.mother, now=self.now)
        target1 = self.discover(1)
        with self.assertRaisesRegex(ValueError, "Sponsor"):
            self.inv.request_lease(target1["uuid"], sponsor="offshoot-1", request_id=str(uuid4()), now=self.now)
        request1 = self.inv.request_lease(target1["uuid"], sponsor="offshoot-2", request_id=str(uuid4()), now=self.now)
        self.inv.grant_lease(request1["request_id"], str(uuid4()), expires_unix=self.now + 600,
                             mother=self.mother, now=self.now)
        target2 = self.discover(2)
        with self.assertRaisesRegex(ValueError, "Active enrollment cap"):
            self.inv.request_lease(target2["uuid"], sponsor="offshoot-3", request_id=str(uuid4()), now=self.now)
        with self.assertRaisesRegex(ValueError, "already has an active lease"):
            self.inv.request_lease(target0["uuid"], sponsor="offshoot-4", request_id=str(uuid4()), now=self.now)

    def test_request_id_idempotency_and_changed_reuse(self):
        target = self.discover(0)
        request_id = str(uuid4())
        first = self.inv.request_lease(target["uuid"], sponsor="offshoot-1", request_id=request_id, now=self.now)
        second = self.inv.request_lease(target["uuid"], sponsor="offshoot-1", request_id=request_id, now=self.now)
        self.assertEqual(first, second)
        with self.assertRaisesRegex(ValueError, "changed contents"):
            self.inv.request_lease(target["uuid"], sponsor="offshoot-2", request_id=request_id, now=self.now)

    def test_invite_and_receipt_denials(self):
        target, request, lease, invite = self.prepare()
        other = target_row(self.policy, 1)
        with self.assertRaisesRegex(ValueError, "target UUID"):
            verify_invite(invite, self.policy, target_uuid=other["uuid"], now=self.now)
        with self.assertRaisesRegex(ValueError, "expired"):
            verify_invite(make_standalone_invite(self.policy, self.mother, target, now=self.now,
                                                 expires_unix=self.now - 1), self.policy, now=self.now)
        tampered = dict(invite)
        tampered["package_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "signature"):
            verify_invite(tampered, self.policy, now=self.now)
        true_absence = {name: False for name in ("peer/lan_agent.py", "model.gguf", "identity.key", "lan-config.json")}
        true_absence["identity.key"] = True
        with self.assertRaisesRegex(ValueError, "garden-free"):
            self.inv.record_receipt(invite, make_receipt(invite, self.target_key, self.target_public,
                                                          now=self.now, initial_absence=true_absence),
                                    mother=self.mother, now=self.now)
        with self.assertRaisesRegex(ValueError, "zero-click"):
            self.inv.record_receipt(invite, make_receipt(invite, self.target_key, self.target_public,
                                                          now=self.now, interactive_input=True),
                                    mother=self.mother, now=self.now)
        receipt = make_receipt(invite, self.target_key, self.target_public, now=self.now)
        changed = dict(receipt)
        changed["target_uuid"] = str(uuid4())
        with self.assertRaisesRegex(ValueError, "bind"):
            self.inv.record_receipt(invite, changed, mother=self.mother, now=self.now)
        first = self.inv.record_receipt(invite, receipt, mother=self.mother, now=self.now)
        self.assertEqual(first["status"], "joined")
        self.assertEqual(self.inv.record_receipt(invite, receipt, mother=self.mother, now=self.now), first)
        replay = make_receipt(invite, self.target_key, self.target_public, now=self.now, boot_id=str(uuid4()))
        with self.assertRaisesRegex(ValueError, "changed contents"):
            self.inv.record_receipt(invite, replay, mother=self.mother, now=self.now)
        self.assertEqual(len(self.inv.members()), 1)

    def test_bounded_retry_attempts_exhaust(self):
        target = self.discover(0)
        for index in range(3):
            self.inv.request_lease(target["uuid"], sponsor=f"offshoot-{index + 1}",
                                   request_id=str(uuid4()), now=self.now)
        with self.assertRaisesRegex(ValueError, "attempts"):
            self.inv.request_lease(target["uuid"], sponsor="offshoot-4",
                                   request_id=str(uuid4()), now=self.now)

    def test_one_invite_per_lease_is_idempotent(self):
        target = self.discover(0)
        request = self.inv.request_lease(target["uuid"], sponsor="offshoot-1",
                                         request_id=str(uuid4()), now=self.now)
        lease = self.inv.grant_lease(request["request_id"], str(uuid4()), expires_unix=self.now + 600,
                                     mother=self.mother, now=self.now)
        arguments = dict(package_sha256=self.package, model_sha256=self.model,
                         torrent_infohash=self.infohash, nonce=str(uuid4()),
                         expires_unix=self.now + 300, mother=self.mother, now=self.now)
        first = self.inv.create_invite(lease["lease_id"], **arguments)
        self.assertEqual(self.inv.create_invite(lease["lease_id"], **arguments), first)
        changed = dict(arguments)
        changed["nonce"] = str(uuid4())
        with self.assertRaisesRegex(ValueError, "different invite"):
            self.inv.create_invite(lease["lease_id"], **changed)

    def test_mark_installing_binds_delivery_evidence_and_receipt_still_joins(self):
        target, request, lease, invite = self.prepare()
        with self.assertRaisesRegex(ValueError, "mother authority"):
            self.inv.mark_installing(lease["lease_id"],
                                     evidence={"transport": "mother-direct", "invite_sha256": digest_json(invite)},
                                     mother=None, now=self.now)
        with self.assertRaisesRegex(ValueError, "hash"):
            self.inv.mark_installing(lease["lease_id"],
                                     evidence={"transport": "mother-direct", "invite_sha256": "0" * 64},
                                     mother=self.mother, now=self.now)
        marked = self.inv.mark_installing(
            lease["lease_id"], evidence={"transport": "mother-direct", "invite_sha256": digest_json(invite)},
            mother=self.mother, now=self.now)
        self.assertEqual(marked["state"], "installing")
        states = {row["uuid"]: row["state"] for row in self.inv.targets()}
        self.assertEqual(states[target["uuid"]], "installing")
        receipt = make_receipt(invite, self.target_key, self.target_public, now=self.now)
        self.assertEqual(self.inv.record_receipt(invite, receipt, mother=self.mother, now=self.now)["status"], "joined")

    def test_admission_requires_a_receipt(self):
        target = self.discover(0)
        with self.assertRaisesRegex(ValueError, "verified receipt"):
            self.inv.admit(target["uuid"], mother=self.mother, now=self.now)

    def test_subagent_cannot_authorize_or_admit(self):
        target = self.discover(0)
        request = self.inv.request_lease(target["uuid"], sponsor="offshoot-1", request_id=str(uuid4()), now=self.now)
        with self.assertRaisesRegex(ValueError, "mother authority"):
            self.inv.grant_lease(request["request_id"], str(uuid4()), expires_unix=self.now + 600,
                                 mother=None, now=self.now)
        with self.assertRaisesRegex(ValueError, "mother authority"):
            self.inv.grant_lease(request["request_id"], str(uuid4()), expires_unix=self.now + 600,
                                 mother=object(), now=self.now)
        self.inv.grant_lease(request["request_id"], str(uuid4()), expires_unix=self.now + 600,
                             mother=self.mother, now=self.now)
        lease = self.inv.leases()[0]
        with self.assertRaisesRegex(ValueError, "mother authority"):
            self.inv.create_invite(lease["lease_id"], package_sha256=self.package, model_sha256=self.model,
                                   torrent_infohash=self.infohash, nonce=str(uuid4()),
                                   expires_unix=self.now + 300, mother=None, now=self.now)
        with self.assertRaisesRegex(ValueError, "mother authority"):
            self.inv.admit(target["uuid"], mother=None, now=self.now)

    def test_revoke_and_expire_lifecycle(self):
        target = self.discover(0)
        revoked = self.inv.revoke(target["uuid"], reason="owner request", mother=self.mother, now=self.now)
        self.assertEqual(revoked["state"], "revoked")
        self.assertIn("target_revoked", [event["kind"] for event in self.inv.events()])
        target1 = self.discover(1)
        request = self.inv.request_lease(target1["uuid"], sponsor="offshoot-1", request_id=str(uuid4()), now=self.now)
        lease = self.inv.grant_lease(request["request_id"], str(uuid4()), expires_unix=self.now + 1,
                                     mother=self.mother, now=self.now)
        self.assertEqual(lease["state"], "active")
        self.assertEqual(self.inv.expire(now=self.now + 2), 1)
        states = {row["uuid"]: row["state"] for row in self.inv.targets()}
        self.assertEqual(states[target1["uuid"]], "expired")
        self.assertEqual(self.inv.leases()[0]["state"], "expired")

    def test_generation_cap_is_enforced(self):
        target = self.discover(0)
        with self.inv.db:
            self.inv.db.execute("UPDATE targets SET generation=2 WHERE uuid=?", (target["uuid"],))
        with self.assertRaisesRegex(ValueError, "generation cap"):
            self.inv.request_lease(target["uuid"], sponsor="offshoot-1", request_id=str(uuid4()), now=self.now)


if __name__ == "__main__":
    unittest.main()
