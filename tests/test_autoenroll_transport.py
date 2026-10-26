"""Transport is delivery-only; couriers cannot sign, alter or admit."""
import tempfile
import time
import unittest
from pathlib import Path

from autoenroll_support import (
    generate_cert_identity, generate_key, make_mother, make_standalone_invite,
    signed_policy,
)
from agenticvm.autoenroll_inventory import (
    delivery_grant_payload, digest_json, sign_canonical, strict_json,
    verify_delivery_grant,
)
from agenticvm.autoenroll_transport import (
    InviteTransport, MotherDirectTransport, SubAgentCourierTransport,
)


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        folder = Path(cls.temp.name)
        cls.owner_key, cls.owner_public = generate_key(folder, "owner")
        cls.mother_key, cls.mother_public, cls.mother_cert = generate_cert_identity(folder, "mother")
        cls.target_key, cls.target_public = generate_key(folder, "target")
        cls.now = int(time.time())
        cls.policy = signed_policy(cls.owner_key, cls.owner_public, cls.mother_public,
                                   cls.mother_cert,
                                   [{"uuid": "00000000-0000-4000-8000-000000000001",
                                     "mac": "52:54:00:4c:41:01",
                                     "image_sha256": "a" * 64, "label": "external-sim-1"}],
                                   now=cls.now)
        cls.mother = make_mother(cls.policy, cls.mother_key, cls.mother_public)
        cls.target = cls.policy["allowed_targets"][0]
        cls.invite = make_standalone_invite(cls.policy, cls.mother, cls.target, now=cls.now)
        cls.grant = cls.mother.create_delivery_grant(
            cls.invite, sub_agent="offshoot-1", expires_unix=cls.now + 120, now=cls.now)

    def test_mother_direct_delivery_and_collection(self):
        seen = {}

        def deliver(invite, target):
            seen["invite"], seen["target"] = invite, target
            return {"delivered": True, "invite_sha256": digest_json(invite)}

        def collect(request_id):
            return {"request_id": request_id, "receipt": {"status": "joined"}}

        transport = MotherDirectTransport(deliver, collect)
        self.assertIsInstance(transport, InviteTransport)
        result = transport.deliver(self.invite, target=self.target)
        self.assertTrue(result["delivered"])
        self.assertEqual(seen["target"], self.target)
        collected = transport.collect(request_id=self.invite["request_id"])
        self.assertEqual(collected["receipt"]["status"], "joined")
        with self.assertRaisesRegex(ValueError, "courier grant"):
            transport.deliver(self.invite, target=self.target, grant=self.grant)

    def test_delivery_grant_scope_and_signature(self):
        self.assertTrue(verify_delivery_grant(self.grant, self.invite, self.policy, now=self.now))
        other = {"uuid": "00000000-0000-4000-8000-000000000002", "mac": "52:54:00:4c:41:02"}
        for change in ({"expires_unix": self.now - 1}, {"invite_sha256": "0" * 64},
                       {"actions": ["deliver-invite"]}, {"target_uuid": other["uuid"]},
                       {"sub_agent": ""}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_delivery_grant({**self.grant, **change}, self.invite, self.policy, now=self.now)
        forged = dict(self.grant)
        forged["mother_signature"] = sign_canonical(self.target_key, delivery_grant_payload(forged))
        with self.assertRaisesRegex(ValueError, "signature"):
            verify_delivery_grant(forged, self.invite, self.policy, now=self.now)

    def test_courier_cannot_alter_or_mint_and_has_no_admission(self):
        def good_deliver(invite, target, grant):
            return {"delivered": True, "invite_sha256": digest_json(invite)}

        def collect(request_id):
            return {"request_id": request_id, "receipt": {"status": "joined"}}

        courier = SubAgentCourierTransport(sub_agent="offshoot-1", policy=self.policy,
                                           deliver=good_deliver, collect=collect, now=lambda: self.now)
        self.assertIsInstance(courier, InviteTransport)
        self.assertFalse(hasattr(courier, "admit"))
        self.assertEqual(courier.deliver(self.invite, target=self.target, grant=self.grant)["delivered"], True)
        self.assertEqual(courier.collect(request_id=self.invite["request_id"])["receipt"]["status"], "joined")
        with self.assertRaisesRegex(ValueError, "grant"):
            courier.deliver(self.invite, target=self.target, grant=None)
        wrong_agent = SubAgentCourierTransport(sub_agent="offshoot-2", policy=self.policy,
                                               deliver=good_deliver, collect=collect, now=lambda: self.now)
        with self.assertRaisesRegex(ValueError, "another sub-agent"):
            wrong_agent.deliver(self.invite, target=self.target, grant=self.grant)
        tampered = SubAgentCourierTransport(sub_agent="offshoot-1", policy=self.policy,
                                            deliver=lambda i, t, g: {"delivered": True, "invite_sha256": "0" * 64},
                                            collect=collect, now=lambda: self.now)
        with self.assertRaisesRegex(ValueError, "altered"):
            tampered.deliver(self.invite, target=self.target, grant=self.grant)

    def test_target_binding_and_callback_validation(self):
        def deliver(invite, target):
            return {"delivered": True, "invite_sha256": digest_json(invite)}

        def collect(request_id):
            return {"request_id": request_id}

        transport = MotherDirectTransport(deliver, collect)
        with self.assertRaisesRegex(ValueError, "binding"):
            transport.deliver(self.invite, target={"uuid": "00000000-0000-4000-8000-000000000002",
                                                   "mac": "52:54:00:4c:41:02"})
        bad = MotherDirectTransport(lambda i, t: {"delivered": False, "invite_sha256": digest_json(i)}, collect)
        with self.assertRaisesRegex(ValueError, "did not complete"):
            bad.deliver(self.invite, target=self.target)
        with self.assertRaises(ValueError):
            MotherDirectTransport(None, collect)
        with self.assertRaises(ValueError):
            SubAgentCourierTransport(sub_agent="", policy=self.policy, deliver=deliver, collect=collect)

    def test_malformed_json_and_grant_inputs(self):
        self.assertEqual(strict_json('{"a":1}'), {"a": 1})
        for raw in ("[]", "false", '{"a":1,"a":2}', "x" * 65537):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                strict_json(raw)
        with self.assertRaises(ValueError):
            verify_delivery_grant({}, self.invite, self.policy, now=self.now)
        with self.assertRaises(ValueError):
            verify_delivery_grant(self.grant, {}, self.policy, now=self.now)


if __name__ == "__main__":
    unittest.main()
