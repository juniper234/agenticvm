"""Strict owner-policy schema/signature tests with real Ed25519 keys."""
import base64
import tempfile
import time
import unittest
from pathlib import Path

from autoenroll_support import (
    allowed_targets, generate_cert_identity, generate_key, resign_policy,
    signed_policy,
)
from agenticvm.autoenroll_inventory import (
    canonical, policy_payload, strict_json, validate_policy, verify_policy,
)


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        folder = Path(cls.temp.name)
        cls.owner_key, cls.owner_public = generate_key(folder, "owner")
        cls.other_key, cls.other_public = generate_key(folder, "other-owner")
        cls.mother_key, cls.mother_public, cls.mother_cert = generate_cert_identity(folder, "mother")
        cls.targets = allowed_targets(3)
        cls.now = int(time.time())
        cls.policy = signed_policy(cls.owner_key, cls.owner_public, cls.mother_public,
                                   cls.mother_cert, cls.targets, now=cls.now)

    def test_valid_policy_and_canonical_encoding(self):
        self.assertIs(validate_policy(self.policy, trusted_owner_public_key=self.owner_public, now=self.now), self.policy)
        self.assertEqual(verify_policy(self.policy, trusted_owner_public_key=self.owner_public, now=self.now), self.policy)
        self.assertEqual(canonical({"b": 1, "a": 2}), b'{"a":2,"b":1}')
        self.assertEqual(policy_payload(self.policy), {key: value for key, value in self.policy.items()
                                                       if key != "owner_signature"})

    def test_tampered_signature_and_wrong_root_are_rejected(self):
        bad = dict(self.policy)
        bad["owner_signature"] = base64.b64encode(b"\x00" * 64).decode()
        with self.assertRaisesRegex(ValueError, "signature"):
            validate_policy(bad, trusted_owner_public_key=self.owner_public, now=self.now)
        with self.assertRaisesRegex(ValueError, "owner root"):
            validate_policy(self.policy, trusted_owner_public_key=self.other_public, now=self.now)
        changed = resign_policy({**self.policy, "owner_public_key": self.other_public}, self.other_key)
        with self.assertRaisesRegex(ValueError, "owner root"):
            validate_policy(changed, trusted_owner_public_key=self.owner_public, now=self.now)

    def test_expired_and_limited_policies_are_rejected(self):
        cases = [
            dict(expires_unix=self.now - 1),
            dict(max_targets=2),
            dict(max_targets=8),
            dict(max_active=1),
            dict(max_active=3),
            dict(max_generation=0),
            dict(max_generation=7),
            dict(children_per_agent=2),
            dict(actions=["install-and-join", "scan"]),
        ]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy = signed_policy(self.owner_key, self.owner_public, self.mother_public,
                                       self.mother_cert, self.targets, now=self.now, **change)
                validate_policy(policy, trusted_owner_public_key=self.owner_public, now=self.now)

    def test_duplicate_targets_and_bad_target_fields_are_rejected(self):
        duplicate_uuid = [self.targets[0], {**self.targets[1], "uuid": self.targets[0]["uuid"]}]
        duplicate_mac = [self.targets[0], {**self.targets[1], "mac": self.targets[0]["mac"]}]
        bad_image = [{**self.targets[0], "image_sha256": "A" * 64}]
        bad_mac = [{**self.targets[0], "mac": "52:54:00:4c:41:ff:ff"}]
        extra_field = [{**self.targets[0], "comment": "no"}]
        for targets in (duplicate_uuid, duplicate_mac, bad_image, bad_mac, extra_field):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                policy = signed_policy(self.owner_key, self.owner_public, self.mother_public,
                                       self.mother_cert, targets, now=self.now)
                validate_policy(policy, trusted_owner_public_key=self.owner_public, now=self.now)

    def test_unknown_fields_and_wrong_types_are_rejected(self):
        extra = dict(self.policy)
        extra["unknown"] = True
        with self.assertRaisesRegex(ValueError, "fields"):
            validate_policy(resign_policy(extra, self.owner_key), trusted_owner_public_key=self.owner_public, now=self.now)
        missing = dict(self.policy)
        missing.pop("max_targets")
        with self.assertRaisesRegex(ValueError, "fields"):
            validate_policy(resign_policy(missing, self.owner_key), trusted_owner_public_key=self.owner_public, now=self.now)
        wrong_type = dict(self.policy)
        wrong_type["max_targets"] = True
        with self.assertRaisesRegex(ValueError, "max_targets"):
            validate_policy(resign_policy(wrong_type, self.owner_key), trusted_owner_public_key=self.owner_public, now=self.now)
        bad_schema = dict(self.policy)
        bad_schema["schema"] = "garden.other-policy.v1"
        with self.assertRaisesRegex(ValueError, "schema"):
            validate_policy(resign_policy(bad_schema, self.owner_key), trusted_owner_public_key=self.owner_public, now=self.now)

    def test_json_input_bounds_duplicate_keys_and_nonobjects(self):
        self.assertEqual(strict_json('{"a":1}'), {"a": 1})
        for raw in ("[]", "false", '{"a":1,"a":2}', "x" * 65537):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                strict_json(raw)


if __name__ == "__main__":
    unittest.main()
