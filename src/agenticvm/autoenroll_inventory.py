"""Owner-authorized, mother-controlled auto-enrollment inventory.

This module is host-only. It defines strict pydantic-free schemas, canonical
Ed25519 signing/verification, a durable SQLite state machine, and the bounded
inventory/lease/invite/receipt transitions. It never scans a network and never
executes a target. Native orchestration is a separate Phase 2 module.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import UUID

def _openssl_path():
    override = os.environ.get("GARDEN_OPENSSL")
    if override:
        return Path(override)
    host = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
    if host.exists():
        return host
    for candidate in (Path("/usr/bin/openssl"), Path("/bin/openssl")):
        if candidate.exists():
            return candidate
    return host


OPENSSL = _openssl_path()

ACTIONS = ["install-and-join"]
DISCOVERY_CHANNELS = ("inventory", "dhcp", "target_hello")
TERMINAL_STATES = ("verified", "revoked", "failed", "expired")
ACTIVE_LEASE_STATES = ("active", "invited", "installing")

POLICY_FIELDS = {
    "schema", "garden", "mother_public_key", "mother_certificate",
    "owner_public_key", "allowed_targets", "max_targets", "max_active",
    "max_generation", "children_per_agent", "actions", "expires_unix",
    "owner_signature",
}
TARGET_FIELDS = {"uuid", "mac", "image_sha256", "label"}
INVITE_FIELDS = {
    "schema", "request_id", "lease_id", "garden", "target_uuid", "target_mac",
    "action", "package_sha256", "model_sha256", "torrent_infohash", "nonce",
    "expires_unix", "mother_certificate", "mother_signature",
}
DELIVERY_GRANT_FIELDS = {
    "schema", "sub_agent", "lease_id", "target_uuid", "invite_sha256",
    "expires_unix", "actions", "mother_signature",
}
RECEIPT_FIELDS = {
    "schema", "request_id", "lease_id", "target_uuid", "target_mac", "action",
    "package_sha256", "model_sha256", "torrent_infohash", "torrent_receipt",
    "identity_fingerprint", "target_public_key", "initial_absence", "boot_id",
    "zero_click", "interactive_input", "signed_unix", "target_signature",
}
TORRENT_RECEIPT_FIELDS = {"peer", "bytes", "trackers", "dht", "pex"}
HELLO_FIELDS = {"schema", "target_uuid", "mac", "nonce", "timestamp", "public_key", "signature"}
INITIAL_ABSENCE_FIELDS = {"peer/lan_agent.py", "model.gguf", "identity.key", "lan-config.json"}
INSTALLING_FIELDS = {"transport", "invite_sha256"}

_MAC = re.compile(r"^52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INFOHASH = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


# ---------------------------------------------------------------------------
# Canonical JSON and Ed25519 helpers
# ---------------------------------------------------------------------------

def canonical(value) -> bytes:
    """Canonical JSON used by every signature in this profile."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest_json(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def identity_fingerprint(public_key: str) -> str:
    if not isinstance(public_key, str):
        raise ValueError("A target public key is required")
    return hashlib.sha256(public_key.strip().encode()).hexdigest()


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def strict_json(raw, *, limit=65536):
    """Parse one object, rejecting oversized, non-object and duplicate-key JSON."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("JSON must be UTF-8") from error
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > limit:
        raise ValueError("JSON object exceeds its input bound")
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError) as error:
        raise ValueError("Malformed JSON object") from error
    if not isinstance(value, dict):
        raise ValueError("A JSON object is required")
    return value


def _openssl(args, *, timeout=10):
    try:
        return subprocess.run([str(OPENSSL), *args], capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("OpenSSL is unavailable for auto-enrollment signing") from error


def sign_canonical(private_key, value) -> str:
    key = Path(private_key)
    if not key.is_file():
        raise ValueError("A signing key is required")
    with tempfile.TemporaryDirectory(prefix="garden-autoenroll-") as directory:
        payload = Path(directory) / "payload"
        payload.write_bytes(canonical(value))
        result = _openssl(["pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(payload)])
    if result.returncode or len(result.stdout) != 64:
        raise ValueError("Ed25519 signing failed")
    return base64.b64encode(result.stdout).decode()


def verify_canonical(public_key, value, signature, *, label="object"):
    if not isinstance(public_key, str) or "-----BEGIN PUBLIC KEY-----" not in public_key:
        raise ValueError(f"{label} public key is malformed")
    try:
        raw = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError(f"{label} signature is malformed") from error
    if len(raw) != 64:
        raise ValueError(f"{label} signature is malformed")
    with tempfile.TemporaryDirectory(prefix="garden-autoenroll-") as directory:
        folder = Path(directory)
        (folder / "payload").write_bytes(canonical(value))
        (folder / "signature").write_bytes(raw)
        (folder / "public.pem").write_text(public_key)
        result = _openssl([
            "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(folder / "public.pem"),
            "-sigfile", str(folder / "signature"), "-in", str(folder / "payload"),
        ])
    if result.returncode:
        raise ValueError(f"{label} signature authentication failed")
    return True


# ---------------------------------------------------------------------------
# Strict scalar validators
# ---------------------------------------------------------------------------

def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields are not exact")
    return value


def _uuid(value, label):
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except (ValueError, TypeError) as error:
        raise ValueError(f"{label} must be a canonical UUID") from error
    if str(parsed) != value:
        raise ValueError(f"{label} must be a canonical UUID")
    return value


def _mac(value, label="MAC"):
    if not isinstance(value, str) or not _MAC.fullmatch(value):
        raise ValueError(f"{label} must be an owned 52:54:00:xx:xx:xx address")
    return value


def _sha256(value, label):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{label} must be 64 lowercase hex characters")
    return value


def _infohash(value, label):
    if not isinstance(value, str) or not _INFOHASH.fullmatch(value):
        raise ValueError(f"{label} must be a 40 or 64 character lowercase hex infohash")
    return value


def _int(value, label):
    if type(value) is not int:
        raise ValueError(f"{label} must be an integer")
    return value


def _bool(value, label):
    if type(value) is not bool:
        raise ValueError(f"{label} must be a boolean")
    return value


def _text(value, label, *, limit=256):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > limit:
        raise ValueError(f"{label} must be bounded non-empty text")
    return value


def _pem(value, label, header):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 16384:
        raise ValueError(f"{label} must be a bounded PEM value")
    if not value.startswith(header) or header.replace("BEGIN", "END") not in value:
        raise ValueError(f"{label} must be a PEM value")
    return value


def _signature(value, label):
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError(f"{label} signature is malformed")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError(f"{label} signature is malformed") from error
    if len(raw) != 64:
        raise ValueError(f"{label} signature is malformed")
    return value


def _clock(now):
    return int(time.time()) if now is None else _int(now, "clock")


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def policy_payload(policy):
    if not isinstance(policy, dict):
        raise ValueError("A policy object is required")
    payload = {key: value for key, value in policy.items() if key != "owner_signature"}
    if set(payload) != POLICY_FIELDS - {"owner_signature"}:
        raise ValueError("Policy fields are not exact")
    return payload


def validate_policy(policy, *, trusted_owner_public_key, now=None):
    _exact(policy, POLICY_FIELDS, "Policy")
    if policy["schema"] != "garden.mother-policy.v1":
        raise ValueError("Unknown policy schema")
    _uuid(policy["garden"], "policy garden")
    _pem(policy["mother_public_key"], "mother public key", "-----BEGIN PUBLIC KEY-----")
    _pem(policy["mother_certificate"], "mother certificate", "-----BEGIN CERTIFICATE-----")
    _pem(policy["owner_public_key"], "owner public key", "-----BEGIN PUBLIC KEY-----")
    max_targets = _int(policy["max_targets"], "max_targets")
    max_active = _int(policy["max_active"], "max_active")
    max_generation = _int(policy["max_generation"], "max_generation")
    children = _int(policy["children_per_agent"], "children_per_agent")
    expires = _int(policy["expires_unix"], "policy expiry")
    if not 3 <= max_targets <= 7:
        raise ValueError("max_targets must be between three and seven")
    if max_active != 2:
        raise ValueError("max_active must be exactly two")
    if not 1 <= max_generation <= 6:
        raise ValueError("max_generation must be between one and six")
    if children != 1:
        raise ValueError("children_per_agent must be exactly one")
    if policy["actions"] != ACTIONS:
        raise ValueError("Policy action allowlist changed")
    allowed = policy["allowed_targets"]
    if not isinstance(allowed, list) or not 1 <= len(allowed) <= max_targets:
        raise ValueError("allowed_targets must be a bounded non-empty list")
    seen_uuid, seen_mac = set(), set()
    for row in allowed:
        _exact(row, TARGET_FIELDS, "Allowed target")
        _uuid(row["uuid"], "allowed target uuid")
        _mac(row["mac"], "allowed target MAC")
        _sha256(row["image_sha256"], "allowed target image")
        _text(row["label"], "allowed target label", limit=64)
        if row["uuid"] in seen_uuid or row["mac"] in seen_mac:
            raise ValueError("Duplicate allowed target UUID or MAC")
        seen_uuid.add(row["uuid"])
        seen_mac.add(row["mac"])
    if _clock(now) >= expires:
        raise ValueError("Policy is expired")
    if not isinstance(trusted_owner_public_key, str) or policy["owner_public_key"].strip() != trusted_owner_public_key.strip():
        raise ValueError("Policy owner root mismatch")
    _signature(policy["owner_signature"], "policy")
    verify_canonical(trusted_owner_public_key, policy_payload(policy), policy["owner_signature"], label="policy")
    return policy


def verify_policy(policy, *, trusted_owner_public_key, now=None):
    return validate_policy(policy, trusted_owner_public_key=trusted_owner_public_key, now=now)


class MotherAuthority:
    """Holds the mother private key; the only object allowed to sign invites."""

    def __init__(self, policy, private_key, public_key):
        if not isinstance(policy, dict):
            raise ValueError("A validated policy is required")
        _pem(public_key, "mother public key", "-----BEGIN PUBLIC KEY-----")
        if policy["mother_public_key"].strip() != public_key.strip():
            raise ValueError("Mother key does not match the policy")
        self.policy = policy
        self.private_key = Path(private_key)
        self.public_key = public_key
        probe = {"probe": "garden.autoenroll.mother.v1"}
        verify_canonical(public_key, probe, sign_canonical(self.private_key, probe), label="mother probe")

    def sign(self, value):
        return sign_canonical(self.private_key, value)

    def create_delivery_grant(self, invite, *, sub_agent, expires_unix, now=None):
        _exact(invite, INVITE_FIELDS, "Invite")
        verify_invite(invite, self.policy, now=now)
        _text(sub_agent, "sub_agent", limit=64)
        _int(expires_unix, "delivery grant expiry")
        if expires_unix <= _clock(now):
            raise ValueError("Delivery grant is expired")
        payload = {
            "schema": "garden.delivery-grant.v1",
            "sub_agent": sub_agent,
            "lease_id": invite["lease_id"],
            "target_uuid": invite["target_uuid"],
            "invite_sha256": digest_json(invite),
            "expires_unix": expires_unix,
            "actions": ["deliver-invite", "collect-receipt"],
        }
        return {**payload, "mother_signature": self.sign(payload)}


# ---------------------------------------------------------------------------
# Invite, delivery grant, receipt and hello validation
# ---------------------------------------------------------------------------

def invite_payload(invite):
    _exact(invite, INVITE_FIELDS, "Invite")
    return {key: value for key, value in invite.items() if key != "mother_signature"}


def verify_invite(invite, policy, *, target_uuid=None, target_mac=None, now=None):
    _exact(invite, INVITE_FIELDS, "Invite")
    if invite["schema"] != "garden.autoenroll.invite.v1":
        raise ValueError("Unknown invite schema")
    for field in ("request_id", "lease_id", "garden", "target_uuid", "nonce"):
        _uuid(invite[field], "invite " + field)
    _mac(invite["target_mac"], "invite target MAC")
    if invite["action"] != ACTIONS[0]:
        raise ValueError("Invite action is outside the allowlist")
    _sha256(invite["package_sha256"], "invite package")
    _sha256(invite["model_sha256"], "invite model")
    _infohash(invite["torrent_infohash"], "invite torrent")
    _int(invite["expires_unix"], "invite expiry")
    _pem(invite["mother_certificate"], "invite mother certificate", "-----BEGIN CERTIFICATE-----")
    _signature(invite["mother_signature"], "invite")
    if invite["garden"] != policy["garden"]:
        raise ValueError("Invite garden binding mismatch")
    if invite["mother_certificate"].strip() != policy["mother_certificate"].strip():
        raise ValueError("Invite mother certificate is not pinned")
    if target_uuid is not None and invite["target_uuid"] != _uuid(target_uuid, "expected target UUID"):
        raise ValueError("Invite target UUID binding mismatch")
    if target_mac is not None and invite["target_mac"] != _mac(target_mac, "expected target MAC"):
        raise ValueError("Invite target MAC binding mismatch")
    if _clock(now) >= invite["expires_unix"]:
        raise ValueError("Invite is expired")
    verify_canonical(policy["mother_public_key"], invite_payload(invite), invite["mother_signature"], label="invite")
    return invite


def delivery_grant_payload(grant):
    _exact(grant, DELIVERY_GRANT_FIELDS, "Delivery grant")
    return {key: value for key, value in grant.items() if key != "mother_signature"}


def verify_delivery_grant(grant, invite, policy, *, now=None):
    _exact(grant, DELIVERY_GRANT_FIELDS, "Delivery grant")
    if grant["schema"] != "garden.delivery-grant.v1":
        raise ValueError("Unknown delivery grant schema")
    _text(grant["sub_agent"], "delivery grant sub_agent", limit=64)
    _uuid(grant["lease_id"], "delivery grant lease")
    _uuid(grant["target_uuid"], "delivery grant target")
    _sha256(grant["invite_sha256"], "delivery grant invite hash")
    _int(grant["expires_unix"], "delivery grant expiry")
    if grant["actions"] != ["deliver-invite", "collect-receipt"]:
        raise ValueError("Delivery grant action scope changed")
    if _clock(now) >= grant["expires_unix"]:
        raise ValueError("Delivery grant is expired")
    verify_invite(invite, policy, now=now)
    if grant["lease_id"] != invite["lease_id"] or grant["target_uuid"] != invite["target_uuid"]:
        raise ValueError("Delivery grant target binding mismatch")
    if grant["invite_sha256"] != digest_json(invite):
        raise ValueError("Delivery grant invite hash mismatch")
    _signature(grant["mother_signature"], "delivery grant")
    verify_canonical(policy["mother_public_key"], delivery_grant_payload(grant), grant["mother_signature"],
                     label="delivery grant")
    return grant


def receipt_payload(receipt):
    _exact(receipt, RECEIPT_FIELDS, "Receipt")
    return {key: value for key, value in receipt.items() if key != "target_signature"}


def verify_receipt(receipt, invite, *, now=None):
    _exact(receipt, RECEIPT_FIELDS, "Receipt")
    if receipt["schema"] != "garden.autoenroll.receipt.v1":
        raise ValueError("Unknown receipt schema")
    for field in ("request_id", "lease_id", "target_uuid"):
        _uuid(receipt[field], "receipt " + field)
    _mac(receipt["target_mac"], "receipt target MAC")
    if receipt["action"] != ACTIONS[0]:
        raise ValueError("Receipt action is outside the allowlist")
    _sha256(receipt["package_sha256"], "receipt package")
    _sha256(receipt["model_sha256"], "receipt model")
    _infohash(receipt["torrent_infohash"], "receipt torrent")
    _exact(receipt["torrent_receipt"], TORRENT_RECEIPT_FIELDS, "Torrent receipt")
    _text(receipt["torrent_receipt"]["peer"], "torrent peer", limit=128)
    if _int(receipt["torrent_receipt"]["bytes"], "torrent bytes") < 1:
        raise ValueError("Torrent receipt has no delivered bytes")
    if _int(receipt["torrent_receipt"]["trackers"], "torrent trackers") != 0:
        raise ValueError("Torrent receipt must not use a tracker")
    if _bool(receipt["torrent_receipt"]["dht"], "torrent dht") or _bool(receipt["torrent_receipt"]["pex"], "torrent pex"):
        raise ValueError("Torrent receipt must not use DHT or PEX")
    _sha256(receipt["identity_fingerprint"], "identity fingerprint")
    _pem(receipt["target_public_key"], "target public key", "-----BEGIN PUBLIC KEY-----")
    if receipt["identity_fingerprint"] != identity_fingerprint(receipt["target_public_key"]):
        raise ValueError("Receipt identity fingerprint mismatch")
    _exact(receipt["initial_absence"], INITIAL_ABSENCE_FIELDS, "Initial absence")
    if any(receipt["initial_absence"].values()):
        raise ValueError("Target was not initially garden-free")
    _text(receipt["boot_id"], "boot id", limit=128)
    if receipt["zero_click"] is not True or receipt["interactive_input"] is not False:
        raise ValueError("Receipt does not prove zero-click/no-input")
    _int(receipt["signed_unix"], "receipt signed time")
    _signature(receipt["target_signature"], "receipt")
    if any(receipt[field] != invite[field] for field in (
            "request_id", "lease_id", "target_uuid", "target_mac", "action",
            "package_sha256", "model_sha256", "torrent_infohash")):
        raise ValueError("Receipt does not bind to the invite")
    verify_canonical(receipt["target_public_key"], receipt_payload(receipt), receipt["target_signature"],
                     label="receipt")
    return receipt


def hello_payload(hello):
    _exact(hello, HELLO_FIELDS, "Target hello")
    return {key: value for key, value in hello.items() if key != "signature"}


def verify_target_hello(hello):
    _exact(hello, HELLO_FIELDS, "Target hello")
    if hello["schema"] != "garden.target-hello.v1":
        raise ValueError("Unknown target hello schema")
    _uuid(hello["target_uuid"], "hello target uuid")
    _mac(hello["mac"], "hello MAC")
    _uuid(hello["nonce"], "hello nonce")
    _int(hello["timestamp"], "hello timestamp")
    _pem(hello["public_key"], "hello public key", "-----BEGIN PUBLIC KEY-----")
    _signature(hello["signature"], "hello")
    verify_canonical(hello["public_key"], hello_payload(hello), hello["signature"], label="target hello")
    return hello


# ---------------------------------------------------------------------------
# Durable inventory / state machine
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE targets (
    uuid TEXT PRIMARY KEY, mac TEXT NOT NULL UNIQUE, image_sha256 TEXT NOT NULL,
    label TEXT NOT NULL, state TEXT NOT NULL, generation INTEGER NOT NULL,
    sponsor TEXT, lease_id TEXT, attempts INTEGER NOT NULL DEFAULT 0,
    updated_unix INTEGER NOT NULL);
CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY, target_uuid TEXT NOT NULL REFERENCES targets(uuid),
    request_id TEXT NOT NULL UNIQUE, sponsor TEXT NOT NULL, generation INTEGER NOT NULL,
    expires_unix INTEGER NOT NULL, state TEXT NOT NULL, invite_sha256 TEXT,
    invite_json TEXT, created_unix INTEGER NOT NULL);
CREATE TABLE requests (
    request_id TEXT PRIMARY KEY, kind TEXT NOT NULL, digest TEXT NOT NULL,
    result TEXT NOT NULL, created_unix INTEGER NOT NULL);
CREATE TABLE members (
    target_uuid TEXT PRIMARY KEY REFERENCES targets(uuid), identity_fingerprint TEXT NOT NULL,
    target_public_key TEXT NOT NULL, joined_unix INTEGER NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0);
CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at_unix INTEGER NOT NULL,
    kind TEXT NOT NULL, target_uuid TEXT, detail TEXT NOT NULL);
"""


class AutoEnrollInventory:
    """Durable mother-controlled target/lease/request/member/audit ledger."""

    def __init__(self, path, *, policy, owner_public_key, mother, now=None):
        if not isinstance(mother, MotherAuthority):
            raise ValueError("A MotherAuthority is required")
        self.policy = validate_policy(policy, trusted_owner_public_key=owner_public_key, now=now)
        if digest_json(mother.policy) != digest_json(self.policy):
            raise ValueError("Mother authority policy changed")
        if mother.public_key.strip() != self.policy["mother_public_key"].strip():
            raise ValueError("Mother authority key mismatch")
        self.mother = mother
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fresh = not self.path.exists()
        self.db = sqlite3.connect(str(self.path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            if fresh:
                self._create(now)
            else:
                self._reopen()
            if self.db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Auto-enrollment ledger integrity check failed")
        except Exception:
            self.db.close()
            raise

    # -- lifecycle ---------------------------------------------------------
    def _create(self, now):
        stamp = _clock(now)
        with self.db:
            self.db.executescript(_SCHEMA)
            metadata = {
                "policy_sha256": digest_json(self.policy),
                "garden": self.policy["garden"],
                "max_targets": self.policy["max_targets"],
                "max_active": self.policy["max_active"],
                "max_generation": self.policy["max_generation"],
                "children_per_agent": self.policy["children_per_agent"],
            }
            self.db.executemany("INSERT INTO metadata VALUES (?,?)",
                                [(key, json.dumps(value)) for key, value in metadata.items()])
            for target in self.policy["allowed_targets"]:
                self.db.execute(
                    "INSERT INTO targets(uuid,mac,image_sha256,label,state,generation,updated_unix) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (target["uuid"], target["mac"], target["image_sha256"], target["label"], "dormant", 0, stamp))

    def _reopen(self):
        row = self.db.execute("SELECT value FROM metadata WHERE key='policy_sha256'").fetchone()
        if row is None or json.loads(row["value"]) != digest_json(self.policy):
            raise ValueError("Persisted policy changed")
        expected = {row["uuid"]: row for row in self.policy["allowed_targets"]}
        actual = {row["uuid"]: row for row in self.db.execute("SELECT * FROM targets")}
        if set(expected) != set(actual):
            raise ValueError("Persisted target inventory changed")
        for uuid, target in expected.items():
            row = actual[uuid]
            if (row["mac"] != target["mac"] or row["image_sha256"] != target["image_sha256"]
                    or row["label"] != target["label"]):
                raise ValueError("Persisted target identity changed")

    def close(self):
        if getattr(self, "db", None) is not None:
            self.db.close()
            self.db = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- lookup helpers ----------------------------------------------------
    def _target(self, target_uuid):
        row = self.db.execute("SELECT * FROM targets WHERE uuid=?", (_uuid(target_uuid, "target UUID"),)).fetchone()
        if row is None:
            raise ValueError("Unknown or unregistered target")
        return dict(row)

    def _lease(self, lease_id):
        row = self.db.execute("SELECT * FROM leases WHERE lease_id=?", (_uuid(lease_id, "lease UUID"),)).fetchone()
        if row is None:
            raise ValueError("Unknown lease")
        return dict(row)

    def _request(self, request_id):
        row = self.db.execute("SELECT * FROM requests WHERE request_id=?", (request_id,)).fetchone()
        return dict(row) if row else None

    def _active_leases(self):
        return [dict(row) for row in self.db.execute(
            "SELECT * FROM leases WHERE state IN (?,?,?)",
            ACTIVE_LEASE_STATES)]

    def _lease_for_target(self, target_uuid):
        row = self.db.execute(
            "SELECT * FROM leases WHERE target_uuid=? AND state IN (?,?,?)",
            (target_uuid, *ACTIVE_LEASE_STATES)).fetchone()
        return dict(row) if row else None

    def _lease_for_sponsor(self, sponsor):
        row = self.db.execute(
            "SELECT * FROM leases WHERE sponsor=? AND state IN (?,?,?)",
            (sponsor, *ACTIVE_LEASE_STATES)).fetchone()
        return dict(row) if row else None

    def _audit(self, kind, target_uuid, detail, now):
        self.db.execute("INSERT INTO audit(at_unix,kind,target_uuid,detail) VALUES (?,?,?,?)",
                        (now, kind, target_uuid, json.dumps(detail, sort_keys=True)))

    def _set_target(self, target_uuid, state, now, **fields):
        values = {"state": state, "updated_unix": now, **fields}
        assignments = ",".join(key + "=?" for key in values)
        self.db.execute(f"UPDATE targets SET {assignments} WHERE uuid=?",
                        (*values.values(), target_uuid))

    def _set_lease(self, lease_id, state, **fields):
        values = {"state": state, **fields}
        assignments = ",".join(key + "=?" for key in values)
        self.db.execute(f"UPDATE leases SET {assignments} WHERE lease_id=?",
                        (*values.values(), lease_id))

    def _store_request(self, request_id, kind, digest, result, now):
        self.db.execute("INSERT INTO requests(request_id,kind,digest,result,created_unix) VALUES (?,?,?,?,?)",
                        (request_id, kind, digest, json.dumps(result, sort_keys=True), now))

    def _idempotent(self, request_id, kind, digest):
        row = self._request(request_id)
        if row is None:
            return None
        if row["kind"] != kind or row["digest"] != digest:
            raise ValueError("Request ID was reused with changed contents")
        return json.loads(row["result"])

    # -- public reads ------------------------------------------------------
    def targets(self):
        return [dict(row) for row in self.db.execute("SELECT * FROM targets ORDER BY uuid")]

    def leases(self):
        return [dict(row) for row in self.db.execute("SELECT * FROM leases ORDER BY created_unix,lease_id")]

    def members(self):
        return [dict(row) for row in self.db.execute("SELECT * FROM members ORDER BY target_uuid")]

    def events(self):
        rows = []
        for row in self.db.execute("SELECT * FROM audit ORDER BY id"):
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            rows.append(item)
        return rows

    # -- discovery ---------------------------------------------------------
    def discover(self, target_uuid, *, channel, evidence, now=None):
        now = _clock(now)
        target = self._target(target_uuid)
        if channel not in DISCOVERY_CHANNELS:
            raise ValueError("Discovery channel is not allowed")
        if target["state"] != "dormant":
            raise ValueError("Only a dormant registered target can be discovered")
        if not isinstance(evidence, dict) or evidence.get("source") != channel:
            raise ValueError("Discovery evidence does not match its channel")
        if channel in ("inventory", "dhcp"):
            if evidence.get("mac") != target["mac"]:
                raise ValueError("Discovery evidence MAC mismatch")
            if channel == "dhcp":
                _int(evidence.get("lease_unix"), "DHCP lease time")
                if evidence["lease_unix"] > now:
                    raise ValueError("DHCP lease evidence is from the future")
        else:
            hello = evidence.get("hello")
            verify_target_hello(hello)
            if hello["target_uuid"] != target_uuid or hello["mac"] != target["mac"]:
                raise ValueError("Target hello binding mismatch")
        with self.db:
            self._set_target(target_uuid, "discovered", now)
            self._audit("discovered", target_uuid, {"channel": channel}, now)
        return self._target(target_uuid)

    # -- leasing -----------------------------------------------------------
    def request_lease(self, target_uuid, *, sponsor, request_id, now=None):
        now = _clock(now)
        target_uuid = _uuid(target_uuid, "target UUID")
        request_id = _uuid(request_id, "request UUID")
        sponsor = _text(sponsor, "sponsor", limit=64)
        payload = {"target_uuid": target_uuid, "sponsor": sponsor}
        digest = digest_json(payload)
        existing = self._idempotent(request_id, "lease-request", digest)
        if existing is not None:
            return existing
        target = self._target(target_uuid)
        if target["state"] != "discovered":
            raise ValueError("Only a discovered target may be leased")
        if target["attempts"] >= 3:
            raise ValueError("Target lease attempts are exhausted")
        if target["generation"] + 1 > self.policy["max_generation"]:
            raise ValueError("Target generation cap reached")
        if self._lease_for_target(target_uuid) is not None:
            raise ValueError("Target already has an active lease")
        if self._lease_for_sponsor(sponsor) is not None:
            raise ValueError("Sponsor already has an active child lease")
        if len(self._active_leases()) >= self.policy["max_active"]:
            raise ValueError("Active enrollment cap reached")
        result = {"request_id": request_id, "target_uuid": target_uuid, "sponsor": sponsor}
        with self.db:
            self._store_request(request_id, "lease-request", digest, result, now)
            self.db.execute("UPDATE targets SET attempts=attempts+1, updated_unix=? WHERE uuid=?", (now, target_uuid))
            self._audit("lease_requested", target_uuid, {"request_id": request_id, "sponsor": sponsor}, now)
        return result

    def grant_lease(self, request_id, lease_id, *, expires_unix, mother, now=None):
        now = _clock(now)
        self._require_mother(mother)
        request_id = _uuid(request_id, "request UUID")
        lease_id = _uuid(lease_id, "lease UUID")
        expires_unix = _int(expires_unix, "lease expiry")
        if not now < expires_unix <= now + 3600:
            raise ValueError("Lease expiry must be within one bounded hour")
        request = self._request(request_id)
        if request is None or request["kind"] != "lease-request":
            raise ValueError("Unknown lease request")
        if self.db.execute("SELECT 1 FROM leases WHERE lease_id=? OR request_id=?", (lease_id, request_id)).fetchone():
            raise ValueError("Lease or request was already consumed")
        result = json.loads(request["result"])
        target = self._target(result["target_uuid"])
        if target["state"] != "discovered":
            raise ValueError("Target is not in a leasable state")
        if target["generation"] + 1 > self.policy["max_generation"]:
            raise ValueError("Target generation cap reached")
        if self._lease_for_target(target["uuid"]) is not None:
            raise ValueError("Target already has an active lease")
        if self._lease_for_sponsor(result["sponsor"]) is not None:
            raise ValueError("Sponsor already has an active child lease")
        if len(self._active_leases()) >= self.policy["max_active"]:
            raise ValueError("Active enrollment cap reached")
        with self.db:
            self.db.execute(
                "INSERT INTO leases(lease_id,target_uuid,request_id,sponsor,generation,expires_unix,state,created_unix) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (lease_id, target["uuid"], request_id, result["sponsor"], target["generation"] + 1,
                 expires_unix, "active", now))
            self._audit("lease_granted", target["uuid"],
                        {"lease_id": lease_id, "request_id": request_id, "sponsor": result["sponsor"]}, now)
        return self._lease(lease_id)

    # -- invite / installation --------------------------------------------
    def create_invite(self, lease_id, *, package_sha256, model_sha256, torrent_infohash,
                      nonce, expires_unix, mother, now=None):
        now = _clock(now)
        self._require_mother(mother)
        lease = self._lease(lease_id)
        target = self._target(lease["target_uuid"])
        package_sha256 = _sha256(package_sha256, "package")
        model_sha256 = _sha256(model_sha256, "model")
        torrent_infohash = _infohash(torrent_infohash, "torrent")
        nonce = _uuid(nonce, "invite nonce")
        expires_unix = _int(expires_unix, "invite expiry")
        if not now < expires_unix <= now + 3600:
            raise ValueError("Invite expiry must be within one bounded hour")
        payload = {
            "schema": "garden.autoenroll.invite.v1",
            "request_id": lease["request_id"],
            "lease_id": lease["lease_id"],
            "garden": self.policy["garden"],
            "target_uuid": target["uuid"],
            "target_mac": target["mac"],
            "action": ACTIONS[0],
            "package_sha256": package_sha256,
            "model_sha256": model_sha256,
            "torrent_infohash": torrent_infohash,
            "nonce": nonce,
            "expires_unix": expires_unix,
            "mother_certificate": self.policy["mother_certificate"],
        }
        invite = {**payload, "mother_signature": mother.sign(payload)}
        if lease["invite_json"] is not None:
            stored = json.loads(lease["invite_json"])
            if stored == invite:
                return stored
            raise ValueError("Lease already has a different invite")
        if lease["state"] != "active":
            raise ValueError("Only an active lease can receive one invite")
        if target["state"] != "discovered":
            raise ValueError("Target is not awaiting an invite")
        with self.db:
            self._set_lease(lease["lease_id"], "invited",
                            invite_sha256=digest_json(invite), invite_json=json.dumps(invite, sort_keys=True))
            self._set_target(target["uuid"], "invited", now, lease_id=lease["lease_id"])
            self._audit("invite_signed", target["uuid"],
                        {"lease_id": lease["lease_id"], "invite_sha256": digest_json(invite)}, now)
        return invite

    def mark_installing(self, lease_id, *, evidence, mother, now=None):
        now = _clock(now)
        self._require_mother(mother)
        lease = self._lease(lease_id)
        if lease["state"] != "invited" or lease["invite_json"] is None:
            raise ValueError("Only an invited lease can start installing")
        _exact(evidence, INSTALLING_FIELDS, "Installing evidence")
        if evidence["transport"] not in ("mother-direct", "sub-agent-courier"):
            raise ValueError("Unknown invite transport")
        if evidence["invite_sha256"] != lease["invite_sha256"]:
            raise ValueError("Installation evidence invite hash mismatch")
        target = self._target(lease["target_uuid"])
        if target["state"] != "invited":
            raise ValueError("Target is not in the invited state")
        with self.db:
            self._set_lease(lease["lease_id"], "installing")
            self._set_target(target["uuid"], "installing", now)
            self._audit("install_started", target["uuid"],
                        {"lease_id": lease["lease_id"], "transport": evidence["transport"]}, now)
        return self._lease(lease["lease_id"])

    # -- receipt / admission ----------------------------------------------
    def record_receipt(self, invite, receipt, *, mother, now=None):
        now = _clock(now)
        self._require_mother(mother)
        verify_invite(invite, self.policy, now=now)
        lease = self._lease(invite["lease_id"])
        if lease["invite_sha256"] != digest_json(invite):
            raise ValueError("Receipt invite does not match the issued invite")
        target = self._target(invite["target_uuid"])
        receipt_key = "receipt:" + invite["request_id"]
        digest = digest_json(receipt)
        existing = self._idempotent(receipt_key, "receipt", digest)
        if existing is not None:
            return existing
        if target["state"] not in ("invited", "installing") or lease["state"] not in ("invited", "installing"):
            raise ValueError("Target is not awaiting a receipt")
        verify_receipt(receipt, invite, now=now)
        if self.db.execute("SELECT 1 FROM members WHERE target_uuid=?", (target["uuid"],)).fetchone():
            raise ValueError("Target is already a member")
        result = {"status": "joined", "target_uuid": target["uuid"],
                  "identity_fingerprint": receipt["identity_fingerprint"]}
        with self.db:
            self.db.execute(
                "INSERT INTO members(target_uuid,identity_fingerprint,target_public_key,joined_unix,verified) "
                "VALUES (?,?,?,?,0)",
                (target["uuid"], receipt["identity_fingerprint"], receipt["target_public_key"], now))
            self._set_lease_target_join(lease, target["uuid"], now)
            self._store_request(receipt_key, "receipt", digest, result, now)
            self._audit("receipt_verified", target["uuid"],
                        {"lease_id": lease["lease_id"], "request_id": invite["request_id"]}, now)
        return result

    def _set_lease_target_join(self, lease, target_uuid, now):
        self._set_lease(lease["lease_id"], "joined")
        self._set_target(target_uuid, "joined", now)

    def admit(self, target_uuid, *, mother, now=None):
        now = _clock(now)
        self._require_mother(mother)
        target = self._target(target_uuid)
        member = self.db.execute("SELECT * FROM members WHERE target_uuid=?", (target["uuid"],)).fetchone()
        if member is None:
            raise ValueError("Target has no verified receipt")
        if target["state"] == "verified" and member["verified"] == 1:
            return dict(member)
        if target["state"] != "joined":
            raise ValueError("Only a joined target can be admitted")
        with self.db:
            self.db.execute("UPDATE members SET verified=1 WHERE target_uuid=?", (target["uuid"],))
            self._set_target(target["uuid"], "verified", now)
            if target["lease_id"]:
                self._set_lease(target["lease_id"], "completed")
            self._audit("member_admitted", target["uuid"], {}, now)
        return dict(self.db.execute("SELECT * FROM members WHERE target_uuid=?", (target["uuid"],)).fetchone())

    # -- revocation / expiry ----------------------------------------------
    def revoke(self, target_uuid, *, reason, mother, now=None):
        now = _clock(now)
        self._require_mother(mother)
        target = self._target(target_uuid)
        if target["state"] in ("revoked", "failed", "expired"):
            return target
        reason = _text(reason, "revocation reason", limit=256)
        with self.db:
            self._set_target(target["uuid"], "revoked", now)
            if target["lease_id"]:
                self._set_lease(target["lease_id"], "revoked")
            self._audit("target_revoked", target["uuid"], {"reason": reason}, now)
        return self._target(target["uuid"])

    def expire(self, *, now=None):
        now = _clock(now)
        rows = [dict(row) for row in self.db.execute(
            "SELECT * FROM leases WHERE state IN (?,?,?) AND expires_unix<=?",
            (*ACTIVE_LEASE_STATES, now))]
        with self.db:
            for lease in rows:
                self._set_lease(lease["lease_id"], "expired")
                target = self._target(lease["target_uuid"])
                if target["state"] in ("discovered", "invited", "installing"):
                    self._set_target(target["uuid"], "expired", now)
                self._audit("lease_expired", target["uuid"], {"lease_id": lease["lease_id"]}, now)
        return len(rows)

    def _require_mother(self, mother):
        if mother is not self.mother or not isinstance(mother, MotherAuthority):
            raise ValueError("Only the mother authority may authorize this transition")
