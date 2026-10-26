"""Shared real-crypto fixtures for auto-enrollment host tests."""
from __future__ import annotations

import hashlib
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "guest"), str(ROOT / "tests")]

from agenticvm.autoenroll_inventory import (  # noqa: E402
    AutoEnrollInventory,
    MotherAuthority,
    canonical,
    identity_fingerprint,
    sign_canonical,
)
from agenticvm.lan_lab import OPENSSL  # noqa: E402


def _run(args):
    result = subprocess.run([str(OPENSSL), *args], capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError("OpenSSL fixture failed: " + result.stderr.decode(errors="replace")[-800:])
    return result


def generate_key(directory, name):
    directory = Path(directory)
    key, pub = directory / (name + ".key"), directory / (name + ".pub")
    _run(["genpkey", "-algorithm", "ed25519", "-out", str(key)])
    _run(["pkey", "-in", str(key), "-pubout", "-out", str(pub)])
    return key, pub.read_text()


def generate_cert_identity(directory, name):
    directory = Path(directory)
    key, cert, pub = directory / (name + ".key"), directory / (name + ".pem"), directory / (name + ".pub")
    _run(["req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "1",
          "-keyout", str(key), "-out", str(cert), "-subj", "/CN=" + name])
    _run(["pkey", "-in", str(key), "-pubout", "-out", str(pub)])
    return key, pub.read_text(), cert.read_text()


def allowed_targets(count=3):
    rows = []
    for index in range(1, count + 1):
        rows.append({
            "uuid": str(uuid4()),
            "mac": f"52:54:00:4c:41:{index:02x}",
            "image_sha256": hashlib.sha256(f"image-{index}".encode()).hexdigest(),
            "label": f"external-sim-{index}",
        })
    return rows


def signed_policy(owner_key, owner_public, mother_public, mother_cert, targets, *, now=None,
                  max_targets=3, max_active=2, max_generation=2, children_per_agent=1,
                  actions=None, expires_unix=None, garden=None):
    now = int(time.time()) if now is None else int(now)
    payload = {
        "schema": "garden.mother-policy.v1",
        "garden": garden or str(uuid4()),
        "mother_public_key": mother_public,
        "mother_certificate": mother_cert,
        "owner_public_key": owner_public,
        "allowed_targets": targets,
        "max_targets": max_targets,
        "max_active": max_active,
        "max_generation": max_generation,
        "children_per_agent": children_per_agent,
        "actions": ["install-and-join"] if actions is None else actions,
        "expires_unix": now + 3600 if expires_unix is None else int(expires_unix),
    }
    return {**payload, "owner_signature": sign_canonical(owner_key, payload)}


def resign_policy(policy, owner_key):
    payload = {key: value for key, value in policy.items() if key != "owner_signature"}
    return {**payload, "owner_signature": sign_canonical(owner_key, payload)}


def make_mother(policy, mother_key, mother_public):
    return MotherAuthority(policy, mother_key, mother_public)


def make_inventory(directory, policy, owner_public, mother, *, name="inventory.sqlite3"):
    path = Path(directory) / name
    return AutoEnrollInventory(path, policy=policy, owner_public_key=owner_public, mother=mother)


def target_row(policy, index=0):
    return dict(policy["allowed_targets"][index])


def make_standalone_invite(policy, mother, target, *, now=None, request_id=None, lease_id=None,
                           package_sha256=None, model_sha256=None, torrent_infohash=None,
                           nonce=None, expires_unix=None):
    now = int(time.time()) if now is None else int(now)
    payload = {
        "schema": "garden.autoenroll.invite.v1",
        "request_id": request_id or str(uuid4()),
        "lease_id": lease_id or str(uuid4()),
        "garden": policy["garden"],
        "target_uuid": target["uuid"],
        "target_mac": target["mac"],
        "action": "install-and-join",
        "package_sha256": package_sha256 or hashlib.sha256(b"package").hexdigest(),
        "model_sha256": model_sha256 or hashlib.sha256(b"model").hexdigest(),
        "torrent_infohash": torrent_infohash or hashlib.sha256(b"torrent").hexdigest(),
        "nonce": nonce or str(uuid4()),
        "expires_unix": now + 600 if expires_unix is None else int(expires_unix),
        "mother_certificate": policy["mother_certificate"],
    }
    return {**payload, "mother_signature": mother.sign(payload)}


def make_receipt(invite, target_key, target_public, *, now=None, torrent_receipt=None,
                 initial_absence=None, boot_id=None, zero_click=True, interactive_input=False,
                 signed_unix=None):
    now = int(time.time()) if now is None else int(now)
    receipt = {
        "schema": "garden.autoenroll.receipt.v1",
        "request_id": invite["request_id"],
        "lease_id": invite["lease_id"],
        "target_uuid": invite["target_uuid"],
        "target_mac": invite["target_mac"],
        "action": invite["action"],
        "package_sha256": invite["package_sha256"],
        "model_sha256": invite["model_sha256"],
        "torrent_infohash": invite["torrent_infohash"],
        "torrent_receipt": torrent_receipt or {
            "peer": "target", "bytes": 1024, "trackers": 0, "dht": False, "pex": False,
        },
        "identity_fingerprint": identity_fingerprint(target_public),
        "target_public_key": target_public,
        "initial_absence": initial_absence or {
            "peer/lan_agent.py": False, "model.gguf": False, "identity.key": False, "lan-config.json": False,
        },
        "boot_id": boot_id or str(uuid4()),
        "zero_click": zero_click,
        "interactive_input": interactive_input,
        "signed_unix": now if signed_unix is None else int(signed_unix),
    }
    return {**receipt, "target_signature": sign_canonical(target_key, receipt)}


def make_hello(target, target_key, target_public, *, now=None, nonce=None):
    now = int(time.time()) if now is None else int(now)
    payload = {
        "schema": "garden.target-hello.v1",
        "target_uuid": target["uuid"],
        "mac": target["mac"],
        "nonce": nonce or str(uuid4()),
        "timestamp": now,
        "public_key": target_public,
    }
    return {**payload, "signature": sign_canonical(target_key, payload)}


def policy_digest(policy):
    return hashlib.sha256(canonical(policy)).hexdigest()
