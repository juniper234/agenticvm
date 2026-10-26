"""Alpine APK v2 signature and dependency closure handling for the desktop image.

Trust roots come from the SHA256-verified Alpine release ISO. RSA PKCS#1 v1.5
signatures protect the compressed index/control member, whose SHA256 datahash
protects each compressed package payload. No downloaded program runs on Windows.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import urllib.request
import zlib

BASE = "https://dl-cdn.alpinelinux.org/alpine/v3.24"


def fetch(url, destination, expected=None, limit=256 * 1024 * 1024):
    destination = Path(destination)
    if destination.exists():
        data = destination.read_bytes()
    else:
        request = urllib.request.Request(url, headers={"User-Agent": "AgenticVM-desktop-builder/0.1"})
        with urllib.request.urlopen(request, timeout=90) as response:
            if int(response.headers.get("Content-Length", "0")) > limit:
                raise ValueError("Download exceeds configured input bound")
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Download exceeds configured input bound")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    if expected and hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Pinned SHA256 mismatch: " + str(destination))
    return data


def first_member(data):
    obj = zlib.decompressobj(31)
    plain = obj.decompress(data, 32 * 1024 * 1024)
    if not obj.eof:
        raise ValueError("Oversized or invalid gzip control member")
    return data[:len(data) - len(obj.unused_data)], plain, obj.unused_data


def tlv(data, offset=0):
    tag, count = data[offset:offset + 2]
    header = 2
    if count & 128:
        header += count & 127
        count = int.from_bytes(data[offset + 2:offset + header], "big")
    end = offset + header + count
    if end > len(data):
        raise ValueError("Truncated public key")
    return tag, data[offset + header:end], end


def signature_verify(data, signature, pem):
    der = base64.b64decode(b"".join(pem.splitlines()[1:-1]), validate=True)
    _, spki, _ = tlv(der)
    _, _, offset = tlv(spki)
    _, bits, _ = tlv(spki, offset)
    _, rsa, _ = tlv(bits[1:])
    _, modulus, offset = tlv(rsa)
    _, exponent, _ = tlv(rsa, offset)
    modulus, exponent = int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")
    size = (modulus.bit_length() + 7) // 8
    if size < 256 or len(signature) != size or int.from_bytes(signature, "big") >= modulus:
        raise ValueError("Invalid RSA signature size/range")
    decoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(size, "big")
    digest_info = bytes.fromhex("3021300906052b0e03021a05000414") + hashlib.sha1(data).digest()
    expected = b"\0\1" + b"\xff" * (size - len(digest_info) - 3) + b"\0" + digest_info
    if decoded != expected:
        raise ValueError("Alpine RSA signature verification failed")


def signed_member(data, keys):
    signature_gz, signature_tar, rest = first_member(data)
    with tarfile.open(fileobj=io.BytesIO(signature_tar), mode="r:") as archive:
        signatures = [m for m in archive if m.name.startswith(".SIGN.RSA.") and m.isfile()]
        if not signatures:
            raise ValueError("Unsigned APK/index rejected")
        for member in signatures:
            name = member.name.removeprefix(".SIGN.RSA.")
            if name in keys:
                signature = archive.extractfile(member).read()
                compressed, plain, payload = first_member(rest)
                signature_verify(compressed, signature, keys[name])
                return compressed, plain, payload, name
    raise ValueError("APK signature does not use a trusted release key")


def records(index):
    result = []
    for paragraph in index.decode("utf-8").strip().split("\n\n"):
        item = dict(line.split(":", 1) for line in paragraph.splitlines() if ":" in line)
        if "P" in item:
            result.append(item)
    return result


def parse_dep(text):
    return re.split(r"([<>=~]+)", text, maxsplit=1)[0]


def resolve(all_records, requested):
    by_name = {item["P"]: item for item in all_records}
    providers = {}
    for item in all_records:
        providers.setdefault(item["P"], []).append(item)
        for provided in item.get("p", "").split():
            providers.setdefault(parse_dep(provided), []).append(item)
    selected, pending = {}, list(requested)
    while True:
        while pending:
            dep = pending.pop(0)
            if dep.startswith("!"):
                continue
            name = parse_dep(dep)
            if name in selected or any(parse_dep(p) == name for item in selected.values()
                                       for p in item.get("p", "").split()):
                continue
            matches = providers.get(name, [])
            if not matches:
                raise ValueError("No package provider for " + dep)
            # The stable branch has one current version per package. Prefer a real
            # package name; otherwise the smallest provider avoids optional servers.
            chosen = by_name.get(name) or min(matches, key=lambda i: (int(i.get("I", 0)), i["P"]))
            if chosen["P"] not in selected:
                selected[chosen["P"]] = chosen
                pending += chosen.get("D", "").split()
        # APK's conditional packages are not plain dependencies. In particular,
        # Alpine 3.24 installs glycin's SVG/bitmap loaders when libglycin appears.
        # Honor positive install_if clauses after the ordinary closure stabilizes.
        installed = set(selected)
        installed.update(parse_dep(p) for item in selected.values() for p in item.get("p", "").split())
        conditional = [item["P"] for item in all_records if item["P"] not in selected and item.get("i")
                       and all(not dep.startswith("!") and parse_dep(dep) in installed for dep in item["i"].split())]
        if not conditional:
            break
        pending += conditional
    return selected


def prepare_packages(cache, keys, requested, lock_path, allow_new_packages=False, allow_package_changes=False):
    cache, lock_path = Path(cache), Path(lock_path)
    old = json.loads(lock_path.read_text("utf-8")) if lock_path.exists() else None
    all_records, index_info = [], []
    for repo in ("main", "community"):
        name = repo + "-APKINDEX.tar.gz"
        expected = next((i["sha256"] for i in old["indexes"] if i["repository"] == repo), None) if old else None
        data = fetch(BASE + "/" + repo + "/x86_64/APKINDEX.tar.gz", cache / name, expected, 8 * 1024 * 1024)
        _, body, tail, signer = signed_member(data, keys)
        if tail:
            raise ValueError("Unexpected unsigned trailing index member")
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as archive:
            parsed = records(archive.extractfile("APKINDEX").read())
        for item in parsed:
            item["repository"] = repo
        all_records += parsed
        index_info.append({"repository": repo, "sha256": hashlib.sha256(data).hexdigest(), "signer": signer})
    chosen = resolve(all_records, requested)
    old_pins = {(i["name"], i["version"]) for i in old["packages"]} if old else set()
    new_pins = {(i["P"], i["V"]) for i in chosen.values()}
    old_versions = dict(old_pins)
    retained_pins_match = all(old_versions.get(name, version) == version for name, version in new_pins)
    permitted = (allow_new_packages and old_pins <= new_pins) or (allow_package_changes and retained_pins_match)
    if old and old_pins != new_pins and not permitted:
        raise ValueError("Resolved packages differ from lock; reviewed --add-packages is required for additions")

    def download(item):
        filename = item["P"] + "-" + item["V"] + ".apk"
        url = BASE + "/" + item["repository"] + "/x86_64/" + filename
        existing = next((p["sha256"] for p in old["packages"] if p["name"] == item["P"]), None) if old else None
        path = cache / "packages" / filename
        data = fetch(url, path, existing)
        control, plain, payload, signer = signed_member(data, keys)
        checksum = "Q1" + base64.b64encode(hashlib.sha1(control).digest()).decode("ascii")
        if checksum != item["C"]:
            raise ValueError("Signed index package checksum mismatch: " + filename)
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as archive:
            info = archive.extractfile(".PKGINFO").read().decode("utf-8")
        fields = dict(line.split(" = ", 1) for line in info.splitlines() if " = " in line)
        if fields.get("datahash") != hashlib.sha256(payload).hexdigest():
            raise ValueError("Signed payload SHA256 mismatch: " + filename)
        return {"name": item["P"], "version": item["V"], "repository": item["repository"],
                "url": url, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                "datahash": fields["datahash"], "signer": signer, "path": str(path),
                "dependencies": item.get("D", "").split(), "license": item.get("L", "UNKNOWN"),
                "origin": item.get("o", item["P"]), "source_commit": item.get("c"),
                "homepage": item.get("U")}

    with ThreadPoolExecutor(max_workers=4) as pool:
        packages = sorted(pool.map(download, chosen.values()), key=lambda i: i["name"])
    lock = {"format": 1, "os": "Alpine Linux", "release": "3.24.2", "branch": "v3.24",
            "architecture": "x86_64", "requested": requested, "indexes": index_info,
            "trust": "Alpine release ISO keys; APK RSA-SHA1 signed control/index and SHA256 datahash",
            "packages": [{k: v for k, v in p.items() if k != "path"} for p in packages]}
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", "utf-8")
    return packages, lock


def package_payload(path):
    data = Path(path).read_bytes()
    _, _, rest = first_member(data)
    _, _, payload = first_member(rest)
    return payload
