"""Verified Debian 13 desktop package inputs; downloaded programs never run.

Trust: pinned official archive key bytes/fingerprints -> gpgv InRelease ->
SHA256 Packages.xz -> SHA256 .deb. GnuPG state is private to the cache.
The resolver deliberately includes Debian Essential packages and ignores
Recommends/Suggests. It is a bootstrap resolver, not a replacement for apt.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import email.utils
from functools import cmp_to_key
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
GPG = Path(r"C:\Program Files\Git\usr\bin\gpg.exe")
GPGV = GPG.with_name("gpgv.exe")
KEYS = {
    "archive-key-12.asc": ("B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8", "c2a9a16fde95e037bafd0fa6b7e31f41b4ff1e85851de5558f19a2a2f0e955e2"),
    "archive-key-12-security.asc": ("05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0", "74f81645b4e3156d1e9a88c8dd9259271b89c7099d64af89a2a6996b592faa1f"),
    "archive-key-13.asc": ("04B54C3CDCA79751B16BC6B5225629DF75B188BD", "6f1d277429dd7ffedcc6f8688a7ad9a458859b1139ffa026d1eeaadcbffb0da7"),
    "archive-key-13-security.asc": ("5E04A1E3223A19A20706E20F9904613D4CCE68C6", "844c07d242db37f283afab9d5531270a0550841e90f9f1a9c3bd599722b808b7"),
    "release-13.asc": ("41587F7DB8C774BCCF131416762F67A0B2C39DE4", "4d097bb93f83d731f475c5b92a0c2fcf108cfce1d4932792fca72d00b48d198b"),
}
REPOSITORIES = {
    "trixie": "https://deb.debian.org/debian/",
    "trixie-security": "https://security.debian.org/debian-security/",
}
BROWSER_VERSION = "153.5.0esr-1~deb13u1"


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fetch(url, path, expected=None, size=None, limit=256 * 1024 * 1024):
    path = Path(path)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".partial")
        request = urllib.request.Request(url, headers={"User-Agent": "AgenticVM-desktop-builder/0.1"})
        count = 0
        try:
            with urllib.request.urlopen(request, timeout=60) as source, temporary.open("wb") as target:
                if int(source.headers.get("Content-Length", "0")) > limit:
                    raise ValueError("Download exceeds configured input limit")
                while chunk := source.read(1024 * 1024):
                    count += len(chunk)
                    if count > limit:
                        raise ValueError("Download exceeds configured input limit")
                    target.write(chunk)
            if (size is not None and count != size) or (expected and sha256(temporary) != expected):
                raise ValueError("Downloaded size/SHA256 mismatch: " + url)
            temporary.replace(path)
        finally:
            if temporary.exists():
                temporary.unlink()
    if path.stat().st_size > limit or (size is not None and path.stat().st_size != size):
        raise ValueError("Cached input size mismatch: " + str(path))
    if expected and sha256(path) != expected:
        raise ValueError("Cached SHA256 mismatch: " + str(path))
    return path


def msys(path):
    value = str(Path(path).resolve())
    return "/" + value[0].lower() + value[2:].replace("\\", "/")


def gpg_run(executable, home, *arguments):
    environment = dict(os.environ, GNUPGHOME=msys(home))
    result = subprocess.run([str(executable), *arguments], env=environment, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=30)
    if result.returncode:
        raise ValueError("Isolated GPG verification failed: " + result.stdout + result.stderr)
    return result


def paragraphs(data):
    result = []
    for paragraph in data.decode("utf-8").split("\n\n"):
        item, key = {}, None
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")) and key:
                item[key] += "\n" + line[1:]
            elif ": " in line:
                key, value = line.split(": ", 1)
                item[key] = value
        if "Package" in item:
            result.append(item)
    return result


def signed_indexes(cache, old=None):
    cache = Path(cache)
    home = cache / "gnupg"
    home.mkdir(parents=True, exist_ok=True)
    bootstrap = ROOT / "runtime/debian-source-check"
    key_info = []
    for name, (fingerprint, digest) in KEYS.items():
        target = cache / name
        if not target.exists() and (bootstrap / name).is_file():
            shutil.copyfile(bootstrap / name, target)
        url = "https://ftp-master.debian.org/keys/" + name
        fetch(url, target, digest, limit=64 * 1024)
        shown = gpg_run(GPG, home, "--no-options", "--homedir", msys(home), "--batch", "--with-colons", "--show-keys", msys(target))
        fingerprints = [line.split(":")[9] for line in shown.stdout.splitlines() if line.startswith("fpr:")]
        if not fingerprints or fingerprints[0] != fingerprint:
            raise ValueError("Unexpected archive key fingerprint: " + name)
        gpg_run(GPG, home, "--no-options", "--homedir", msys(home), "--batch", "--yes", "--output", msys(cache / (name + ".gpg")), "--dearmor", msys(target))
        key_info.append({"name": name, "url": url, "sha256": digest, "fingerprint": fingerprint})
    keyring = cache / "debian-archive-keyring.gpg"
    keyring.write_bytes(b"".join((cache / (name + ".gpg")).read_bytes() for name in KEYS))
    all_records, indexes = [], []
    for suite, base in REPOSITORIES.items():
        name = suite + ".InRelease"
        path = cache / name
        if not path.exists() and (bootstrap / name).is_file():
            shutil.copyfile(bootstrap / name, path)
        prior = next((row for row in old.get("indexes", []) if row["repository"] == suite), None) if old else None
        release_url = base + "dists/" + suite + "/InRelease"
        fetch(release_url, path, prior["release_sha256"] if prior else None, limit=2 * 1024 * 1024)
        verified = gpg_run(GPGV, home, "--homedir", msys(home), "--status-fd", "1", "--keyring", msys(keyring), msys(path))
        required = KEYS["archive-key-13-security.asc" if suite.endswith("security") else "archive-key-13.asc"][0]
        signatures = [line.split() for line in verified.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        if not any(line[-1] == required for line in signatures):
            raise ValueError("Missing required Debian 13 archive signature")
        text = path.read_text("utf-8")
        fields = dict(re.findall(r"^([A-Za-z-]+): (.*)$", text, re.M))
        if fields.get("Codename") != suite:
            raise ValueError("Unexpected Debian release codename")
        now = dt.datetime.now(dt.timezone.utc)
        if email.utils.parsedate_to_datetime(fields["Date"]) > now + dt.timedelta(hours=24):
            raise ValueError("Release metadata is in the future")
        if "Valid-Until" in fields and email.utils.parsedate_to_datetime(fields["Valid-Until"]) < now:
            raise ValueError("Release metadata expired; refresh and review package pins")
        match = re.search(r"^ ([a-f0-9]{64}) +(\d+) +main/binary-amd64/Packages.xz$", text, re.M)
        if not match:
            raise ValueError("Missing signed SHA256 Packages index entry")
        index_path = cache / (suite + ".Packages.xz")
        if not index_path.exists() and (bootstrap / index_path.name).is_file():
            shutil.copyfile(bootstrap / index_path.name, index_path)
        index_url = base + "dists/" + suite + "/main/binary-amd64/Packages.xz"
        fetch(index_url, index_path, match[1], int(match[2]), 32 * 1024 * 1024)
        # A bounded streaming decompressor limits malformed input expansion.
        with lzma.open(index_path, "rb") as source:
            plain = source.read(96 * 1024 * 1024 + 1)
        if len(plain) > 96 * 1024 * 1024:
            raise ValueError("Decompressed Packages index exceeds input bound")
        records = paragraphs(plain)
        for item in records:
            item["repository"] = suite
        all_records.extend(records)
        indexes.append({"repository": suite, "release_url": release_url, "release_sha256": sha256(path),
                        "date": fields["Date"], "valid_until": fields.get("Valid-Until"), "version": fields.get("Version"),
                        "url": index_url, "sha256": match[1], "bytes": int(match[2]),
                        "valid_signatures": verified.stdout.splitlines()})
    return all_records, indexes, key_info


def version_compare(left, right):
    def split(value):
        epoch, rest = value.split(":", 1) if ":" in value else ("0", value)
        upstream, revision = rest.rsplit("-", 1) if "-" in rest else (rest, "0")
        return int(epoch), upstream, revision

    def part(a, b):
        def order(char):
            return -1 if char == "~" else 0 if not char else ord(char) if char.isalpha() else ord(char) + 256
        while a or b:
            while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
                ca, cb = a[0] if a else "", b[0] if b else ""
                # Digits behave like the end of a non-digit run.
                oa, ob = order(ca) if not ca.isdigit() else 0, order(cb) if not cb.isdigit() else 0
                if oa != ob:
                    return (oa > ob) - (oa < ob)
                a, b = a[1:] if a else a, b[1:] if b else b
            na = re.match(r"\d*", a)[0]
            nb = re.match(r"\d*", b)[0]
            sa, sb = na.lstrip("0"), nb.lstrip("0")
            if len(sa) != len(sb):
                return (len(sa) > len(sb)) - (len(sa) < len(sb))
            if sa != sb:
                return (sa > sb) - (sa < sb)
            a, b = a[len(na):], b[len(nb):]
        return 0

    ea, ua, ra = split(left)
    eb, ub, rb = split(right)
    return ((ea > eb) - (ea < eb)) if ea != eb else (part(ua, ub) or part(ra, rb))


def dependency(text):
    match = re.fullmatch(r"\s*([a-z0-9][a-z0-9+.-]*)(?::[a-z0-9-]+)?\s*(?:\((<<|<=|=|>=|>>)\s*([^()]+)\))?\s*", text)
    if not match:
        raise ValueError("Unsupported binary dependency syntax: " + text)
    return match[1], match[2], match[3]


def satisfies(version, operator, target):
    if operator is None:
        return True
    if version is None:
        return False
    comparison = version_compare(version, target)
    return {"<<": comparison < 0, "<=": comparison <= 0, "=": comparison == 0,
            ">=": comparison >= 0, ">>": comparison > 0}[operator]


def resolve(records, requested):
    by_name, providers = {}, {}
    for item in records:
        if item.get("Architecture") not in ("amd64", "all"):
            continue
        by_name.setdefault(item["Package"], []).append(item)
        for provided in item.get("Provides", "").split(","):
            if provided.strip():
                name, operator, version = dependency(provided)
                providers.setdefault(name, []).append((item, version if operator else None))
    for versions in by_name.values():
        versions.sort(key=cmp_to_key(lambda a, b: version_compare(b["Version"], a["Version"]) or
                                    ((b["repository"] > a["repository"]) - (b["repository"] < a["repository"]))))
    selected = {}

    def options(name, operator, target):
        actual = [(item, item["Version"]) for item in by_name.get(name, [])]
        virtual = sorted(providers.get(name, []), key=lambda pair: (int(pair[0].get("Installed-Size", "0")), pair[0]["Package"]))
        return [(item, version) for item, version in actual + virtual if satisfies(version, operator, target)]

    def selected_matches(group):
        for alternative in group.split("|"):
            for item, _ in options(*dependency(alternative)):
                if item["Package"] in selected and selected[item["Package"]]["Version"] == item["Version"]:
                    return True
        return False

    essentials = sorted(name for name, versions in by_name.items() if any(item.get("Essential") == "yes" for item in versions))
    pending = [(name, "requested") for name in list(requested) + essentials]
    while pending:
        group, parent = pending.pop(0)
        if selected_matches(group):
            continue
        chosen = None
        for alternative in group.split("|"):
            for candidate, _ in options(*dependency(alternative)):
                existing = selected.get(candidate["Package"])
                if existing is None or existing["Version"] == candidate["Version"]:
                    chosen = candidate
                    break
            if chosen:
                break
        if chosen is None:
            raise ValueError("Unsatisfied/conflicting dependency " + group + " required by " + parent)
        selected[chosen["Package"]] = chosen
        for field in ("Pre-Depends", "Depends"):
            pending.extend((group.strip(), chosen["Package"]) for group in chosen.get(field, "").split(",") if group.strip())
    for item in selected.values():
        for field in ("Pre-Depends", "Depends"):
            for group in item.get(field, "").split(","):
                if group.strip() and not selected_matches(group):
                    raise ValueError("Final dependency closure validation failed: " + group)
    return selected, essentials


def package_payload(path):
    """Return the compressed data.tar payload from a Debian ar container."""
    with Path(path).open("rb") as source:
        if source.read(8) != b"!<arch>\n":
            raise ValueError("Invalid Debian ar header")
        while header := source.read(60):
            if len(header) != 60 or header[58:60] != b"`\n":
                raise ValueError("Invalid/truncated Debian ar member")
            name = header[:16].decode("ascii").strip().rstrip("/")
            size = int(header[48:58].decode("ascii").strip())
            if size < 0 or size > 256 * 1024 * 1024:
                raise ValueError("Debian member exceeds input bound")
            if name.startswith("data.tar"):
                payload = source.read(size)
                if len(payload) != size:
                    raise ValueError("Truncated Debian data member")
                if name not in ("data.tar", "data.tar.xz", "data.tar.gz", "data.tar.bz2"):
                    raise ValueError("Unsupported Debian payload compression: " + name)
                return payload
            source.seek(size + (size % 2), 1)
    raise ValueError("Debian package lacks data.tar payload")


def package_members(path):
    with tarfile.open(fileobj=io.BytesIO(package_payload(path)), mode="r|*") as archive:
        for member in archive:
            yield member, archive.extractfile(member) if member.isfile() else None


def prepare_packages(cache, requested, lock_path, allow_new_packages=False, allow_package_changes=False):
    cache, lock_path = Path(cache), Path(lock_path)
    previous = json.loads(lock_path.read_text("utf-8")) if lock_path.exists() else None
    old = previous if previous and previous.get("os") == "Debian GNU/Linux" else None
    records, indexes, key_info = signed_indexes(cache, old)
    chosen, essentials = resolve(records, requested)
    if "firefox-esr" in chosen and (chosen["firefox-esr"]["Version"] != BROWSER_VERSION or
                                     chosen["firefox-esr"]["repository"] != "trixie-security"):
        raise ValueError("Firefox must match the reviewed Debian security release " + BROWSER_VERSION)
    old_pins = {(item["name"], item["version"], item["sha256"]) for item in old["packages"]} if old else set()
    new_pins = {(item["Package"], item["Version"], item["SHA256"]) for item in chosen.values()}
    if old and old_pins != new_pins and not (allow_package_changes or (allow_new_packages and old_pins <= new_pins)):
        raise ValueError("Debian package closure differs from reviewed lock")

    def download(item):
        name, filename = item["Package"], item["Filename"]
        if not filename.startswith("pool/") or not re.fullmatch(r"[a-zA-Z0-9_+~./-]+\.deb", filename) or ".." in filename.split("/"):
            raise ValueError("Unsafe Debian package filename")
        url = REPOSITORIES[item["repository"]] + filename
        path = cache / "packages" / (item["SHA256"][:12] + "-" + Path(filename).name)
        bootstrap = ROOT / "runtime/debian-source-check" / Path(filename).name
        if not path.exists() and bootstrap.is_file():
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(bootstrap, path)
        fetch(url, path, item["SHA256"], int(item["Size"]))
        dependencies = [group.strip() for field in ("Pre-Depends", "Depends") for group in item.get(field, "").split(",") if group.strip()]
        return {"name": name, "version": item["Version"], "architecture": item["Architecture"],
                "repository": item["repository"], "url": url, "sha256": item["SHA256"],
                "bytes": int(item["Size"]), "installed_bytes": int(item.get("Installed-Size", "0")) * 1024,
                "path": str(path), "dependencies": dependencies,
                "license": "Debian-package-copyright:/usr/share/doc/" + name + "/copyright",
                "origin": item.get("Source", name), "source_commit": None, "homepage": item.get("Homepage")}

    with ThreadPoolExecutor(max_workers=4) as pool:
        packages = sorted(pool.map(download, chosen.values()), key=lambda item: item["name"])
    lock = {"format": 2, "os": "Debian GNU/Linux", "release": "13", "codename": "trixie",
            "architecture": "amd64", "requested": list(requested), "essential": essentials,
            "trust": "Pinned Debian archive keys; gpgv InRelease; SHA256 Packages.xz and .deb",
            "keys": key_info, "indexes": indexes,
            "packages": [{key: value for key, value in item.items() if key != "path"} for item in packages]}
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", "utf-8")
    return packages, lock
