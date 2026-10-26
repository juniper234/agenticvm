"""Prepare pinned official Android tools locally; no global SDK or host changes."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import shutil
import sys
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def digest(path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def fetch(item, cache):
    target = cache / item["url"].rsplit("/", 1)[1]
    if not target.exists():
        partial = target.with_suffix(".partial-" + str(uuid4()))
        print("Downloading " + item["name"], flush=True)
        with urllib.request.urlopen(item["url"], timeout=60) as source, partial.open("xb") as out:
            shutil.copyfileobj(source, out, 1024 * 1024)
        if partial.stat().st_size != item["size"] or digest(partial, "sha1") != item["sha1"]:
            raise ValueError("Publisher digest mismatch: " + str(partial))
        partial.rename(target)
    if target.stat().st_size != item["size"] or digest(target, "sha1") != item["sha1"]:
        raise ValueError("Cached publisher digest mismatch: " + str(target))
    return {**item, "archive_sha256": digest(target), "archive": str(target)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download", action="store_true", help="Download and extract the pinned free SDK assets")
    args = parser.parse_args()
    lock = json.loads((ROOT / "tools/android-lock.json").read_text())
    if not args.download:
        print(json.dumps(lock, indent=2))
        return 0
    cache, sdk = ROOT / "downloads/android", ROOT / "tools/android/sdk"
    cache.mkdir(parents=True, exist_ok=True)
    sdk.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(sdk).free < 10 * 1024**3:
        raise RuntimeError("Android preparation requires 10 GiB free disk")
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        sources = list(pool.map(lambda item: fetch(item, cache), lock["sources"]))
    for item in sources:
        destination = sdk / item["destination"]
        if destination.exists():
            print("Preserving existing " + str(destination), flush=True)
            continue
        staging = sdk / (".prepare-" + str(uuid4()))
        staging.mkdir()
        with zipfile.ZipFile(item["archive"]) as archive:
            for member in archive.infolist():
                parts = PurePosixPath(member.filename).parts
                if not parts or ".." in parts or ":" in member.filename or "\\" in member.filename or member.filename.startswith("/"):
                    raise ValueError("Unsafe archive member")
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Archive symlinks are not supported")
            archive.extractall(staging)
        destination.parent.mkdir(parents=True, exist_ok=True)
        (staging / item["archive_root"]).rename(destination)
        print("Prepared " + item["name"], flush=True)
    pins = {}
    for item in sources:
        for path in sorted((sdk / item["destination"]).rglob("*")):
            if path.is_file():
                pins[str(path.relative_to(sdk)).replace("\\", "/")] = {"size": path.stat().st_size, "sha256": digest(path)}
    receipt = {"schema": "agenticvm.android-prepared.v1", "prepared_at": time.time(), "sdk": str(sdk),
               "sources": sources, "files": pins, "source_lock_sha256": digest(ROOT / "tools/android-lock.json")}
    output = sdk.parent / "prepared.json"
    if output.exists():
        previous = json.loads(output.read_text())
        if previous["files"] != pins:
            raise RuntimeError("Existing SDK differs from its receipt; preserving both for investigation")
    else:
        output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"prepared": True, "receipt": str(output), "files": len(pins), "sources": sources}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
