"""Check or restore pinned, workspace-local Windows build tools.

--check is read-only. --download permits HTTPS downloads and extraction beneath
this workspace. Installers are treated as archives; none are executed. Existing
valid tools remain untouched, and replaced directories are retained as backups.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "tools/build-tools-lock.json"
MIB = 1024 * 1024


def digest(path, algorithm="sha256"):
    value = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            value.update(chunk)
    return value.hexdigest()


def safe(root, relative):
    """Resolve only plain relative paths, rejecting junctions and symlinks."""
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    if not parts or any(p in (".", "..") or ":" in p for p in parts) or parts[0] == "/":
        raise ValueError("Unsafe relative path: " + relative)
    target = root.joinpath(*parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("Path escapes owned directory: " + str(target))
    for parent in (target, *target.parents):
        if parent == root.parent:
            break
        if parent.is_symlink() or (parent.exists() and os.path.isjunction(parent)):
            raise ValueError("Reparse point refused: " + str(parent))
    return target


def check_payload(name, spec, destination):
    if not destination.is_dir():
        return {"ready": False, "reason": "missing payload directory"}
    if name == "zig":
        tree, count, size = hashlib.sha256(), 0, 0
        files = []
        # Check each directory once; repeatedly resolving all ancestors of
        # 18,105 small files is particularly slow on Windows antivirus scans.
        for parent, directories, filenames in os.walk(destination, followlinks=False):
            for child in directories + filenames:
                path = Path(parent) / child
                if path.is_symlink() or os.path.isjunction(path):
                    return {"ready": False, "reason": "Zig tree contains a reparse point"}
            files.extend(Path(parent) / filename for filename in filenames)
        for path in sorted(files, key=lambda p: p.relative_to(destination).as_posix()):
            relative = path.relative_to(destination).as_posix()
            length = path.stat().st_size
            size += length
            if size > spec["max_unpacked_bytes"] or count >= spec["file_count"]:
                return {"ready": False, "reason": "unexpected Zig file count or byte total"}
            tree.update((relative + "\0" + str(length) + "\0" + digest(path) + "\n").encode("utf-8"))
            count += 1
        ok = count == spec["file_count"] and size == spec["unpacked_bytes"] and tree.hexdigest() == spec["tree_sha256"]
        return {"ready": ok, "files_checked": count, "bytes_checked": size,
                "reason": "verified full Zig tree" if ok else "Zig tree differs from lock"}
    checked = 0
    for item in spec["files"]:
        path = safe(destination, item["path"])
        if not path.is_file() or path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            return {"ready": False, "reason": "missing or different payload: " + item["path"]}
        checked += 1
    return {"ready": True, "files_checked": checked, "reason": "verified pinned payload files"}


def acquire(spec, report):
    archive = safe(ROOT, spec["archive"])
    if archive.exists() and archive.stat().st_size == spec["bytes"] and digest(archive, spec["algorithm"]) == spec["digest"]:
        return archive
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        backup = archive.with_name(archive.name + ".invalid-" + uuid.uuid4().hex[:8])
        archive.rename(backup)
        report.setdefault("retained_backups", []).append(str(backup))
    partial = archive.with_name(archive.name + ".part-" + uuid.uuid4().hex[:8])
    hashed, total = hashlib.new(spec["algorithm"]), 0
    request = urllib.request.Request(spec["url"], headers={"User-Agent": "AgenticVM-local-build-tools/1"})
    with urllib.request.urlopen(request, timeout=45) as source, partial.open("xb") as target:
        if not source.url.startswith("https://"):
            raise RuntimeError("Download redirected away from HTTPS")
        while chunk := source.read(MIB):
            total += len(chunk)
            if total > spec["bytes"] or total > 250 * MIB:
                raise RuntimeError("Download exceeds pinned byte budget")
            hashed.update(chunk)
            target.write(chunk)
    if total != spec["bytes"] or hashed.hexdigest() != spec["digest"]:
        raise RuntimeError("Downloaded size or published digest differs from lock: " + str(partial))
    partial.rename(archive)
    report["downloaded_archive"] = str(archive)
    return archive


def extract_zig(archive, spec, stage):
    with zipfile.ZipFile(archive) as package:
        entries = [item for item in package.infolist() if not item.is_dir()]
        if len(entries) != spec["file_count"] or sum(i.file_size for i in entries) > spec["max_unpacked_bytes"]:
            raise ValueError("Zig ZIP exceeds pinned extraction budget")
        seen = set()
        for item in entries:
            if not item.filename.startswith(spec["archive_root"] + "/") or (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Unexpected ZIP root or symlink")
            relative = item.filename[len(spec["archive_root"]) + 1:]
            target = safe(stage, relative)
            if str(target).casefold() in seen:
                raise ValueError("Duplicate ZIP destination")
            seen.add(str(target).casefold())
            target.parent.mkdir(parents=True, exist_ok=True)
            with package.open(item) as source, target.open("xb") as destination:
                shutil.copyfileobj(source, destination, MIB)


def extract_7zip(archive, spec, stage, scratch):
    # Bind only the repository's existing read-only MSI/CAB utilities. They do
    # not call Windows Installer install, session, or custom-action APIs.
    path = ROOT / "scripts/extract-virtualbox-windows.py"
    module_spec = importlib.util.spec_from_file_location("agenticvm_msi_readonly", path)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    database = module.MsiDatabase(archive)
    try:
        media = database.table("Media", ["Cabinet"])
        names = {row["Cabinet"].removeprefix("#") for row in media}
        if names != {"product.cab"}:
            raise ValueError("Unexpected pinned 7-Zip MSI media")
        for record in database.records("SELECT `Name`,`Data` FROM `_Streams`"):
            name = database.string(record, 1)
            if name in names:
                database.stream(record, 2, safe(scratch, name))
    finally:
        database.close()
    cabinet = scratch / "product.cab"
    members = module.cabinet_members(cabinet)
    if len(members) > 256 or sum(m["bytes"] for m in members) > spec["max_unpacked_bytes"]:
        raise ValueError("7-Zip CAB exceeds extraction budget")
    expanded = module.unpack_cabinet(cabinet, scratch)
    for item in spec["files"]:
        matches = [m for m in expanded["members"] if m["name"].removeprefix("_") == item["path"]]
        if len(matches) != 1:
            raise ValueError("Missing or duplicate 7-Zip CAB file")
        shutil.copyfile(matches[0]["extracted_path"], safe(stage, item["path"]))


def extract_qemu(archive, spec, stage, scratch, report):
    seven = safe(ROOT, "tools/7zip/26.04/7z.exe")
    total = sum(item["bytes"] for item in spec["files"])
    if len(spec["files"]) != 129 or total > spec["max_unpacked_bytes"]:
        raise ValueError("QEMU selection exceeds pinned extraction budget")
    for item in spec["files"]:
        safe(stage, item["path"])
    selected = scratch / "qemu-files.txt"
    selected.write_text("".join(item["path"].replace("/", "\\") + "\n" for item in spec["files"]), encoding="utf-8")
    evidence = "runtime/build-tools-qemu-" + uuid.uuid4().hex[:12]
    command = [sys.executable, "-I", str(ROOT / "scripts/run-bounded.py"), "--memory-mib", "512",
               "--seconds", "120", "--output", evidence, "--", str(seven), "x", str(archive),
               "-o" + str(stage), "-y", "-bb0", "-bso0", "-bsp0", "-scsUTF-8", "@" + str(selected)]
    child = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=140, check=False)
    report["extraction_evidence"] = str(ROOT / evidence)
    if child.returncode:
        raise RuntimeError("Bounded QEMU extraction failed; inspect " + str(ROOT / evidence))
    actual = {p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file()}
    if actual != {item["path"] for item in spec["files"]}:
        raise ValueError("QEMU output inventory differs from exact selection")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Read-only full payload verification")
    mode.add_argument("--download", action="store_true", help="Restore pinned tools beneath workspace")
    args = parser.parse_args()
    result = {"schema": "agenticvm.build-tools-check.v1", "mode": "check" if args.check else "download",
              "workspace": str(ROOT), "installer_execution": False, "tools": {}, "ready": False}
    try:
        if os.name != "nt" or os.environ.get("PROCESSOR_ARCHITECTURE", "").upper() not in ("AMD64", "X86"):
            raise RuntimeError("This pinned tool bundle targets x64 Windows")
        lock = json.loads(LOCK.read_text("utf-8"))
        if lock["schema"] != "agenticvm.build-tools.v1":
            raise ValueError("Unsupported build-tools lock schema")
        for name in ("zig", "7zip", "qemu"):
            spec = lock["sources"][name]
            destination = safe(ROOT, spec["destination"])
            report = check_payload(name, spec, destination)
            result["tools"][name] = report
            report["destination"] = str(destination)
            if report["ready"] or args.check:
                continue
            if shutil.disk_usage(ROOT).free < 1536 * MIB:
                raise RuntimeError("Restore requires at least 1.5 GiB free workspace storage")
            archive = acquire(spec, report)
            scratch = safe(ROOT, "tools/.prepare-" + name + "-" + uuid.uuid4().hex[:12])
            stage = scratch / "payload"
            stage.mkdir(parents=True)
            if name == "zig":
                extract_zig(archive, spec, stage)
            elif name == "7zip":
                extract_7zip(archive, spec, stage, scratch)
            else:
                extract_qemu(archive, spec, stage, scratch, report)
            verified = check_payload(name, spec, stage)
            if not verified["ready"]:
                raise RuntimeError("Staged tool failed verification: " + json.dumps(verified))
            destination.parent.mkdir(parents=True, exist_ok=True)
            previous = None
            if destination.exists():
                previous = destination.with_name(destination.name + ".previous-" + uuid.uuid4().hex[:8])
                destination.rename(previous)
                report.setdefault("retained_backups", []).append(str(previous))
            try:
                stage.rename(destination)
            except OSError:
                if previous is not None and not destination.exists():
                    previous.rename(destination)
                raise
            report.update(verified, restored=True)
        result["ready"] = all(t["ready"] for t in result["tools"].values()) and len(result["tools"]) == 3
    except BaseException as error:
        result["error"] = repr(error)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ready"] else 1)


if __name__ == "__main__":
    main()
