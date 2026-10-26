"""Prepare a pinned embedded Python, or assemble a fresh local portable bundle.

No installers, global settings, existing bundle replacement, or user workspaces
are involved. --download permits only the pinned official Python ZIP download.
Run --prepare-only while the desktop image is still being built.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
MIB = 1024 * 1024
PYTHON_LOCK = ROOT / "tools/python-runtime-lock.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(MIB), b""):
            digest.update(block)
    return digest.hexdigest()


def plain(root: Path, relative: str) -> Path:
    """Use only ordinary files/directories beneath an explicitly owned root."""
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    if not parts or any(part in {".", "..", "/"} or ":" in part for part in parts):
        raise ValueError(f"Unsafe relative path: {relative}")
    target = root.joinpath(*parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes its owned directory: {relative}")
    cursor = target
    while cursor != root.parent:
        if cursor.is_symlink() or (cursor.exists() and getattr(os.path, "isjunction", lambda _: False)(cursor)):
            raise ValueError(f"Reparse point refused: {cursor}")
        if cursor == root:
            break
        cursor = cursor.parent
    return target


def load(path: Path) -> dict:
    if path.stat().st_size > 4 * MIB:
        raise ValueError(f"Manifest is too large: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Manifest must be an object: {path}")
    return value


def pth_contents(lock: dict, *, portable: bool) -> bytes:
    source = lock["portable_source_path" if portable else "development_source_path"]
    return f"{lock['stdlib_zip']}\n.\n{source}\n# Isolated AgenticVM runtime; site and environment imports stay disabled.\n".encode("ascii")


def acquire_python(lock: dict, *, download: bool) -> Path:
    archive = plain(ROOT, lock["archive"])
    if archive.is_file():
        if archive.stat().st_size == lock["bytes"] and sha256(archive) == lock["sha256"]:
            return archive
        raise ValueError(f"Existing Python archive differs from its published checksum; retained untouched: {archive}")
    if not download:
        raise ValueError("Pinned Python archive is missing. Repeat with --download to fetch it from python.org.")
    archive.parent.mkdir(parents=True, exist_ok=True)
    partial = archive.with_name(archive.name + ".part-" + uuid.uuid4().hex[:8])
    started, total = time.monotonic(), 0
    digest = hashlib.sha256()
    request = urllib.request.Request(lock["url"], headers={"User-Agent": "AgenticVM-portable-builder/1"})
    with urllib.request.urlopen(request, timeout=15) as source, partial.open("xb") as output:
        parsed = urllib.parse.urlsplit(source.url)
        if parsed.scheme != "https" or parsed.hostname not in {"www.python.org", "python.org"}:
            raise ValueError("Python download redirected away from the official HTTPS host.")
        while chunk := source.read(128 * 1024):
            total += len(chunk)
            if total > lock["bytes"] or time.monotonic() - started > 120:
                raise ValueError("Python download exceeds its pinned size or 120 second deadline.")
            digest.update(chunk)
            output.write(chunk)
    if total != lock["bytes"] or digest.hexdigest() != lock["sha256"]:
        raise ValueError(f"Downloaded Python ZIP does not match its published SHA256; retained: {partial}")
    partial.rename(archive)
    return archive


def zip_entries(archive: Path, lock: dict) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(archive) as package:
        entries = package.infolist()
    files = [item for item in entries if not item.is_dir()]
    if len(files) > lock["max_files"] or sum(item.file_size for item in files) > lock["max_unpacked_bytes"]:
        raise ValueError("Python ZIP exceeds its extraction budget.")
    names = set()
    for item in entries:
        parts = PurePosixPath(item.filename.replace("\\", "/")).parts
        if (not parts or len(parts) != 1 or parts[0] in {".", "..", "/"} or ":" in parts[0]
                or stat.S_ISLNK(item.external_attr >> 16)):
            raise ValueError("Python ZIP contains an unexpected path or symlink.")
        folded = item.filename.casefold()
        if folded in names:
            raise ValueError("Python ZIP contains duplicate destinations.")
        names.add(folded)
    required = {"python.exe", "pythonw.exe", "python3.dll", "python313.dll", lock["stdlib_zip"], lock["pth_file"], "LICENSE.txt"}
    if not required.issubset({item.filename for item in files}):
        raise ValueError("Pinned Python ZIP is missing expected runtime files.")
    return files


def verify_python_tree(directory: Path, archive: Path, lock: dict, *, portable: bool = False) -> dict:
    entries = zip_entries(archive, lock)
    allowed = {item.filename for item in entries}
    actual = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()}
    # runtime-verification.json records the preparation; it is not an executable
    # payload file and is omitted from the portable interpreter directory.
    if actual - {"runtime-verification.json"} != allowed:
        raise ValueError("Embedded Python file inventory differs from the pinned ZIP.")
    with zipfile.ZipFile(archive) as package:
        for item in entries:
            target = plain(directory, item.filename)
            reference = pth_contents(lock, portable=portable) if item.filename == lock["pth_file"] else package.read(item)
            if not target.is_file() or target.stat().st_size != len(reference) or sha256(target) != hashlib.sha256(reference).hexdigest():
                raise ValueError(f"Embedded Python payload differs from the pinned ZIP/configuration: {item.filename}")
    return {"files": len(entries), "version": lock["version"], "archive_sha256": lock["sha256"], "isolated": True}


def authenticode(directory: Path, lock: dict) -> list[dict]:
    if os.name != "nt":
        raise ValueError("Portable Windows runtime preparation requires Windows Authenticode verification.")
    # Paths are supplied through a temporary environment variable, never inserted
    # into PowerShell source. This only reads signatures; it executes no payload.
    environment = os.environ.copy()
    environment["AGENTICVM_SIGNATURE_PATHS"] = json.dumps([str(plain(directory, name)) for name in lock["authenticode"]["files"]])
    source = ("$ErrorActionPreference='Stop'; "
              "Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop; $rows=@(); "
              "foreach($p in ($env:AGENTICVM_SIGNATURE_PATHS | ConvertFrom-Json)) { "
              "$s=Get-AuthenticodeSignature -LiteralPath $p; "
              "$rows += [pscustomobject]@{file=[System.IO.Path]::GetFileName($p);status=$s.Status.ToString();"
              "subject=$s.SignerCertificate.Subject;thumbprint=$s.SignerCertificate.Thumbprint} }; "
              "ConvertTo-Json -InputObject $rows -Compress")
    child = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", source],
                           env=environment, capture_output=True, text=True, timeout=45, check=False,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if child.returncode:
        raise ValueError("Cannot verify Python Authenticode signatures: " + child.stderr[-2000:])
    rows = json.loads(child.stdout)
    if not isinstance(rows, list) or len(rows) != len(lock["authenticode"]["files"]):
        raise ValueError("Python signature verifier returned an unexpected result.")
    for row in rows:
        if row["status"] != "Valid" or lock["authenticode"]["required_publisher"] not in (row.get("subject") or ""):
            raise ValueError(f"Python runtime signature is not valid for the expected publisher: {row}")
    return rows


def smoke_python(directory: Path, *, import_product: bool = True) -> dict:
    statement = "import sys,json,ctypes,socket,ssl,sqlite3,zipfile; "
    if import_product:
        statement += "import agenticvm.cli,agenticvm.mcp,agenticvm.desktop; "
    statement += "print(json.dumps({'version':sys.version.split()[0],'isolated':sys.flags.isolated,'product_imported':" + str(import_product) + "}))"
    child = subprocess.run([str(directory / "python.exe"), "-I", "-B", "-c", statement],
                           capture_output=True, text=True, timeout=20, check=False,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if child.returncode:
        raise ValueError("Prepared Python import smoke failed: " + child.stderr[-3000:])
    result = json.loads(child.stdout)
    if result.get("isolated") != 1:
        raise ValueError("Embedded Python did not preserve isolated mode.")
    return result


def prepare_python(*, download: bool) -> tuple[Path, Path, dict]:
    lock = load(PYTHON_LOCK)
    archive = acquire_python(lock, download=download)
    destination = plain(ROOT, lock["destination"])
    if not destination.exists():
        entries = zip_entries(archive, lock)
        destination.mkdir(parents=True, mode=0o700)
        with zipfile.ZipFile(archive) as package:
            for item in entries:
                target = plain(destination, item.filename)
                with package.open(item) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, MIB)
        plain(destination, lock["pth_file"]).write_bytes(pth_contents(lock, portable=False))
    verified = verify_python_tree(destination, archive, lock)
    verified["authenticode"] = authenticode(destination, lock)
    verified["smoke"] = smoke_python(destination)
    (destination / "runtime-verification.json").write_text(json.dumps(verified, indent=2) + "\n", encoding="utf-8")
    return destination, archive, verified


def verify_qemu() -> tuple[Path, list[dict], dict]:
    spec = load(ROOT / "tools/build-tools-lock.json")["sources"]["qemu"]
    directory = plain(ROOT, spec["destination"])
    for item in spec["files"]:
        target = plain(directory, item["path"])
        if not target.is_file() or target.stat().st_size != item["bytes"] or sha256(target) != item["sha256"]:
            raise ValueError("QEMU payload differs from its lock: " + item["path"])
    return directory, spec["files"], spec


def verify_image_manifest(relative: str, *, desktop: bool, peer: bool = False) -> tuple[dict, list[tuple[Path, str]]]:
    path = plain(ROOT, relative)
    manifest = load(path)
    if desktop and manifest.get("profile") != "desktop":
        raise ValueError("Desktop build manifest does not identify the desktop profile.")
    if peer and manifest.get("profile") != "agent":
        raise ValueError("Peer build manifest does not identify the agent profile.")
    if desktop and manifest.get("package_lock"):
        package_lock = plain(ROOT, manifest["package_lock"])
        if package_lock != ROOT / "tools/desktop-image-lock.json":
            raise ValueError("Desktop build manifest points at an unexpected package lock.")
        if manifest.get("package_lock_sha256") and sha256(package_lock) != manifest["package_lock_sha256"]:
            raise ValueError("Desktop package lock differs from its build manifest.")
    selected = [manifest.get("output") or manifest.get("iso")]
    if desktop:
        selected.append(manifest.get("root_disk"))
    result = [(path, relative)]
    seen = set()
    expected_parent = "runtime/linux-desktop" if desktop else "runtime/linux-peer" if peer else "runtime/linux-agent"
    for item in selected:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("Image build manifest lacks a required artifact.")
        artifact = plain(ROOT, item["path"])
        normalized = artifact.relative_to(ROOT).as_posix()
        if artifact.parent != ROOT / expected_parent or normalized in seen:
            raise ValueError("Image build manifest points outside its expected image directory or repeats an artifact.")
        seen.add(normalized)
        if (not artifact.is_file() or artifact.stat().st_size != item["bytes"]
                or not 1 <= item["bytes"] <= 4 * 1024 * MIB or sha256(artifact) != item["sha256"]):
            raise ValueError("Built image differs from its build manifest: " + normalized)
        result.append((artifact, normalized))
    return manifest, result


def source_files() -> list[tuple[Path, str]]:
    result = []
    for relative in ("README.md", "pyproject.toml", "mcp.example.json", "agenticvm.ps1", "agenticvm-mcp.ps1", "agenticvm-peers.ps1", "Start-AgenticVM.ps1", "Start-AgenticVM.cmd",
                     "tools/build-tools-lock.json", "tools/desktop-image-lock.json", "tools/python-runtime-lock.json"):
        path = plain(ROOT, relative)
        if not path.is_file():
            raise ValueError("Required product/launcher file is not ready: " + relative)
        result.append((path, relative))
    selections = (("src/agenticvm", {".py", ".html", ".css", ".js", ".svg"}),
                  ("guest", {".py", ".c", ".h", ".sh", ".md", ".js", ".html", ".xml", ".conf"}),
                  ("scripts", {".py", ".ps1", ".mjs"}),
                  ("docs", {".md", ".json"}))
    for folder, suffixes in selections:
        directory = plain(ROOT, folder)
        for path in sorted(directory.rglob("*")):
            if "__pycache__" in path.parts or not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            relative = path.relative_to(ROOT).as_posix()
            result.append((plain(ROOT, relative), relative))
    for path in sorted(plain(ROOT, "research").glob("*.md")):
        if path.is_file():
            relative = path.relative_to(ROOT).as_posix()
            result.append((plain(ROOT, relative), relative))
    if not any(relative == "src/agenticvm/web/index.html" for _, relative in result):
        raise ValueError("Product viewer assets are not ready.")
    return result


def copy_one(source: Path, destination: Path):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, MIB)


def build_bundle(output: Path, python_directory: Path, python_archive: Path, python_verified: dict) -> dict:
    output = output.absolute()
    if output.parent.resolve() != (ROOT / "dist").resolve() or output.name in {".", ".."}:
        raise ValueError("Portable output must be a new direct child of this workspace's dist directory.")
    plain(ROOT, output.relative_to(ROOT).as_posix())
    if output.exists():
        raise ValueError("Portable output already exists; select a fresh --output name. Existing bundles are never overwritten.")
    output = output.resolve()

    # Complete all dependency/image validation before creating a bundle tree.
    qemu_directory, qemu_files, qemu_spec = verify_qemu()
    desktop_manifest, images = verify_image_manifest("runtime/linux-desktop/build-manifest.json", desktop=True)
    command_manifest, command_images = verify_image_manifest("runtime/linux-agent/build-manifest.json", desktop=False)
    peer_manifest, peer_images = verify_image_manifest("runtime/linux-peer/build-manifest.json", desktop=False, peer=True)
    if peer_manifest["root_disk"]["sha256"] != desktop_manifest["root_disk"]["sha256"]:
        raise ValueError("Peer and desktop manifests reference different immutable root images.")
    files = source_files() + images + command_images + peer_images
    for item in qemu_files:
        files.append((plain(qemu_directory, item["path"]), "tools/qemu/11.1.0/" + item["path"]))
    python_lock = load(PYTHON_LOCK)
    for item in zip_entries(python_archive, python_lock):
        files.append((plain(python_directory, item.filename), "tools/python/" + item.filename))
    names = [relative.casefold() for _, relative in files]
    if len(set(names)) != len(names):
        raise ValueError("Portable file selections contain duplicate destinations.")
    output.mkdir(parents=True, mode=0o700)
    for source, relative in files:
        copy_one(source, plain(output, relative))
    (output / "tools/python" / python_lock["pth_file"]).write_bytes(pth_contents(python_lock, portable=True))
    verify_python_tree(output / "tools/python", python_archive, python_lock, portable=True)
    for item in qemu_files:
        copied = plain(output / "tools/qemu/11.1.0", item["path"])
        if copied.stat().st_size != item["bytes"] or sha256(copied) != item["sha256"]:
            raise ValueError("Copied QEMU payload differs from its lock: " + item["path"])
    for manifest in (desktop_manifest, command_manifest, peer_manifest):
        for item in (manifest.get("output") or manifest.get("iso"), manifest.get("root_disk")):
            if not item:
                continue
            copied = plain(output, item["path"])
            if copied.stat().st_size != item["bytes"] or sha256(copied) != item["sha256"]:
                raise ValueError("Copied image differs from its build manifest: " + item["path"])
    if desktop_manifest.get("package_lock_sha256"):
        copied_lock = plain(output, desktop_manifest["package_lock"])
        if sha256(copied_lock) != desktop_manifest["package_lock_sha256"]:
            raise ValueError("Copied desktop package lock differs from its build manifest.")
    runtime_smoke = smoke_python(output / "tools/python")
    portable_mcp = {"mcpServers": {"agenticvm": {"command": "powershell.exe", "args": [
        "-NoProfile", "-File", (output / "agenticvm-mcp.ps1").as_posix(),
        "--workspace", (output / "runtime/desktop").as_posix(),
        "--profile", "desktop", "--persistent", "--network"]}}}
    (output / "mcp.example.json").write_text(json.dumps(portable_mcp, indent=2) + "\n", encoding="utf-8")
    notices = ("AgenticVM local portable development bundle\n\n"
               "No new license is assigned here to the user's AgenticVM code.\n\n"
               "Python " + python_lock["version"] + ": official CPython embeddable Windows runtime.\n"
               "License: tools/python/LICENSE.txt\nRelease/checksum: " + python_lock["digest_source"] + "\n"
               "Source: https://www.python.org/ftp/python/" + python_lock["version"] + "/Python-" + python_lock["version"] + ".tar.xz\n\n"
               "QEMU " + qemu_spec["version"] + " Windows build " + qemu_spec["build"] + ":\n"
               "Licenses: tools/qemu/11.1.0/COPYING and COPYING.LIB; additional provenance in tools/build-tools-lock.json.\n"
               "Upstream: https://www.qemu.org/download/\nWindows build: " + qemu_spec["url"] + "\n\n"
               f"Desktop guest: {desktop_manifest.get('os', 'Linux')} {desktop_manifest.get('release', '')}.\n"
               "Exact package versions and package/source provenance\n"
               "are recorded in runtime/linux-desktop/build-manifest.json and tools/desktop-image-lock.json.\n"
               "Package license/copyright files supplied by the guest distribution remain inside its root filesystem image.\n"
               "Guest kernel, userspace and bootloader provenance: both runtime/*/build-manifest.json files.\n"
               "Guest customization source is included under guest/ and scripts/.\n\n"
               "This local bundle is an assembly for testing; external redistribution has not been performed.\n")
    (output / "THIRD-PARTY-NOTICES.txt").write_text(notices, encoding="utf-8")
    (output / "PORTABLE-QUICKSTART.txt").write_text(
        "Double-click Start-AgenticVM.cmd to open AgenticVM.\n"
        "The bundled Python and QEMU run locally; no system Python installation is required.\n"
        "Windows Hypervisor Platform and firmware virtualization must already be enabled.\n"
        "Runtime VM state and your persistent guest workspace are created only after launch.\n"
        "For MCP, copy the agenticvm entry from mcp.example.json into your client's configuration.\n"
        "Its command is powershell.exe, with these arguments:\n"
        '-NoProfile -File "' + str(output / "agenticvm-mcp.ps1") + '" '
        '--workspace "' + str(output / "runtime/desktop") + '" '
        '--profile desktop --persistent --network\n'
        "The example uses this bundle's absolute paths and shares the viewer's persistent desktop.\n"
        "Update both paths in your MCP configuration if you move the folder.\n"
        "Keep the entire folder together when moving it. See README.md for usage and current limits.\n",
        encoding="utf-8")
    inventory = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            inventory.append({"path": path.relative_to(output).as_posix(), "bytes": path.stat().st_size, "sha256": sha256(path)})
    report = {"schema": "agenticvm.portable-bundle.v1", "platform": "windows-x86_64", "files": inventory,
              "file_count": len(inventory), "bytes": sum(item["bytes"] for item in inventory),
              "python": python_verified, "packaged_runtime_smoke": runtime_smoke,
              "qemu": {"version": qemu_spec["version"], "files_verified": len(qemu_files), "archive_digest": qemu_spec["digest"]},
              "desktop_artifacts": {key: desktop_manifest.get(key) for key in ("profile", "os", "release", "root_disk", "output", "iso", "package_lock", "package_lock_sha256")},
              "command_artifact": command_manifest["output"], "peer_artifact": peer_manifest["iso"], "user_workspace_files_copied": False,
              "installer_execution": False, "global_settings_changed": False, "published": False}
    (output / "package-manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return {"ready": True, "output": str(output), "files": report["file_count"], "bytes": report["bytes"],
            "manifest": str(output / "package-manifest.json"), "python_smoke": runtime_smoke}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true", help="Prepare and verify the local embedded interpreter only")
    parser.add_argument("--download", action="store_true", help="Permit the pinned official Python ZIP download")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/AgenticVM", help="Fresh direct child of dist; never overwrite")
    args = parser.parse_args()
    try:
        directory, archive, verified = prepare_python(download=args.download)
        if args.prepare_only:
            result = {"ready": True, "mode": "prepare-only", "python": str(directory / "python.exe"), "verification": verified,
                      "installer_execution": False, "global_settings_changed": False}
        else:
            result = build_bundle(args.output, directory, archive, verified)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print(json.dumps({"ready": False, "error": str(error), "existing_outputs_preserved": True}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
