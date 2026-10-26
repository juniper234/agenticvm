"""Build a BIOS-bootable, offline Linux kernel/BusyBox diagnostic CD.

Dependency (workspace-local): uv pip install --target tools/python/iso pycdlib==1.21.0
This script parses trusted-source artifacts. It never launches guest code on the host.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import importlib.metadata
import json
import stat
import struct
import sys
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools/python/iso"))
import pycdlib  # noqa: E402

VERSION = "3.24.2"
BASE = f"https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/"
ISO_NAME = f"alpine-virt-{VERSION}-x86_64.iso"
MAX_ISO = 200 * 1024 * 1024
MAX_INITRD = 120 * 1024 * 1024
OUT = ROOT / "runtime/linux-probe"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str, limit: int) -> bytes:
    with urlopen(Request(url, headers={"User-Agent": "agenticvm-research"}), timeout=60) as response:
        if int(response.headers.get("Content-Length", "0")) > limit:
            raise ValueError("Content-Length exceeds configured input bound")
        result = response.read(limit + 1)
        if len(result) > limit:
            raise ValueError("Downloaded input exceeds configured bound")
        return result


def verified_iso() -> tuple[Path, dict]:
    dest = ROOT / "downloads/alpine" / VERSION
    dest.mkdir(parents=True, exist_ok=True)
    sums = fetch(BASE + ISO_NAME + ".sha256", 4096)
    digest, name = sums.decode("ascii").strip().split(maxsplit=1)
    if name.strip(" *") != ISO_NAME or len(digest) != 64:
        raise ValueError("Unexpected official checksum response")
    target = dest / ISO_NAME
    if not target.exists():
        data = fetch(BASE + ISO_NAME, MAX_ISO)
        if sha(data) != digest:
            raise ValueError("Official ISO SHA256 mismatch")
        target.write_bytes(data)
    if target.stat().st_size > MAX_ISO:
        raise ValueError("Existing ISO exceeds input bound")
    with target.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != digest:
        raise ValueError("Existing ISO SHA256 mismatch")
    (dest / (ISO_NAME + ".sha256")).write_bytes(sums)
    provenance = {"version": VERSION, "url": BASE + ISO_NAME,
                  "checksum_url": BASE + ISO_NAME + ".sha256",
                  "sha256": actual, "bytes": target.stat().st_size,
                  "sha256_verified": True, "gpg_verified": False,
                  "release_source": "https://www.alpinelinux.org/downloads/"}
    (dest / "download-manifest.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return target, provenance


def extract(iso: pycdlib.PyCdlib, path: str) -> bytes:
    output = io.BytesIO()
    iso.get_file_from_iso_fp(output, rr_path=path)
    return output.getvalue()


def unpack_newc(data: bytes) -> dict[str, tuple[int, bytes]]:
    """Read bounded newc data without creating host files or following links."""
    entries = {}
    cursor = 0
    while cursor + 110 <= len(data):
        if data[cursor:cursor + 6] not in (b"070701", b"070702"):
            if not data[cursor:].strip(b"\0"):
                break
            raise ValueError(f"Unsupported cpio header at {cursor}")
        fields = [int(data[cursor + 6 + 8 * n:cursor + 14 + 8 * n], 16) for n in range(13)]
        mode, length, namelen = fields[1], fields[6], fields[11]
        start = cursor + 110
        if not 1 <= namelen <= 4096 or start + namelen > len(data):
            raise ValueError("Malformed cpio name")
        name = data[start:start + namelen - 1].decode("utf-8")
        start = (start + namelen + 3) & ~3
        if start + length > len(data) or length > MAX_INITRD:
            raise ValueError("Malformed cpio payload")
        cursor = (start + length + 3) & ~3
        if name == "TRAILER!!!":
            continue  # Also permit aligned concatenated newc archives.
        if name.startswith("/") or ".." in name.split("/"):
            raise ValueError("Unsafe cpio member name")
        entries[name.removeprefix("./")] = (mode, data[start:start + length])
        if len(entries) > 10000:
            raise ValueError("Excessive cpio entries")
    return entries


def source_initrd(iso: pycdlib.PyCdlib) -> dict[str, tuple[int, bytes]]:
    compressed = extract(iso, "/boot/initramfs-virt")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        expanded = stream.read(MAX_INITRD + 1)
    if len(expanded) > MAX_INITRD:
        raise ValueError("Initramfs exceeds expanded size bound")
    return unpack_newc(expanded)


def elf_info(data: bytes) -> dict:
    """Inspect ELF64 x86-64 dependencies without executing any ELF binary."""
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 62:
        raise ValueError("Expected little-endian ELF64 x86-64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize != 56 or phnum > 100:
        raise ValueError("Unexpected ELF program table")
    headers = [struct.unpack_from("<IIQQQQQQ", data, phoff + n * phentsize) for n in range(phnum)]
    interpreter = None
    needed, string_addr = [], None
    for kind, flags, offset, addr, paddr, filesz, memsz, align in headers:
        if offset + filesz > len(data):
            raise ValueError("ELF segment exceeds file")
        if kind == 3:
            interpreter = data[offset:offset + filesz].rstrip(b"\0").decode("ascii")
        if kind == 2:
            for current in range(offset, offset + filesz, 16):
                tag, value = struct.unpack_from("<QQ", data, current)
                if tag == 0:
                    break
                if tag == 1:
                    needed.append(value)
                if tag == 5:
                    string_addr = value
    names = []
    for string_offset in needed:
        for kind, flags, offset, addr, paddr, filesz, memsz, align in headers:
            if kind == 1 and addr <= string_addr + string_offset < addr + filesz:
                pos = offset + string_addr + string_offset - addr
                end = data.index(b"\0", pos, min(pos + 512, len(data)))
                names.append(data[pos:end].decode("ascii"))
                break
        else:
            raise ValueError("ELF dynamic string address is outside load segments")
    return {"interpreter": interpreter, "needed": names}


def make_newc(entries: dict[str, tuple[int, bytes, int, int]]) -> bytes:
    """Create deterministic Linux newc data, including required device nodes."""
    output = bytearray()
    items = sorted(entries.items()) + [("TRAILER!!!", (0, b"", 0, 0))]
    for inode, (name, (mode, data, major, minor)) in enumerate(items, 1):
        encoded = name.encode("utf-8") + b"\0"
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0]
        output += b"070701" + b"".join(f"{field:08x}".encode("ascii") for field in fields)
        output += encoded
        output += b"\0" * (-len(output) % 4)
        output += data
        output += b"\0" * (-len(output) % 4)
    output += b"\0" * (-len(output) % 512)
    return bytes(output)


def build(iso: pycdlib.PyCdlib, provenance: dict) -> None:
    kernel_config = extract(iso, "/boot/config-6.18.52-0-virt").decode("ascii")
    required_kernel = ("CONFIG_BLK_DEV_INITRD=y", "CONFIG_BINFMT_ELF=y", "CONFIG_BINFMT_SCRIPT=y",
                       "CONFIG_DEVTMPFS=y", "CONFIG_PROC_FS=y", "CONFIG_SYSFS=y", "CONFIG_TMPFS=y",
                       "CONFIG_SERIAL_8250=y", "CONFIG_SERIAL_8250_CONSOLE=y")
    if any(option not in kernel_config.splitlines() for option in required_kernel):
        raise ValueError("Kernel is missing a required built-in probe facility")
    source = source_initrd(iso)
    mode, busybox = source["usr/bin/busybox"]
    dependency = elf_info(busybox)
    # Explicitly fail if a later ISO changes the required dependency closure.
    if dependency != {"interpreter": "/lib/ld-musl-x86_64.so.1", "needed": ["libc.musl-x86_64.so.1"]}:
        raise ValueError(f"Review new BusyBox dependency closure: {dependency}")
    loader_mode, loader = source["usr/lib/ld-musl-x86_64.so.1"]
    if elf_info(loader)["needed"]:
        raise ValueError("Musl loader unexpectedly has further dependencies")
    payload_sha = sha(b"\0" * (1024 * 1024))
    init = (ROOT / "scripts/linux-probe-init.sh").read_bytes().replace(b"\r\n", b"\n")
    init = init.replace(b"@PAYLOAD_SHA256@", payload_sha.encode("ascii"))
    entries = {name: (stat.S_IFDIR | 0o755, b"", 0, 0) for name in
               ("bin", "lib", "dev", "proc", "sys", "tmp")}
    entries.update({
        "bin/busybox": (mode, busybox, 0, 0),
        "bin/sh": (stat.S_IFLNK | 0o777, b"busybox", 0, 0),
        "lib/ld-musl-x86_64.so.1": (loader_mode, loader, 0, 0),
        "lib/libc.musl-x86_64.so.1": (stat.S_IFLNK | 0o777, b"ld-musl-x86_64.so.1", 0, 0),
        "init": (stat.S_IFREG | 0o755, init, 0, 0),
        "dev/console": (stat.S_IFCHR | 0o600, b"", 5, 1),
        "dev/null": (stat.S_IFCHR | 0o666, b"", 1, 3),
        "dev/ttyS0": (stat.S_IFCHR | 0o600, b"", 4, 64),
    })
    # gzip mtime=0 and normalized source line endings make the initramfs reproducible.
    initrd = gzip.compress(make_newc(entries), compresslevel=9, mtime=0)
    roundtrip = unpack_newc(gzip.decompress(initrd))
    if roundtrip["init"] != (stat.S_IFREG | 0o755, init):
        raise ValueError("Initramfs init mode/content roundtrip failed")
    for applet in (b"sha256sum\0", b"poweroff\0", b"mount\0", b"uname\0", b"dd\0"):
        if applet not in busybox:
            raise ValueError(f"BusyBox applet marker missing: {applet!r}")
    files = {
        "vmlinuz": extract(iso, "/boot/vmlinuz-virt"),
        "initrd.gz": initrd,
        "isolinux.bin": extract(iso, "/boot/syslinux/isolinux.bin"),
        "ldlinux.c32": extract(iso, "/boot/syslinux/ldlinux.c32"),
        # Preserved from Alpine for provenance; CD boot uses El Torito, not this MBR.
        "isohdpfx.bin": extract(iso, "/boot/syslinux/isohdpfx.bin"),
    }
    config = ("SERIAL 0 115200\nDEFAULT probe\nPROMPT 0\nTIMEOUT 1\n\nLABEL probe\n"
              "KERNEL /boot/vmlinuz\nINITRD /boot/initrd.gz\n"
              "APPEND rdinit=/init console=tty0 console=ttyS0,115200n8 loglevel=3 panic=0\n").encode("ascii")
    files["isolinux.cfg"] = files["syslinux.cfg"] = config
    for name, data in files.items():
        (OUT / name).write_bytes(data)
    # Build a new image; the official input image is never edited.
    image = pycdlib.PyCdlib()
    image.new(interchange_level=3, rock_ridge="1.09", vol_ident="AGENTICVM_PROBE")
    image.add_directory("/BOOT", rr_name="boot")
    image.add_directory("/BOOT/SYSLINUX", rr_name="syslinux")
    paths = {}
    for name in files:
        directory = "/BOOT" if name in ("vmlinuz", "initrd.gz") else "/BOOT/SYSLINUX"
        iso_name = name.upper() if "." in name else name.upper() + "."
        path = f"{directory}/{iso_name};1"
        paths[name] = path
        image.add_file(str(OUT / name), iso_path=path, rr_name=name, creation_time=0)
    image.add_eltorito(paths["isolinux.bin"], bootcatfile="/BOOT/SYSLINUX/BOOT.CAT;1",
                      rr_bootcatname="boot.cat", boot_load_size=4, boot_info_table=True,
                      platform_id=0, media_name="noemul")
    target = OUT / "agenticvm-linux-probe.iso"
    image.write(str(target))
    image.close()
    check = pycdlib.PyCdlib()
    check.open(str(target))
    for name in ("vmlinuz", "initrd.gz", "ldlinux.c32", "isolinux.cfg", "syslinux.cfg"):
        out = io.BytesIO()
        check.get_file_from_iso_fp(out, iso_path=paths[name])
        if out.getvalue() != files[name]:
            raise ValueError(f"Output ISO roundtrip mismatch: {name}")
    bootcat = check.eltorito_boot_catalog
    entry = bootcat.initial_entry
    if bootcat.validation_entry.platform_id != 0 or entry.boot_indicator != 0x88 or entry.sector_count != 4:
        raise ValueError("Unexpected BIOS boot catalog")
    boot_validation = {"platform_id": bootcat.validation_entry.platform_id,
                       "boot_indicator": entry.boot_indicator,
                       "load_sectors": entry.sector_count, "boot_image_lba": entry.load_rba}
    final_boot = io.BytesIO()
    check.get_file_from_iso_fp(final_boot, iso_path=paths["isolinux.bin"])
    boot_bytes = final_boot.getvalue()
    pvd_lba, boot_lba, boot_length, boot_checksum = struct.unpack_from("<IIII", boot_bytes, 8)
    checksum_bytes = boot_bytes[64:] + b"\0" * (-len(boot_bytes[64:]) % 4)
    computed = sum(struct.unpack("<" + "I" * (len(checksum_bytes) // 4), checksum_bytes)) & 0xffffffff
    if (pvd_lba, boot_lba, boot_length, boot_checksum) != (16, entry.load_rba, len(boot_bytes), computed):
        raise ValueError("ISOLINUX boot info table does not match final ISO")
    boot_validation["boot_info_table_checksum_valid"] = True
    check.close()
    manifest = {"purpose": "Minimal Linux kernel and BusyBox early userspace, not a desktop or full Alpine workload",
                "source_iso": provenance, "pycdlib_version": "1.21.0",
                "busybox_elf": dependency, "busybox_source_mode": oct(mode),
                "initramfs_init_mode": "0100755", "kernel_version": "6.18.52-0-virt",
                "kernel_required_facilities_verified": list(required_kernel),
                "build_script_sha256": sha(Path(__file__).read_bytes()),
                "init_source_sha256": sha((ROOT / "scripts/linux-probe-init.sh").read_bytes()),
                "tmpfs_payload_bytes": 1024 * 1024, "tmpfs_payload_sha256": payload_sha,
                "network_configured": False, "attached_disk_access": False,
                "console": "ttyS0 at 115200 baud", "boot_mode": "BIOS El Torito CD, not USB hybrid",
                "static_verification": boot_validation, "runtime_boot_verified": False,
                "four_gb_host_tested": False,
                "components": {name: {"bytes": len(data), "sha256": sha(data)} for name, data in files.items()},
                "output": {"path": str(target.relative_to(ROOT)), "bytes": target.stat().st_size,
                           "sha256": sha(target.read_bytes())}}
    (OUT / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


def main() -> None:
    if importlib.metadata.version("pycdlib") != "1.21.0":
        raise SystemExit("Install the pinned pycdlib==1.21.0 into tools/python/iso first")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect", action="store_true")
    args = parser.parse_args()
    source, provenance = verified_iso()
    OUT.mkdir(parents=True, exist_ok=True)
    iso = pycdlib.PyCdlib()
    iso.open(str(source))
    if args.inspect:
        print(json.dumps(provenance, indent=2))
        for path, dirs, files in iso.walk(rr_path="/"):
            if path.startswith("/boot"):
                print(path, dirs, files)
        print(extract(iso, "/boot/syslinux/syslinux.cfg").decode())
        for name, (mode, data) in source_initrd(iso).items():
            if name.endswith("busybox") or "musl" in name or ".so" in name or name == "init":
                print(name, oct(mode), len(data), data[:24].hex())
        config = extract(iso, "/boot/config-6.18.52-0-virt").decode()
        print("\n".join(line for line in config.splitlines() if any(term in line for term in
              ("CONFIG_DEVTMPFS", "CONFIG_SERIAL_8250", "CONFIG_TMPFS", "CONFIG_BLK_DEV_INITRD", "CONFIG_BINFMT_ELF"))))
        iso.close()
        return
    build(iso, provenance)
    iso.close()


if __name__ == "__main__":
    main()
