"""Build the diskless Linux command guest from verified local components.

Uses the same pinned Alpine source and ISO library as the research probe. The
guest agent is compiled separately with the pinned Zig musl crosscompiler.
"""
from __future__ import annotations

import argparse
import gzip
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("probe_builder", ROOT / "scripts/build-linux-probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def build(agent: Path, output: Path) -> dict:
    if not agent.is_file() or agent.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Compile a Linux agent binary below 8 MiB first")
    binary = agent.read_bytes()
    if probe.elf_info(binary) != {"interpreter": None, "needed": []}:
        raise ValueError("Guest agent must be a static x86-64 Linux ELF")
    source, provenance = probe.verified_iso()
    iso = probe.pycdlib.PyCdlib()
    iso.open(str(source))
    try:
        entries = probe.source_initrd(iso)
        busy_mode, busybox = entries["usr/bin/busybox"]
        loader_mode, loader = entries["usr/lib/ld-musl-x86_64.so.1"]
        if probe.elf_info(busybox) != {"interpreter": "/lib/ld-musl-x86_64.so.1", "needed": ["libc.musl-x86_64.so.1"]}:
            raise ValueError("Unexpected BusyBox dependencies")
        config = probe.extract(iso, "/boot/config-6.18.52-0-virt").decode("ascii")
        facilities = ["CONFIG_BLK_DEV_INITRD=y", "CONFIG_BINFMT_ELF=y", "CONFIG_BINFMT_SCRIPT=y",
                      "CONFIG_DEVTMPFS=y", "CONFIG_PROC_FS=y", "CONFIG_SYSFS=y", "CONFIG_TMPFS=y",
                      "CONFIG_SERIAL_8250=y", "CONFIG_SERIAL_8250_CONSOLE=y", "CONFIG_VIRTIO=y",
                      "CONFIG_VIRTIO_PCI=y", "CONFIG_VIRTIO_CONSOLE=y"]
        if any(x not in config.splitlines() for x in facilities):
            raise ValueError("Kernel lacks a required built-in facility")
        init = (ROOT / "guest/init.sh").read_bytes().replace(b"\r\n", b"\n")
        files = {x: (stat.S_IFDIR | 0o755, b"", 0, 0) for x in
                 ("bin", "usr", "usr/bin", "lib", "etc", "dev", "proc", "sys", "tmp", "workspace")}
        files.update({
            "bin/busybox": (busy_mode, busybox, 0, 0),
            "bin/sh": (stat.S_IFLNK | 0o777, b"busybox", 0, 0),
            "bin/agentd": (stat.S_IFREG | 0o755, binary, 0, 0),
            "lib/ld-musl-x86_64.so.1": (loader_mode, loader, 0, 0),
            "lib/libc.musl-x86_64.so.1": (stat.S_IFLNK | 0o777, b"ld-musl-x86_64.so.1", 0, 0),
            "init": (stat.S_IFREG | 0o755, init, 0, 0),
            "etc/passwd": (stat.S_IFREG | 0o644, b"root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000:agent:/workspace:/bin/sh\n", 0, 0),
            "etc/group": (stat.S_IFREG | 0o644, b"root:x:0:\nagent:x:1000:\n", 0, 0),
            "etc/os-release": (stat.S_IFREG | 0o644, b'NAME="AgenticVM command guest"\nID=agenticvm\nVERSION_ID=0.1\n', 0, 0),
            "dev/console": (stat.S_IFCHR | 0o600, b"", 5, 1),
            "dev/null": (stat.S_IFCHR | 0o666, b"", 1, 3),
            "dev/ttyS0": (stat.S_IFCHR | 0o600, b"", 4, 64),
        })
        initrd = gzip.compress(probe.make_newc(files), compresslevel=9, mtime=0)
        check_cpio = probe.unpack_newc(gzip.decompress(initrd))
        if check_cpio["init"] != (stat.S_IFREG | 0o755, init) or check_cpio["bin/agentd"][1] != binary:
            raise ValueError("Agent/init initramfs roundtrip failed")
        components = {
            "vmlinuz": probe.extract(iso, "/boot/vmlinuz-virt"),
            "initrd.gz": initrd,
            "isolinux.bin": probe.extract(iso, "/boot/syslinux/isolinux.bin"),
            "ldlinux.c32": probe.extract(iso, "/boot/syslinux/ldlinux.c32"),
        }
    finally:
        iso.close()
    bootcfg = ("DEFAULT agent\nPROMPT 0\nTIMEOUT 1\n\nLABEL agent\n"
               "KERNEL /boot/vmlinuz\nINITRD /boot/initrd.gz\n"
               "APPEND rdinit=/init console=tty0 console=ttyS1,115200n8 loglevel=3 panic=0\n").encode("ascii")
    components["isolinux.cfg"] = components["syslinux.cfg"] = bootcfg
    output.mkdir(parents=True, exist_ok=True)
    image = probe.pycdlib.PyCdlib()
    image.new(interchange_level=3, rock_ridge="1.09", vol_ident="AGENTICVM_AGENT")
    image.add_directory("/BOOT", rr_name="boot")
    image.add_directory("/BOOT/SYSLINUX", rr_name="syslinux")
    paths = {}
    for name, content in components.items():
        path = output / name
        path.write_bytes(content)
        directory = "/BOOT" if name in ("vmlinuz", "initrd.gz") else "/BOOT/SYSLINUX"
        filename = name.upper() if "." in name else name.upper() + "."
        paths[name] = f"{directory}/{filename};1"
        image.add_file(str(path), iso_path=paths[name], rr_name=name, creation_time=0)
    image.add_eltorito(paths["isolinux.bin"], bootcatfile="/BOOT/SYSLINUX/BOOT.CAT;1",
                      rr_bootcatname="boot.cat", boot_load_size=4, boot_info_table=True,
                      platform_id=0, media_name="noemul")
    target = output / "agenticvm-linux-agent.iso"
    image.write(str(target))
    image.close()
    check = probe.pycdlib.PyCdlib()
    check.open(str(target))
    try:
        for name in ("vmlinuz", "initrd.gz", "ldlinux.c32", "isolinux.cfg", "syslinux.cfg"):
            data = io.BytesIO()
            check.get_file_from_iso_fp(data, iso_path=paths[name])
            if data.getvalue() != components[name]:
                raise ValueError("Final ISO component roundtrip failed: " + name)
        entry = check.eltorito_boot_catalog.initial_entry
        data = io.BytesIO()
        check.get_file_from_iso_fp(data, iso_path=paths["isolinux.bin"])
        boot = data.getvalue()
        checksum_data = boot[64:] + b"\0" * (-len(boot[64:]) % 4)
        checksum = sum(struct.unpack("<" + "I" * (len(checksum_data) // 4), checksum_data)) & 0xffffffff
        if struct.unpack_from("<IIII", boot, 8) != (16, entry.load_rba, len(boot), checksum):
            raise ValueError("Invalid ISOLINUX boot table")
        if entry.boot_indicator != 0x88 or entry.sector_count != 4:
            raise ValueError("Not a bootable BIOS CD")
    finally:
        check.close()
    manifest = {
        "purpose": "Diskless Linux command guest with unprivileged serial agent",
        "version": "0.1.0", "protocol": 1, "source_iso": provenance,
        "agent": {"bytes": len(binary), "sha256": probe.sha(binary), "static_elf": True},
        "init_sha256": probe.sha(init), "workspace": {"path": "/workspace", "temporary": True, "limit_mib": 64},
        "uid": 1000, "network": False, "persistent_disk": False, "desktop": False,
        "control_channels": ["virtio-serial preferred", "16550 UART fallback"],
        "kernel_version": "6.18.52-0-virt", "runtime_verified": False,
        "components": {name: {"bytes": len(data), "sha256": probe.sha(data)} for name, data in components.items()},
        "output": {"path": str(target.relative_to(ROOT)), "bytes": target.stat().st_size, "sha256": probe.sha(target.read_bytes())},
    }
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", type=Path, default=ROOT / "runtime/guest-build/agentd")
    parser.add_argument("--output", type=Path, default=ROOT / "runtime/linux-agent")
    args = parser.parse_args()
    print(json.dumps(build(args.agent, args.output), indent=2))
