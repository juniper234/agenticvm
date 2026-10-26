"""Build only the headless boot ISO over the already verified immutable Debian base."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("desktop_builder", ROOT / "scripts/build-linux-desktop.py")
desktop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(desktop)
probe = desktop.probe


def record(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size, "sha256": digest}


def build(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "agenticvm-linux-peer.iso").exists():
        raise FileExistsError("Use a fresh output folder; refusing to overwrite a built ISO")
    base = json.loads((ROOT / "runtime/linux-desktop/build-manifest.json").read_text("utf-8"))
    root_disk = ROOT / "runtime/linux-desktop/rootfs.ext2"
    actual_root = record(root_disk)
    if actual_root["sha256"] != base["root_disk"]["sha256"]:
        raise ValueError("The immutable Debian base differs from its build manifest")
    agent = args.agent.read_bytes()
    if probe.elf_info(agent) != {"interpreter": None, "needed": []}:
        raise ValueError("Peer agent must be a static x86_64 ELF")
    source, provenance = probe.verified_iso()
    iso = probe.pycdlib.PyCdlib()
    iso.open(str(source))
    try:
        original = probe.source_initrd(iso)
        module_base = ROOT / "runtime/linux-desktop/kernel-modules/modules" / base["kernel_version"]
        dependencies = dict(line.split(":", 1) for line in (module_base / "modules.dep").read_text("utf-8").splitlines())
        fw_cfg = next(name for name in dependencies if name.endswith("/qemu_fw_cfg.ko"))
        modules = []
        def visit(name):
            if name in modules:
                return
            for dependency in dependencies[name].split():
                visit(dependency)
            modules.append(name)
        for name in [*base["boot_modules"], fw_cfg]:
            visit(name)
        files = {name: (stat.S_IFDIR | 0o755, b"", 0, 0) for name in
                 ("bin", "lib", "dev", "proc", "sys", "lower", "overlay", "newroot", "modules", "assets")}
        boot_paths = []
        for module in modules:
            name = "modules/" + Path(module).name
            data = (module_base / module).read_bytes()
            if data[:4] != b"\x7fELF":
                raise ValueError("Boot module must be an uncompressed ELF")
            files[name] = (stat.S_IFREG | 0o644, data, 0, 0)
            boot_paths.append(name)
        init = (ROOT / "guest/peer-bootstrap.sh").read_bytes().replace(b"\r\n", b"\n").replace(b"@BOOT_MODULES@", " ".join(boot_paths).encode())
        peer_init = (ROOT / "guest/peer-init.sh").read_bytes().replace(b"\r\n", b"\n")
        busy_mode, busybox = original["usr/bin/busybox"]
        loader_mode, loader = original["usr/lib/ld-musl-x86_64.so.1"]
        files.update({"init": (stat.S_IFREG | 0o755, init, 0, 0),
                      "assets/peer-init.sh": (stat.S_IFREG | 0o755, peer_init, 0, 0),
                      "assets/agentd": (stat.S_IFREG | 0o755, agent, 0, 0),
                      "bin/busybox": (busy_mode, busybox, 0, 0),
                      "bin/sh": (stat.S_IFLNK | 0o777, b"busybox", 0, 0),
                      "lib/ld-musl-x86_64.so.1": (loader_mode, loader, 0, 0),
                      "lib/libc.musl-x86_64.so.1": (stat.S_IFLNK | 0o777, b"ld-musl-x86_64.so.1", 0, 0),
                      "dev/console": (stat.S_IFCHR | 0o600, b"", 5, 1)})
        initrd = gzip.compress(probe.make_newc(files), compresslevel=9, mtime=0)
        roundtrip = probe.unpack_newc(gzip.decompress(initrd))
        if roundtrip["assets/agentd"][1] != agent or roundtrip["assets/peer-init.sh"][1] != peer_init:
            raise ValueError("Peer initramfs asset verification failed")
        image = desktop.make_boot_iso(iso, initrd, output, "peer")
    finally:
        iso.close()
    manifest = {"profile": "agent", "os": "Debian GNU/Linux 13", "memory_mib": 256,
                "cpus": 1, "uid": 1000, "display": None, "desktop_started": False,
                "source_iso": provenance, "kernel_version": base["kernel_version"], "root_disk": actual_root,
                "immutable_root_unchanged": True, "agent": record(args.agent.resolve()), "iso": record(image),
                "boot_modules": modules, "peer_device": "/dev/virtio-ports/org.agenticvm.peer",
                "isolated_network": {"listen": "192.0.2.1/30", "connect": "192.0.2.2/30", "gateway": None, "dns": None},
                "runtime_verified": False}
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", "utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", type=Path, default=ROOT / "runtime/guest-build/agentd-peer")
    parser.add_argument("--output", type=Path, default=ROOT / "runtime/linux-peer")
    build(parser.parse_args())
