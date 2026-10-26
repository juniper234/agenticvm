"""Refresh only the desktop boot ISO's guest-local start page over the frozen base."""
from __future__ import annotations

import argparse
import copy
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
    if (output / "agenticvm-linux-desktop.iso").exists():
        raise FileExistsError("Use a fresh output; refusing to overwrite an existing desktop ISO")
    manifest = copy.deepcopy(json.loads((ROOT / "runtime/linux-desktop/build-manifest.json").read_text("utf-8")))
    root_disk = ROOT / "runtime/linux-desktop/rootfs.ext2"
    if record(root_disk)["sha256"] != manifest["root_disk"]["sha256"]:
        raise ValueError("The immutable Debian root differs from its pinned manifest")
    fixture = (ROOT / "guest/desktop-fixture.html").read_bytes().replace(b"\r\n", b"\n")
    if len(fixture) > 65536 or b"AgenticVM Desktop Ready" not in fixture:
        raise ValueError("Guest start page exceeds its limit or lacks the boot readiness marker")
    source, provenance = probe.verified_iso()
    iso = probe.pycdlib.PyCdlib()
    iso.open(str(source))
    try:
        original = probe.source_initrd(iso)
        files = {name: (stat.S_IFDIR | 0o755, b"", 0, 0) for name in
                 ("bin", "lib", "dev", "proc", "sys", "lower", "overlay", "newroot", "modules", "assets")}
        module_base = ROOT / "runtime/linux-desktop/kernel-modules/modules" / manifest["kernel_version"]
        boot_paths = []
        for path in manifest["boot_modules"]:
            data = (module_base / path).read_bytes()
            if data[:4] != b"\x7fELF":
                raise ValueError("Boot module must be an uncompressed ELF")
            name = "modules/" + Path(path).name
            files[name] = (stat.S_IFREG | 0o644, data, 0, 0)
            boot_paths.append(name)
        init = (ROOT / "guest/desktop-bootstrap.sh").read_bytes().replace(b"\r\n", b"\n")
        init = init.replace(b"@BOOT_MODULES@", " ".join(boot_paths).encode())
        busy_mode, busybox = original["usr/bin/busybox"]
        loader_mode, loader = original["usr/lib/ld-musl-x86_64.so.1"]
        files.update({"init": (stat.S_IFREG | 0o755, init, 0, 0),
                      "assets/desktop-fixture.html": (stat.S_IFREG | 0o644, fixture, 0, 0),
                      "bin/busybox": (busy_mode, busybox, 0, 0),
                      "bin/sh": (stat.S_IFLNK | 0o777, b"busybox", 0, 0),
                      "lib/ld-musl-x86_64.so.1": (loader_mode, loader, 0, 0),
                      "lib/libc.musl-x86_64.so.1": (stat.S_IFLNK | 0o777, b"ld-musl-x86_64.so.1", 0, 0),
                      "dev/console": (stat.S_IFCHR | 0o600, b"", 5, 1)})
        initrd = gzip.compress(probe.make_newc(files), compresslevel=9, mtime=0)
        check = probe.unpack_newc(gzip.decompress(initrd))
        if check["init"][1] != init or check["assets/desktop-fixture.html"][1] != fixture:
            raise ValueError("Desktop refresh initramfs roundtrip failed")
        image = desktop.make_boot_iso(iso, initrd, output)
    finally:
        iso.close()
    manifest.update(source_iso=provenance, iso=record(image), output=record(image), runtime_verified=False)
    manifest["boot_refresh"] = {"immutable_root_unchanged": True,
                                "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
                                "bootstrap_sha256": hashlib.sha256(init).hexdigest(),
                                "fixture_guest_path": "/usr/share/agenticvm/www/index.html"}
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", "utf-8")
    print(json.dumps({"iso": manifest["iso"], "root_disk": manifest["root_disk"], "boot_refresh": manifest["boot_refresh"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "runtime/linux-desktop-simple")
    build(parser.parse_args())
