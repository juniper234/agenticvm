"""Build a minimal Debian 13 x86_64 Xfce/Firefox ESR AgenticVM image on Windows.

The boot CD is tiny. Packages live in an immutable ext2 block image, avoiding an
expanded desktop initramfs copy in guest RAM. Run through run-bounded.py.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from agenticvm.ext2 import Node, build_ext2, read_image_file


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load("desktop_probe", "build-linux-probe.py")
packages_lib = load("desktop_packages", "desktop-image-debian.py")
REQUESTED = ["base-files", "base-passwd", "busybox-static", "ca-certificates", "curl", "udev", "e2fsprogs", "procps",
             "dbus-daemon", "dbus-bin", "dbus-session-bus-common", "dbus-system-bus-common", "dbus-x11",
             "xserver-xorg-core", "xserver-xorg-input-evdev", "xauth", "x11-utils", "x11-xserver-utils",
             "xdotool", "xclip", "wmctrl", "xfce4-session", "xfwm4", "xfdesktop4",
             "xfce4-panel", "xfce4-settings", "xfce4-appfinder", "xfce4-terminal", "thunar",
             "fonts-dejavu", "fonts-noto-cjk", "fonts-noto-color-emoji", "adwaita-icon-theme", "firefox-esr", "shared-mime-info", "libglib2.0-bin",
             "libgdk-pixbuf2.0-bin", "librsvg2-common", "libgtk-3-bin", "fontconfig"]


def normalize(name):
    name = name.removeprefix("./").rstrip("/")
    if name.startswith("/") or ".." in name.split("/") or "\0" in name:
        raise ValueError("Unsafe package member: " + name)
    name = "/".join(part for part in name.split("/") if part not in ("", "."))
    for old, new in (("bin/", "usr/bin/"), ("sbin/", "usr/sbin/"), ("lib/", "usr/lib/"), ("lib64/", "usr/lib64/")):
        if name.startswith(old):
            name = new + name[len(old):]
    return name


def read_packages(packages, content):
    nodes = {"": Node(stat.S_IFDIR | 0o755)}
    hardlinks = []
    for package in packages:
        print("Extracting signed package", package["name"], package["version"], flush=True)
        payload = packages_lib.package_payload(package["path"])
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r|*") as archive:
            for member in archive:
                name = normalize(member.name)
                if not name or name in ("bin", "sbin", "lib", "lib64"):
                    continue
                if member.isdir():
                    nodes[name] = Node(stat.S_IFDIR | (member.mode & 0o7777), uid=member.uid, gid=member.gid)
                elif member.issym():
                    nodes[name] = Node(stat.S_IFLNK | 0o777, member.linkname.encode("utf-8"), member.uid, member.gid)
                elif member.islnk():
                    hardlinks.append((name, normalize(member.linkname), member))
                elif member.isfile():
                    # Stream into regular host files addressed by package/member;
                    # downloaded tar paths are never used as Windows filenames.
                    target = content / hashlib.sha256((package["name"] + "\0" + name).encode()).hexdigest()
                    with archive.extractfile(member) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                    nodes[name] = Node(stat.S_IFREG | (member.mode & 0o7777), target, member.uid, member.gid)
                else:
                    raise ValueError("Unsupported signed package member type: " + name)
    for name, target, member in hardlinks:
        source = nodes[target]
        nodes[name] = Node(source.mode, source.data, member.uid, member.gid)
    for name, destination in (("bin", "usr/bin"), ("sbin", "usr/sbin"), ("lib", "usr/lib"), ("lib64", "usr/lib64")):
        nodes[name] = Node(stat.S_IFLNK | 0o777, destination.encode())
    return nodes


def modules_from_iso(iso, output):
    stage = output / "kernel-modules"
    archive = output / "modloop-virt"
    if not stage.exists():
        archive.write_bytes(probe.extract(iso, "/boot/modloop-virt"))
        stage.mkdir()
        seven = ROOT / "tools/7zip/26.04/7z.exe"
        subprocess.run([str(seven), "x", str(archive), "-o" + str(stage), "-y", "-bb0"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=90)
    versions = list(stage.glob("modules/*/modules.dep"))
    if len(versions) != 1:
        raise ValueError("Unexpected module layout in official modloop")
    base = versions[0].parent
    deps = dict(line.split(":", 1) for line in versions[0].read_text("utf-8").splitlines())
    by_name = {Path(name).name.split(".ko")[0].replace("-", "_"): name for name in deps}

    def closure(names):
        result = []
        seen = set()
        def visit(name):
            if name in seen:
                return
            seen.add(name)
            for child in deps[name].split():
                visit(child)
            result.append(name)
        for name in names:
            if name not in by_name:
                raise ValueError("Expected kernel module missing: " + name)
            visit(by_name[name])
        return result
    boot = closure(["virtio_blk", "ext2", "overlay"])
    desktop = closure(["bochs", "evdev", "psmouse", "xhci_pci", "usbhid", "hid_generic", "e1000", "virtio_net", "zram"])
    return base, deps, boot, list(dict.fromkeys(boot + desktop))


def add_assets(nodes, agent, module_base, module_paths, keys):
    def add(name, data, mode=0o644):
        nodes[name] = Node(stat.S_IFREG | mode, data)
    for name in ("dev", "proc", "sys", "tmp", "run", "workspace", "root", "mnt", "etc/X11/xorg.conf.d",
                 "usr/local/bin", "usr/share/agenticvm/www", "etc/agenticvm", "etc/xdg/autostart"):
        nodes.setdefault(name, Node(stat.S_IFDIR | 0o755))
    # Avoid prepackaged desktop power/locking/autostart services. Core Xfce
    # session still starts its normal window manager, panel and desktop.
    for name in list(nodes):
        if name.startswith("etc/xdg/autostart/"):
            del nodes[name]
    add("sbin/agenticvm-init".replace("sbin/", "usr/sbin/"), (ROOT / "guest/desktop-init.sh").read_bytes().replace(b"\r\n", b"\n"), 0o755)
    add("usr/local/bin/agenticvm-desktop-session", (ROOT / "guest/desktop-session.sh").read_bytes().replace(b"\r\n", b"\n"), 0o755)
    add("usr/local/bin/agenticvm-browser", (ROOT / "guest/desktop-browser.sh").read_bytes().replace(b"\r\n", b"\n"), 0o755)
    add("etc/agenticvm/browser-user.js", (ROOT / "guest/desktop-browser-user.js").read_bytes().replace(b"\r\n", b"\n"))
    add("usr/local/bin/agentd", agent, 0o755)
    add("usr/share/agenticvm/www/index.html", (ROOT / "guest/desktop-fixture.html").read_bytes())
    add("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\nmessagebus:x:81:81:dbus:/run/dbus:/sbin/nologin\nagent:x:1000:1000:AgenticVM:/workspace:/bin/sh\n")
    add("etc/group", b"root:x:0:\ntty:x:5:\naudio:x:18:agent\nvideo:x:27:agent\ninput:x:28:agent\nmessagebus:x:81:\nagent:x:1000:\n")
    add("etc/shadow", b"root:!:0:0:99999:7:::\nagent:!:0:0:99999:7:::\n", 0o600)
    add("etc/hostname", b"agenticvm\n")
    add("etc/fstab", b"# Managed immutable root and optional owned workspace; no host mounts.\n")
    add("etc/apt/sources.list", b"deb https://deb.debian.org/debian trixie main\ndeb https://security.debian.org/debian-security trixie-security main\n")
    cert_prefix = "usr/share/ca-certificates/"
    public_cas = sorted(name[len(cert_prefix):] for name, node in nodes.items()
                        if name.startswith(cert_prefix) and name.endswith(".crt") and stat.S_ISREG(node.mode))
    if not public_cas:
        raise ValueError("Verified Debian package supplied no public CA certificates")
    add("etc/ca-certificates.conf", ("# Public CAs from the verified Debian ca-certificates package.\n" +
                                    "\n".join(public_cas) + "\n").encode("utf-8"))
    nodes["usr/sbin/udevd"] = Node(stat.S_IFLNK | 0o777, b"../lib/systemd/systemd-udevd")
    query = "usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/gdk-pixbuf-query-loaders"
    if query not in nodes:
        raise ValueError("Missing Debian pixbuf loader cache tool")
    nodes["usr/bin/gdk-pixbuf-query-loaders"] = Node(stat.S_IFLNK | 0o777, ("/" + query).encode())
    add("etc/X11/xorg.conf", b'''Section "ServerLayout"
 Identifier "AgenticVM"
 Screen "Screen0"
EndSection
Section "Device"
 Identifier "Video0"
 Driver "modesetting"
 Option "AccelMethod" "none"
 Option "SWcursor" "true"
EndSection
Section "Screen"
 Identifier "Screen0"
 Device "Video0"
 DefaultDepth 24
 SubSection "Display"
  Depth 24
  Modes "1024x768"
 EndSubSection
EndSection
''')
    add("etc/agenticvm/xfwm4.xml", b'''<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfwm4" version="1.0"><property name="general" type="empty">
<property name="use_compositing" type="bool" value="false"/>
<property name="workspace_count" type="int" value="1"/>
</property></channel>\n''')
    # BusyBox modprobe reads modules.dep without depmod execution on Windows.
    prefix = "usr/lib/modules/" + module_base.name + "/"
    for path in module_paths:
        add(prefix + path, module_base / path)
    for name in ("modules.dep", "modules.alias", "modules.builtin", "modules.order", "modules.softdep"):
        if (module_base / name).is_file():
            add(prefix + name, module_base / name)
    for name, data in keys.items():
        add("etc/apk/keys/" + name, data)


def make_boot_iso(source_iso, initrd, output, profile="desktop"):
    if profile not in {"desktop", "peer"}:
        raise ValueError("Unknown boot ISO profile")
    components = {"vmlinuz": probe.extract(source_iso, "/boot/vmlinuz-virt"), "initrd.gz": initrd,
                  "isolinux.bin": probe.extract(source_iso, "/boot/syslinux/isolinux.bin"),
                  "ldlinux.c32": probe.extract(source_iso, "/boot/syslinux/ldlinux.c32")}
    config = (f"DEFAULT {profile}\nPROMPT 0\nTIMEOUT 1\nLABEL {profile}\nKERNEL /boot/vmlinuz\n"
              "INITRD /boot/initrd.gz\nAPPEND rdinit=/init console=tty0 console=ttyS1,115200n8 loglevel=3 panic=0\n").encode()
    components["isolinux.cfg"] = components["syslinux.cfg"] = config
    target = output / f"agenticvm-linux-{profile}.iso"
    image = probe.pycdlib.PyCdlib()
    image.new(interchange_level=3, rock_ridge="1.09", vol_ident="AGENTICVM_" + profile.upper())
    image.add_directory("/BOOT", rr_name="boot")
    image.add_directory("/BOOT/SYSLINUX", rr_name="syslinux")
    paths = {}
    for name, data in components.items():
        file = output / name
        file.write_bytes(data)
        parent = "/BOOT" if name in ("vmlinuz", "initrd.gz") else "/BOOT/SYSLINUX"
        paths[name] = parent + "/" + name.upper() + (";1" if "." in name else ".;1")
        image.add_file(str(file), iso_path=paths[name], rr_name=name, creation_time=0)
    image.add_eltorito(paths["isolinux.bin"], bootcatfile="/BOOT/SYSLINUX/BOOT.CAT;1",
                      rr_bootcatname="boot.cat", boot_load_size=4, boot_info_table=True,
                      platform_id=0, media_name="noemul")
    image.write(str(target)); image.close()
    return target


def build(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source, provenance = probe.verified_iso()
    iso = probe.pycdlib.PyCdlib(); iso.open(str(source))
    try:
        initrd_source = probe.source_initrd(iso)
        keys = {Path(name).name: data for name, (_, data) in initrd_source.items() if name.startswith("etc/apk/keys/")}
        config = probe.extract(iso, "/boot/config-6.18.52-0-virt").decode()
        required = ("CONFIG_USER_NS=y", "CONFIG_PID_NS=y", "CONFIG_NET_NS=y", "CONFIG_SECCOMP=y", "CONFIG_SECCOMP_FILTER=y")
        if any(line not in config.splitlines() for line in required):
            raise ValueError("Kernel lacks Chromium sandbox namespaces/seccomp")
        packages, lock = packages_lib.prepare_packages(ROOT / "downloads/debian/trixie", REQUESTED,
                                                       ROOT / "tools/desktop-image-lock.json",
                                                       args.add_packages, args.replace_browser)
        content = output / "content"; content.mkdir(exist_ok=True)
        nodes = read_packages(packages, content)
        module_base, deps, boot_modules, all_modules = modules_from_iso(iso, output)
        agent = args.agent.read_bytes()
        if probe.elf_info(agent) != {"interpreter": None, "needed": []}:
            raise ValueError("Desktop agent must be static x86_64 ELF")
        add_assets(nodes, agent, module_base, all_modules, keys)
        root_disk = output / "rootfs.ext2"
        if root_disk.exists():
            raise FileExistsError("Use a fresh --output; refusing to overwrite rootfs.ext2")
        root_info = build_ext2(root_disk, nodes)
        print("Immutable ext2 root built", json.dumps(root_info), flush=True)
        for guest_path, source_file in (("/usr/sbin/agenticvm-init", "guest/desktop-init.sh"),
                                        ("/usr/local/bin/agenticvm-desktop-session", "guest/desktop-session.sh"),
                                        ("/usr/local/bin/agenticvm-browser", "guest/desktop-browser.sh"),
                                        ("/etc/agenticvm/browser-user.js", "guest/desktop-browser-user.js"),
                                        ("/usr/share/agenticvm/www/index.html", "guest/desktop-fixture.html")):
            if read_image_file(root_disk, guest_path) != (ROOT / source_file).read_bytes().replace(b"\r\n", b"\n"):
                raise ValueError("Final ext2 asset roundtrip failed: " + guest_path)
        if read_image_file(root_disk, "/usr/local/bin/agentd") != agent:
            raise ValueError("Final ext2 guest agent roundtrip failed")
        files = {n: (stat.S_IFDIR | 0o755, b"", 0, 0) for n in
                 ("bin", "lib", "dev", "proc", "sys", "lower", "overlay", "newroot", "modules")}
        busy_mode, busybox = initrd_source["usr/bin/busybox"]
        loader_mode, loader = initrd_source["usr/lib/ld-musl-x86_64.so.1"]
        module_names = []
        for path in boot_modules:
            # Module files in this release are uncompressed .ko. Fail closed if
            # a future release changes format rather than silently booting less.
            data = (module_base / path).read_bytes()
            if data[:4] != b"\x7fELF":
                raise ValueError("Boot module unexpectedly compressed")
            name = "modules/" + Path(path).name
            files[name] = (stat.S_IFREG | 0o644, data, 0, 0)
            module_names.append(name)
        init = (ROOT / "guest/desktop-bootstrap.sh").read_bytes().replace(b"\r\n", b"\n")
        init = init.replace(b"@BOOT_MODULES@", " ".join(module_names).encode())
        files.update({"init": (stat.S_IFREG | 0o755, init, 0, 0),
                      "bin/busybox": (busy_mode, busybox, 0, 0),
                      "bin/sh": (stat.S_IFLNK | 0o777, b"busybox", 0, 0),
                      "lib/ld-musl-x86_64.so.1": (loader_mode, loader, 0, 0),
                      "lib/libc.musl-x86_64.so.1": (stat.S_IFLNK | 0o777, b"ld-musl-x86_64.so.1", 0, 0),
                      "dev/console": (stat.S_IFCHR | 0o600, b"", 5, 1)})
        initrd = gzip.compress(probe.make_newc(files), compresslevel=9, mtime=0)
        image = make_boot_iso(iso, initrd, output)
    finally:
        iso.close()
    def record(path):
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        return {"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size, "sha256": digest}
    manifest = {"profile": "desktop", "os": "Debian GNU/Linux", "release": "13", "architecture": "x86_64",
                "desktop": "Xfce 4.20", "browser": "Firefox ESR",
                "browser_package": "firefox-esr", "browser_version": next(p["version"] for p in packages if p["name"] == "firefox-esr"),
                "source_iso": provenance, "kernel_version": module_base.name, "kernel_sandbox_facilities": list(required),
                "package_lock": "tools/desktop-image-lock.json", "package_count": len(packages),
                "package_lock_sha256": hashlib.sha256((ROOT / "tools/desktop-image-lock.json").read_bytes()).hexdigest(),
                "userland_provenance": lock.get("provenance", {}),
                "packages": [{k: p[k] for k in ("name", "version", "license", "origin", "source_commit", "homepage")}
                             for p in packages],
                "package_signatures_verified": True, "agent_sha256": hashlib.sha256(agent).hexdigest(),
                "root_disk": record(root_disk), "iso": record(image), "output": record(image),
                "boot_modules": boot_modules, "desktop_modules": all_modules,
                "memory_mib": 1024, "cpus": 1, "resolution": [1024, 768],
                "compressed_swap": {"logical_mib": 256, "maximum_physical_mib": 128, "algorithm": "lzo-rle", "swappiness": 100},
                "workspace": {"path": "/workspace", "optional_persistent_device": "/dev/vdb", "required_label": "AGENTICVM_DATA"},
                "display": ":0", "uid": 1000, "browser_sandbox_disabled": False, "runtime_verified": False}
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", "utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", type=Path, default=ROOT / "runtime/guest-build/agentd-desktop-profile")
    parser.add_argument("--output", type=Path, default=ROOT / "runtime/linux-desktop")
    parser.add_argument("--add-packages", action="store_true", help="Permit reviewed additions, preserving every existing package and index pin")
    parser.add_argument("--replace-browser", action="store_true", help="Permit reviewed package additions/removals, preserving retained versions and every index pin")
    build(parser.parse_args())
