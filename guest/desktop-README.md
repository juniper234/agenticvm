# Desktop image

The desktop guest uses **Debian GNU/Linux 13 “Trixie”, x86_64**, **Xfce 4.20**,
and the official Debian-security **Firefox ESR 153.5.0** package. It reuses the
SHA256-verified Alpine 3.24.2 release's **6.18.52-0-virt** kernel with a tiny
custom boot/init layer. Xfce runs without a compositor. Debian supplies glibc
compatibility and a current supported browser; Firefox keeps its normal Linux
namespace/seccomp sandbox.

The earlier Alpine desktop prototype exposed an actual Chromium GPU seccomp
failure on `pwritev2`; the available signed Alpine Firefox packages lagged
Mozilla's supported releases. The desktop switched to Debian's signed security
package. The separate command-only guest remains minimal.

Desktop files live in an automatically sized sparse ext2 disk. The roughly
13.3 MiB boot ISO includes only the kernel, BusyBox, musl and the small module
closure needed to mount that disk. There is no expanded desktop initramfs copy
in guest RAM. Disk size and guest RAM allocation are separate quantities.

## Build

Requirements: the existing verified Alpine release ISO for its kernel, verified
local 7-Zip, Python, Git's existing GPG tools, and a static Linux x86_64 guest
agent with desktop profile support. Packages come from official Debian main and
Debian-security repositories. From the workspace root:

```powershell
python scripts/run-bounded.py --memory-mib 1536 --seconds 240 `
  --output runtime/build-desktop-<unique-name> -- `
  python.exe -I scripts/build-linux-desktop.py `
  --agent runtime/guest-build/agentd-desktop-profile `
  --output runtime/linux-desktop
```

Use a fresh output directory if an existing root image is in use. The builder
refuses to overwrite `rootfs.ext2`. Never replace an ISO or root disk while a VM
has it open.

`tools/desktop-image-lock.json` pins Debian archive key hashes/fingerprints,
signed release metadata, index hashes and package hashes/versions. `gpgv`
verifies pinned official Debian keys in an isolated workspace directory. The
builder checks release validity, the index SHA256/size from signed `InRelease`,
and every `.deb` SHA256 from that index. A modified cache entry fails verification.
No package program or installation script executes on Windows. Copyright files
remain inside `/usr/share/doc/<package>/copyright`.

The resolver includes Essential packages, versioned dependencies, `Pre-Depends`,
alternatives and virtual providers. It excludes optional Recommends/Suggests.
Boot creates library, certificate, MIME, GSettings, pixbuf, icon and font caches.
The CA configuration explicitly selects the 150 public Mozilla certificates
from the verified Debian package; startup requires a nonempty resulting trust
bundle. Host certificates are not imported. Noto CJK and color-emoji fonts
provide actual glyph rendering alongside DejaVu.
Package pins stay fixed until a reviewed update; expired repository metadata
requires a new verified update.

Package tar paths become explicit image metadata rather than host symlinks or
permissions. Payload bytes stream into owned regular files before the pure
Python ext2 writer emits the disk. Final init/session/browser scripts and agent
ELF bytes are read back from ext2 and compared independently. The manifest
records output hashes. Container ISO timestamps can vary: input pins are
reproducible without claiming bit-identical ISO containers.

## Boot and storage

Attach `rootfs.ext2` read-only as the first virtio block device and boot the
desktop ISO. The initramfs loads block/ext2/overlay dependencies, mounts
`/dev/vda` read-only, and switches to an overlay with a 192 MiB tmpfs upper limit.
Temporary root changes disappear on restart. Debian's static BusyBox is PID1;
installed systemd libraries/tools do not make systemd the running init system.

An optional second virtio block device, `/dev/vdb`, persists `/workspace`. Its
ext2 label must be `AGENTICVM_DATA`; unknown disks are refused and never formatted.
Before mounting, `e2fsck -p` must exit with 0 or 1. Other results preserve the
disk and refuse the mount. Create a new managed disk with the packaged
`agenticvm.ext2.create_empty_workspace_disk` function, or:

```powershell
python scripts/desktop-image-ext2.py --workspace <new-owned-path>.ext2 --size-mib 512
```

The writer refuses existing destinations, attempts Windows sparse allocation on
the newly created file handle, and rounds sizes to 128 MiB block groups. Without
a persistent disk, `/workspace` is a 192 MiB tmpfs. `/tmp` and `/dev/shm` each have
96 MiB tmpfs limits. These are limits, not upfront memory reservations.

Orderly shutdown terminates desktop user processes, allows one second for browser
state to flush, kills stragglers, syncs and unmounts `/workspace`, then powers off.
The same cleanup is installed early for failed init paths. Forced termination can
still interrupt writes; the next boot performs recovery before mounting.

The immutable base also receives a forced read-only `e2fsck -fn` check before
desktop startup. An independently discovered tar-root alias bug was corrected:
a bare `.` archive entry is the existing filesystem root, never another child
directory. Regression tests reject dot aliases, and the finished disk has been
opened by the independent 7-Zip ext2 parser. Its extracted 183,768,576-byte
Firefox `libxul.so` exactly matched the verified Debian package payload.

## Desktop session

Use standard QEMU VGA at 1024×768, virtio serial for agent control, and optionally
an e1000 adapter on QEMU user-mode networking. The module closure supports the
XHCI USB keyboard/tablet. Init creates a fresh Xauthority cookie each boot,
starts Xorg without a TCP listener, and starts the desktop as UID/GID 1000.
Readiness requires successful local HTTP, a visible Firefox fixture title, a
live panel/window manager and a two-second stability interval.

The desktop job environment includes:

```text
HOME=/workspace
DISPLAY=:0
XAUTHORITY=/workspace/.Xauthority
XDG_RUNTIME_DIR=/run/user/1000
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
```

Firefox starts maximized with its normal toolbar, software rendering, a 32 MiB
disk-cache limit and bounded memory caches. No sandbox-disabling flag or
preference is used. Runtime checks verified a Firefox tab process running as
UID 1000 with `NoNewPrivs: 1` and `Seccomp: 2`. The forkserver helper was
recorded separately; these tab-process results do not describe every Firefox
process.

Text insertion uses the guest's X11 selections and Shift+Insert through the
verified `xclip` package, avoiding Unicode keyboard-map races. The host clipboard
is unaffected. Real Firefox and terminal probes preserved accented Latin,
Greek, Chinese and emoji text exactly.

Content process prelaunch is disabled; normal content-process count is limited
to two and the per-site isolated count to one. Site isolation and browser
sandbox settings remain enabled. The guest has 256 MiB logical LZO-RLE zram
swap with a 128 MiB data-allocation cap. It uses guest RAM dynamically and
never changes host swap settings. Swappiness is 100; zram usage/compression is
inspectable through `/sys/block/zram0/mm_stat` and `/proc/swaps`. Persistent
workspace storage avoids keeping browser profile bytes in a large tmpfs.

`/usr/local/bin/agenticvm-browser [URL]` is the fixed entry point for reopening
Firefox. Its one quoted argument accepts HTTP(S) and `about:blank`; it does not
evaluate URL text as shell code. It waits for its child so agent job cancellation
can stop the process group. Boot clears only exact known stale browser lock
names inside the managed profile; other user data is preserved.

A loopback-only BusyBox HTTP server provides `http://127.0.0.1:8080/`. Typing and
submitting a message changes both page output and actual browser title, enabling
end-to-end verification without a browser debugging port. Optional QEMU user
networking uses its private 10.0.2.0/24 subnet and DNS proxy. Certificate caches
are generated for real HTTPS.

The optional fixture URL `http://127.0.0.1:8080/?scroll=1` creates a taller page
whose actual scroll events update the browser title with `scrollY`, allowing
mouse-wheel verification without a debugging port.

The default 768 MiB guest configuration passed 10 desktop end-to-end checks,
18 live guest checks and 10 official MCP checks; 1024 MiB is also available.
The 512 MiB desktop experiment exhausted compressed swap and timed out during
browser navigation after its first three checks, so 512 MiB is unsupported for
the desktop profile. A physical 4 GB Windows host remains unverified: Windows,
the viewer, QEMU and browser workload share that total budget.
