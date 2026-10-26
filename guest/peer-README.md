# Headless Debian agent guest

The `agent` profile boots Debian 13 without Xorg, Xfce or Firefox. It shares the
existing read-only Debian filesystem with the desktop profile. A separate
14,022,656-byte boot ISO installs a new init and the 58,056-byte static command
service into a bounded RAM overlay; it never rewrites the shared base.

The default is 256 MiB guest RAM and one CPU. The writable root overlay and
ephemeral `/workspace` are each capped at 64 MiB, `/tmp` at 32 MiB and shared
memory at 16 MiB. Compressed swap has a 128 MiB logical size and 64 MiB physical
cap. These are limits inside the guest, not additional upfront host allocations.

Jobs run as UID/GID 1000 with `NoNewPrivs=1`, a 128 MiB virtual address limit,
32 MiB maximum file size, 64 file descriptors and 64 UID processes. The service
retains at most eight jobs, with two running concurrently. Explicit asynchronous
jobs may use timeout zero, so a small agent daemon can remain available. Guest
memory still bounds the whole VM. The service's ordinary command/file channel
remains separate from agent conversation bytes.

## Environment to virtual environment

`--peer-channel` adds a second virtio serial device named
`org.agenticvm.peer`. Init gives only UID 1000 access to its mode-0600 device at
`/dev/virtio-ports/org.agenticvm.peer`. The corresponding host endpoint is a
private AF_UNIX socket named `c` in that session's short temporary directory.
The normal command channel is `s` and the monitor is `q`.

No guest network card is needed. This byte transport does not itself encrypt
data: the installed agent endpoint must put authenticated TLS over it. The
controller's TLS agent protocol owns certificates, identities, framing, time
limits, message sizes and checkpoint policy.

## Virtual environment to virtual environment

Each pair receives a freshly allocated canonical UUID and a private socket
directory. Its only shared socket is `n`. QEMU's `stream` netdev connects the
two e1000 virtual network cards over that AF_UNIX socket, without a host network
interface, TCP listener, bridge, NAT or forwarding rule.

The listener has `192.0.2.1/30`; the connector has `192.0.2.2/30`. Init reads only
the strict `listen` or `connect` value from QEMU firmware configuration and
rejects an unexpected network card or role. Neither guest has a default route
or DNS configuration. Guest agent TLS endpoints communicate directly over this
Ethernet link; no host message relay is involved after provisioning.

The orchestrator must start the listener first, then the connector. It owns
the pair directory and may call `cleanup_pair_directory(pair_uuid)` only after
both exact VM processes have exited. A session stop cleans its own `s`, `q`
and optional `c` sockets, never the shared pair directory. Unknown files prevent
directory removal rather than being recursively deleted.

Optional packet capture uses only the session's fixed `vms/<owned-name>/peer.pcap`
path. Capture is a bounded experiment's diagnostic option, so the orchestrator
must stop the VMs when its checkpoint deadline expires.

## Controller API and CLI

```python
from uuid import uuid4
from agenticvm.qemu import prepare_pair_directory, cleanup_pair_directory

pair_uuid = str(uuid4())
prepare_pair_directory(pair_uuid)
# One distinct StateStore and QemuBackend instance per VM:
listener.start(iso, 256, profile="agent", root_disk=debian_base,
               isolated_link={"pair_uuid": pair_uuid, "role": "listen"})
connector.start(iso, 256, profile="agent", root_disk=debian_base,
                isolated_link={"pair_uuid": pair_uuid, "role": "connect"})
# Provision TLS agents and let them exchange messages.
# In finally: stop connector and listener, then clean the pair directory.
```

The equivalent start flags are:

```text
start --profile agent --peer-channel
start --profile agent --pair <prepared-UUID> --peer-role listen
start --profile agent --pair <prepared-UUID> --peer-role connect --peer-capture
```

`--pair` and `--peer-role` must appear together. Agent NAT is rejected. A reset
preserves the profile and explicit link settings. Resetting a pair should be
coordinated as a pair: stop both members and create/restart their link before
continuing conversation checkpoints.

## Rebuild and verified behavior

Compile `guest/agent.c` with the pinned Zig musl compiler and the existing
Windows Job Object build wrapper, then run:

```text
python -I scripts/run-bounded.py --output runtime/<fresh-build-log> -- python -I scripts/build-linux-peer.py --output runtime/<fresh-image-folder>
```

The builder verifies the immutable Debian root hash against its build manifest,
checks the static ELF, verifies the Alpine kernel source ISO checksum, verifies
the initramfs asset roundtrip, and refuses to overwrite a built peer ISO. It
does not download or rebuild Debian packages. The existing Alpine source
provenance records checksum verification and explicitly records that its GPG
signature was not verified.

On 17 October 2026, a 256 MiB headless VM booted ready in 7.08 seconds. Its real
Python 3.13.5/OpenSSL 3.5.7 process constructed a TLS 1.3 context within the job
memory limit; it reported UID 1000, `NoNewPrivs=1`, no display variable, no
graphical processes, empty routes and resolver, and a UID-1000 mode-0600 peer
device. A zero-deadline Python job started and was cancelled successfully.

Two fresh 256 MiB VMs then booted in 6.99 and 6.94 seconds. A Python TCP client
at `192.0.2.2` exchanged bytes with the guest server at `192.0.2.1`, over the
private QEMU Ethernet fabric. Both guests had only loopback and one Ethernet
device, only the connected `/30` route, and no resolver or default gateway.
Both VMs stopped and their exact session and pair sockets were cleaned.
These are headless runtime and transport checks; the encrypted agent loop has
its own end-to-end verification and checkpoints.

The build compiler peaked at 1,085,939,712 committed bytes in 10.656 seconds;
the boot ISO build peaked at 177,369,088 bytes in 4.926 seconds. Both completed
under the existing 1.5 GiB/two-CPU Job Object limit. A physical 4 GiB host was
not available for qualification.
