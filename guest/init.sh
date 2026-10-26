#!/bin/busybox sh
# PID 1 for the diskless development guest. Serial is reserved for agent RPC.
BB=/bin/busybox
export PATH=/bin:/usr/bin
export HOME=/workspace
export LANG=C
umask 077
$BB mount -t devtmpfs devtmpfs /dev || exit 1
exec </dev/console >/dev/console 2>&1
$BB mount -t proc proc /proc || exit 1
$BB mount -t sysfs -o ro sysfs /sys || exit 1
$BB mount -t tmpfs -o size=32m,mode=1777,nosuid,nodev tmpfs /tmp || exit 1
$BB mount -t tmpfs -o size=64m,mode=0700,nosuid,nodev tmpfs /workspace || exit 1
$BB chown 1000:1000 /workspace || exit 1
$BB --install -s /bin
echo 'AgenticVM: Linux command guest starting; workspace is temporary.'

shutdown_guest() {
    $BB sync
    $BB poweroff -f
}
trap shutdown_guest TERM INT USR1

# The service drops supplementary groups and UID/GID before accepting requests.
# PID 1 remains available only to finish the guest shutdown sequence.
channel=/dev/ttyS0
if [ -c /dev/vport0p1 ]; then channel=/dev/vport0p1; fi
echo "AgenticVM: control channel $channel"
exec 3<>"$channel"
/bin/agentd --workspace /workspace --uid 1000 --gid 1000 <&3 >&3 3>&- 2>/dev/console
service_exit=$?
exec 3>&-
echo "AgenticVM: service exited ($service_exit); powering off."
shutdown_guest
while :; do $BB sleep 60; done
