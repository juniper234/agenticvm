#!/bin/busybox sh
# Offline diagnostic early userspace. This is not a complete Alpine installation.
BB=/bin/busybox
export PATH=/bin
$BB mount -t devtmpfs devtmpfs /dev || exit 1
exec </dev/ttyS0 >/dev/ttyS0 2>&1
$BB mount -t proc proc /proc || exit 1
$BB mount -t sysfs sysfs /sys || exit 1
$BB mount -t tmpfs -o size=16m,mode=1777 tmpfs /tmp || exit 1

stop_probe() {
    echo AGENTICVM_PROBE_SHUTDOWN
    $BB sync
    $BB poweroff -f
}
trap stop_probe TERM INT USR1

echo AGENTICVM_PROBE_BEGIN
echo 'SCOPE=Linux_kernel_and_BusyBox_early_userspace_only'
echo 'NETWORK=unconfigured; STORAGE_TEST=tmpfs_only; LOGIN=none'
$BB uname -a
echo MEMINFO_BEGIN
$BB cat /proc/meminfo
echo MEMINFO_END
echo UPTIME
$BB cat /proc/uptime

# Bounded RAM-backed file exercise, deliberately no attached-disk writes.
if $BB dd if=/dev/zero of=/tmp/probe.bin bs=1024 count=1024 2>/dev/null; then
    result=$($BB sha256sum /tmp/probe.bin)
    actual=${result%% *}
    echo "TMPFS_FILE_SHA256=$actual"
    if [ "$actual" = '@PAYLOAD_SHA256@' ]; then
        echo TMPFS_FILE_TEST=PASS
    else
        echo TMPFS_FILE_TEST=FAIL
    fi
else
    echo TMPFS_FILE_TEST=FAIL
fi
$BB rm -f /tmp/probe.bin
$BB sync
echo 'AGENTICVM_PROBE_IDLE; serial commands: status or poweroff'

# No shell login or command evaluator. Only the two diagnostic commands exist.
while :; do
    if read -r command; then
        case "$command" in
            status)
                $BB cat /proc/uptime
                $BB cat /proc/meminfo
                ;;
            poweroff) stop_probe ;;
            '') ;;
            *) echo UNKNOWN_PROBE_COMMAND ;;
        esac
    else
        $BB sleep 1
    fi
done
