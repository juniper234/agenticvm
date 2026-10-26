#!/bin/busybox sh
# This bootstrap is downloaded from the mother, never placed on the virgin disk.
BB=/bin/busybox
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin LANG=C.UTF-8 HOME=/workspace
export MALLOC_ARENA_MAX=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
umask 077
$BB mount -t devtmpfs devtmpfs /dev || exit 1
exec </dev/console >/dev/console 2>&1
$BB mount -t proc proc /proc || exit 1
$BB mount -t sysfs sysfs /sys || exit 1
$BB mkdir -p /run /dev/pts /dev/shm /tmp /workspace
$BB mount -t devpts -o gid=5,mode=0620 devpts /dev/pts || exit 1
$BB mount -t tmpfs -o size=32m,mode=1777,nosuid,nodev tmpfs /tmp || exit 1
$BB mount -t tmpfs -o size=16m,mode=1777,nosuid,nodev tmpfs /dev/shm || exit 1
# RAM only. Existing/blank block storage is never mounted or formatted.
$BB mount -t tmpfs -o size=512m,mode=0700,nosuid,nodev tmpfs /workspace || exit 1
chown 1000:1000 /workspace
printf '127.0.0.1 localhost\n' >/etc/hosts
: >/etc/resolv.conf
chmod 0644 /etc/hosts /etc/resolv.conf
modprobe e1000 || exit 1
ip link set lo up || exit 1
ip link set eth0 up || exit 1
ip addr add 192.0.2.4/24 dev eth0 || exit 1
/usr/sbin/ldconfig || exit 1
echo 'INDEPENDENT_NETWORK_BOOT_READY'
echo 'INDEPENDENT_AGENT_ABSENT_AT_BOOT'
if [ -f /probe-only ]; then
    echo 'INDEPENDENT_DEFAULT_FIRMWARE_EXECUTED_NETWORK_PAYLOAD'
else
    $BB su garden -s /bin/sh -c '/usr/bin/python3 -I /boot-provision.py' &
fi
while :; do
    if [ -f /workspace/pxe-result.json ]; then
        printf 'PXE_TARGET_REPORT '
        cat /workspace/pxe-result.json
    fi
    $BB sleep 3
done
