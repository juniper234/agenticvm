#!/bin/busybox sh
# Downloaded over the trusted private PXE LAN. No local operating system disk.
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
modprobe virtio_pci || exit 1
modprobe virtio_blk || exit 1
modprobe ext2 || exit 1
modprobe e1000 || exit 1
count=0
while [ ! -b /dev/vda ]; do
    count=$((count+1)); [ "$count" -lt 100 ] || exit 1
    $BB sleep 0.1
done
# This is the experiment's new, empty nonbootable data volume, never an existing OS.
mount -t ext2 -o rw,nosuid,nodev /dev/vda /workspace || exit 1
[ -f /workspace/owned-pxe-data ] || exit 1
chown 1000:1000 /workspace
chmod 0700 /workspace
printf '127.0.0.1 localhost\n' >/etc/hosts
: >/etc/resolv.conf
chmod 0644 /etc/hosts /etc/resolv.conf
ip link set lo up || exit 1
ip link set eth0 up || exit 1
ip addr add 192.0.2.4/24 dev eth0 || exit 1
/usr/sbin/ldconfig || exit 1
echo 'PXE_TARGET_BOOT_READY 192.0.2.4'
echo 'PXE_AGENT_ABSENT 192.0.2.4'
$BB su garden -s /bin/sh -c '/usr/bin/python3 -I /boot-provision.py' &
while :; do
    if [ -f /workspace/pxe-result.json ]; then
        printf 'PXE_TARGET_REPORT '
        cat /workspace/pxe-result.json
    fi
    sync
    $BB sleep 3
done
