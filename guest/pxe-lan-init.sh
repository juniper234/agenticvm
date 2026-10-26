#!/bin/busybox sh
# Existing garden VMs: private LAN, no SSH, no host command channel.
BB=/bin/busybox
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin LANG=C.UTF-8 HOME=/workspace
export MALLOC_ARENA_MAX=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
umask 077
exec </dev/console >/dev/console 2>&1
$BB mkdir -p /run /dev/pts /dev/shm /tmp /workspace
$BB mount -t devpts -o gid=5,mode=0620 devpts /dev/pts || exit 1
$BB mount -t tmpfs -o size=32m,mode=1777,nosuid,nodev tmpfs /tmp || exit 1
$BB mount -t tmpfs -o size=16m,mode=1777,nosuid,nodev tmpfs /dev/shm || exit 1
mount -t ext2 -o rw,nosuid,nodev /dev/vdb /workspace || exit 1
chown 1000:1000 /workspace
chmod 0700 /workspace
hostname garden-pxe-lab
printf '127.0.0.1 localhost\n' >/etc/hosts
: >/etc/resolv.conf
chmod 0644 /etc/hosts /etc/resolv.conf
ip link set lo up || exit 1
modprobe e1000 || exit 1
address=$(cat /workspace/lab-address)
case "$address" in 192.0.2.[1-3]) ;; *) exit 1 ;; esac
ip link set eth0 up || exit 1
ip addr add "$address/24" dev eth0 || exit 1
/usr/sbin/ldconfig || exit 1
echo "PXE_GARDEN_BOOT_READY $address"
if [ "$address" = 192.0.2.1 ]; then
    /usr/bin/python3 -I /workspace/pxe_server.py >/workspace/pxe-server.log 2>&1 &
fi
$BB su garden -s /bin/sh -c '/bin/sh /workspace/lab/start.sh' &
while :; do
    if [ -f /workspace/lan-report.json ]; then
        printf 'LAN_REPORT '
        cat /workspace/lan-report.json
    fi
    sync
    $BB sleep 3
done
