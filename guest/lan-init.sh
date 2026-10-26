#!/bin/busybox sh
# Explicit isolated lab profile. No host command channel or automatic receiver.
BB=/bin/busybox
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin LANG=C.UTF-8 HOME=/workspace
export MALLOC_ARENA_MAX=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
umask 077
exec </dev/console >/dev/console 2>&1
$BB mkdir -p /run/sshd /dev/pts /dev/shm /tmp /workspace
$BB mount -t devpts -o gid=5,mode=0620 devpts /dev/pts || exit 1
$BB mount -t tmpfs -o size=32m,mode=1777,nosuid,nodev tmpfs /tmp || exit 1
$BB mount -t tmpfs -o size=16m,mode=1777,nosuid,nodev tmpfs /dev/shm || exit 1
mount -t ext2 -o rw,nosuid,nodev /dev/vdb /workspace || exit 1
chown 1000:1000 /workspace
chmod 0700 /workspace
hostname garden-lab
printf '127.0.0.1 localhost\n' >/etc/hosts
: >/etc/resolv.conf
chmod 0644 /etc/hosts /etc/resolv.conf
ip link set lo up || exit 1
modprobe e1000 || exit 1
address=$(cat /workspace/lab-address)
case "$address" in 192.0.2.[1-5]) ;; *) echo 'Invalid lab-only address'; exit 1 ;; esac
ip link set eth0 up || exit 1
ip addr add "$address/24" dev eth0 || exit 1
/usr/sbin/ldconfig || exit 1
echo "LAN_BOOT_READY $address"
# SSH is an explicit preauthorized baseline, not a hidden garden installer.
if [ -f /workspace/sshd_config ]; then
    /usr/sbin/sshd -D -e -f /workspace/sshd_config >/workspace/sshd.log 2>&1 &
fi
# Only mother/offshoot fixture disks carry an application start script.
# Fresh target and negative control disks contain no such script.
if [ -f /workspace/lab/start.sh ]; then
    /bin/busybox su garden -s /bin/sh -c '/bin/sh /workspace/lab/start.sh' &
fi
shutdown_lab() {
    sync
    /bin/busybox poweroff -f
    while :; do /bin/busybox sleep 30; done
}
trap shutdown_lab TERM INT USR1
while :; do
    if [ ! -e /workspace/peer/lan_agent.py ] && [ ! -e /workspace/model.gguf ]; then
        echo "LAN_AGENT_ABSENT $address"
    fi
    if [ -f /workspace/lan-report.json ]; then
        printf 'LAN_REPORT '
        cat /workspace/lan-report.json
    fi
    /bin/busybox sleep 3
done
