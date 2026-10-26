#!/bin/busybox sh
# Debian headless PID 1: no display server, desktop, browser, NAT or host mounts.
BB=/bin/busybox
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export LANG=C.UTF-8 HOME=/workspace
unset DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS
umask 022
exec </dev/console >/dev/console 2>&1
$BB --install -s /usr/bin
workspace_mounted=0
shutdown_guest() {
    trap '' TERM INT USR1
    /usr/bin/pkill -TERM -u 1000 2>/dev/null || true
    $BB sleep 0.2
    /usr/bin/pkill -KILL -u 1000 2>/dev/null || true
    sync
    [ "$workspace_mounted" != 1 ] || umount /workspace || true
    $BB poweroff -f
    while :; do $BB sleep 60; done
}
failed_init() { echo "AgenticVM: headless init failed ($?)."; shutdown_guest; }
trap failed_init EXIT
trap shutdown_guest TERM INT USR1
mkdir -p /run/user/1000 /dev/pts /dev/shm /tmp /workspace /dev/virtio-ports
$BB mount -t devpts -o gid=5,mode=0620 devpts /dev/pts || exit 1
$BB mount -t tmpfs -o size=32m,mode=1777,nosuid,nodev tmpfs /tmp || exit 1
$BB mount -t tmpfs -o size=16m,mode=1777,nosuid,nodev tmpfs /dev/shm || exit 1
/usr/sbin/e2fsck -fn /dev/vda || exit 1
if [ -b /dev/vdb ]; then
    label=$(/usr/sbin/blkid -s LABEL -o value /dev/vdb)
    [ "$label" = AGENTICVM_DATA ] || { echo 'AgenticVM: refusing unrecognized workspace.'; exit 1; }
    /usr/sbin/e2fsck -p /dev/vdb
    code=$?
    case "$code" in 0|1) ;; *) exit 1 ;; esac
    $BB mount -t ext2 -o rw,nosuid,nodev /dev/vdb /workspace || exit 1
else
    $BB mount -t tmpfs -o size=64m,mode=0700,nosuid,nodev tmpfs /workspace || exit 1
fi
workspace_mounted=1
chown 1000:1000 /workspace /run/user/1000
chmod 0700 /workspace /run/user/1000
modprobe zram num_devices=1 || exit 1
echo lzo-rle >/sys/block/zram0/comp_algorithm || exit 1
echo 67108864 >/sys/block/zram0/mem_limit || exit 1
echo 134217728 >/sys/block/zram0/disksize || exit 1
/usr/sbin/mkswap /dev/zram0 >/dev/null || exit 1
/usr/sbin/swapon --priority 100 /dev/zram0 || exit 1
echo 80 >/proc/sys/vm/swappiness
echo 0 >/proc/sys/vm/page-cluster
hostname agenticvm
printf '127.0.0.1 localhost agenticvm\n::1 localhost\n' >/etc/hosts
# Empty resolver plus no default route: isolated guests have no internet/DNS path.
: >/etc/resolv.conf
ip link set lo up || exit 1
modprobe e1000 2>/dev/null || true
role_file=/sys/firmware/qemu_fw_cfg/by_name/opt/agenticvm/peer-role/raw
if [ -f "$role_file" ]; then
    role=$(cat "$role_file")
    case "$role" in
        listen) address=192.0.2.1/30 ;;
        connect) address=192.0.2.2/30 ;;
        *) echo 'AgenticVM: refusing an invalid isolated role.'; exit 1 ;;
    esac
    ip link set eth0 up || exit 1
    ip addr add "$address" dev eth0 || exit 1
    echo "AgenticVM: isolated Ethernet $role at $address, no gateway or DNS."
elif ip link show eth0 >/dev/null 2>&1; then
    echo 'AgenticVM: refusing an unconfigured network device.'; exit 1
fi
/usr/sbin/ldconfig || exit 1
[ -s /etc/ca-certificates.conf ] || exit 1
/usr/sbin/update-ca-certificates >/tmp/ca-certificates.log 2>&1 || exit 1
[ -s /etc/ssl/certs/ca-certificates.crt ] || exit 1
[ ! -c /dev/vport0p2 ] || {
    chown 1000:1000 /dev/vport0p2 || exit 1
    chmod 0600 /dev/vport0p2 || exit 1
    ln -sf /dev/vport0p2 /dev/virtio-ports/org.agenticvm.peer || exit 1
}
[ -c /dev/vport0p1 ] || { echo 'AgenticVM: control channel absent.'; exit 1; }
echo 'AgenticVM: Debian headless agent ready as UID 1000.'
exec 3<>/dev/vport0p1
/usr/local/bin/agentd --profile agent --workspace /workspace --uid 1000 --gid 1000 <&3 >&3 3>&- 2>/dev/console
exec 3>&-
shutdown_guest
