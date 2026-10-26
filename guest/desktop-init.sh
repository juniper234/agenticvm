#!/bin/busybox sh
# PID 1 after switch_root. Debian userland; desktop lives outside command jobs.
BB=/bin/busybox
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export LANG=C.UTF-8 HOME=/workspace DISPLAY=:0
export XAUTHORITY=/workspace/.Xauthority XDG_RUNTIME_DIR=/run/user/1000
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
umask 022
exec </dev/console >/dev/console 2>&1
$BB --install -s /usr/bin
xorg_pid=
workspace_mounted=0
shutdown_guest() {
    trap '' TERM INT USR1
    /usr/bin/pkill -TERM -u 1000 2>/dev/null || true
    $BB sleep 1
    /usr/bin/pkill -KILL -u 1000 2>/dev/null || true
    [ -z "$xorg_pid" ] || kill "$xorg_pid" 2>/dev/null || true
    $BB sleep 0.2
    sync
    if [ "$workspace_mounted" = 1 ]; then
        umount /workspace || echo 'AgenticVM: workspace unmount failed after sync.'
    fi
    $BB poweroff -f
    while :; do $BB sleep 60; done
}
failed_init() {
    code=$?
    echo "AgenticVM: init exited with status $code; shutting down safely."
    shutdown_guest
}
trap failed_init EXIT
trap shutdown_guest TERM INT USR1
# Keep /run's initramfs backing mounts visible. /tmp and /dev/shm are bounded.
mkdir -p /run/user/1000 /run/dbus /run/lock /dev/pts /dev/shm /tmp /workspace
$BB mount -t devpts -o gid=5,mode=0620 devpts /dev/pts
$BB mount -t tmpfs -o size=96m,mode=1777,nosuid,nodev tmpfs /tmp || exit 1
$BB mount -t tmpfs -o size=96m,mode=1777,nosuid,nodev tmpfs /dev/shm || exit 1
echo 'AgenticVM: checking immutable base filesystem read-only.'
/usr/sbin/e2fsck -fn /dev/vda || { echo 'AgenticVM: immutable base filesystem check failed.'; exit 1; }
if [ -b /dev/vdb ]; then
    label=$(/usr/sbin/blkid -s LABEL -o value /dev/vdb)
    case "$label" in
        AGENTICVM_DATA)
            /usr/sbin/e2fsck -p /dev/vdb
            fsck_code=$?
            case "$fsck_code" in 0|1) ;; *) echo "AgenticVM: workspace recovery refused mount (e2fsck $fsck_code)"; exit 1 ;; esac
            $BB mount -t ext2 -o rw,nosuid,nodev /dev/vdb /workspace || exit 1 ;;
        *) echo 'AgenticVM: refusing an unrecognized workspace disk'; exit 1 ;;
    esac
else
    $BB mount -t tmpfs -o size=192m,mode=0700,nosuid,nodev tmpfs /workspace || exit 1
fi
workspace_mounted=1
chown 1000:1000 /workspace /run/user/1000
chmod 0700 /workspace /run/user/1000
mkdir -p /workspace/.config /workspace/.cache /workspace/Desktop
chown -R 1000:1000 /workspace/.config /workspace/.cache /workspace/Desktop
# Only stale locks in the single managed browser profile are cleared at boot.
# No browser is running yet. Keep all history, cookies, downloads and preferences.
for lock in .parentlock parent.lock lock SingletonLock SingletonCookie SingletonSocket; do
    rm -f "/workspace/.config/agenticvm-browser/$lock"
done
for module in bochs evdev psmouse xhci_pci usbhid hid_generic e1000 virtio_net; do
    modprobe "$module" 2>/dev/null || true
done
modprobe zram num_devices=1 || exit 1
echo lzo-rle >/sys/block/zram0/comp_algorithm || exit 1
echo 134217728 >/sys/block/zram0/mem_limit || exit 1
echo 268435456 >/sys/block/zram0/disksize || exit 1
/usr/sbin/mkswap /dev/zram0 >/dev/null || exit 1
/usr/sbin/swapon --priority 100 /dev/zram0 || exit 1
echo 100 >/proc/sys/vm/swappiness
echo 0 >/proc/sys/vm/page-cluster
echo 'AgenticVM: compressed swap 256 MiB logical, 128 MiB physical cap, lzo-rle.'
# Unprivileged Chromium uses its normal namespace/seccomp sandbox.
[ ! -f /proc/sys/kernel/unprivileged_userns_clone ] || echo 1 >/proc/sys/kernel/unprivileged_userns_clone
[ ! -f /proc/sys/user/max_user_namespaces ] || echo 1024 >/proc/sys/user/max_user_namespaces
echo agenticvm >/etc/hostname
hostname agenticvm
printf '127.0.0.1 localhost agenticvm\n::1 localhost\n' >/etc/hosts
printf 'nameserver 10.0.2.3\n' >/etc/resolv.conf
ip link set lo up
if ip link show eth0 >/dev/null 2>&1; then
    ip link set eth0 up
    # QEMU slirp's conventional subnet; networking is present only when opted in.
    ip addr add 10.0.2.15/24 dev eth0
    ip route add default via 10.0.2.2 dev eth0
fi
udevd --daemon
udevadm trigger --action=add
udevadm settle --timeout=5
dbus-uuidgen --ensure=/etc/machine-id
mkdir -p /var/lib/dbus
ln -sf /etc/machine-id /var/lib/dbus/machine-id
dbus-daemon --system --fork
/usr/sbin/ldconfig || exit 1
[ -s /etc/ca-certificates.conf ] || { echo 'AgenticVM: public CA configuration missing.'; exit 1; }
/usr/sbin/update-ca-certificates >/tmp/ca-certificates.log 2>&1 || { cat /tmp/ca-certificates.log; exit 1; }
[ -s /etc/ssl/certs/ca-certificates.crt ] || { echo 'AgenticVM: public CA bundle generation failed.'; cat /tmp/ca-certificates.log; exit 1; }
/usr/bin/update-mime-database /usr/share/mime || exit 1
/usr/bin/glib-compile-schemas /usr/share/glib-2.0/schemas || exit 1
/usr/bin/gdk-pixbuf-query-loaders --update-cache || exit 1
/usr/bin/gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || exit 1
/usr/bin/gtk-update-icon-cache -q -t -f /usr/share/icons/Adwaita || exit 1
/usr/bin/fc-cache || exit 1
cookie=$($BB hexdump -n 16 -e '16/1 "%02x"' /dev/urandom)
rm -f /workspace/.Xauthority
touch /workspace/.Xauthority
chmod 0600 /workspace/.Xauthority
xauth -f /workspace/.Xauthority add :0 . "$cookie" || exit 1
chown 1000:1000 /workspace/.Xauthority
Xorg :0 -noreset -nolisten tcp -auth /workspace/.Xauthority -config /etc/X11/xorg.conf -logfile /tmp/Xorg.0.log vt1 >/tmp/xorg-console.log 2>&1 &
xorg_pid=$!
count=0
while ! xdpyinfo >/dev/null 2>&1; do
    count=$((count + 1)); [ "$count" -lt 100 ] || { cat /tmp/Xorg.0.log; exit 1; }
    $BB sleep 0.1
done
xrandr --output Virtual-1 --mode 1024x768 2>/dev/null || xrandr --size 1024x768 2>/dev/null || true
$BB httpd -f -p 127.0.0.1:8080 -h /usr/share/agenticvm/www >/tmp/httpd.log 2>&1 &
httpd_pid=$!
count=0
while ! /usr/bin/curl --fail --silent --noproxy '*' --max-time 2 http://127.0.0.1:8080/ >/tmp/fixture-check.html; do
    count=$((count + 1)); [ "$count" -lt 20 ] || { cat /tmp/httpd.log; exit 1; }
    $BB sleep 0.1
done
$BB grep -q 'AgenticVM Desktop Ready' /tmp/fixture-check.html || exit 1
$BB su agent -s /bin/sh -c '/usr/local/bin/agenticvm-desktop-session' >/tmp/desktop-session.log 2>&1 &
count=0
while [ ! -f /run/user/1000/agenticvm-desktop-ready ]; do
    count=$((count + 1)); [ "$count" -lt 200 ] || { cat /tmp/desktop-session.log; exit 1; }
    $BB sleep 0.1
done
echo 'AgenticVM: Debian desktop and sandboxed Firefox ESR ready.'
channel=/dev/ttyS0
[ ! -c /dev/vport0p1 ] || channel=/dev/vport0p1
exec 3<>"$channel"
/usr/local/bin/agentd --profile desktop --workspace /workspace --uid 1000 --gid 1000 <&3 >&3 3>&- 2>/dev/console
code=$?
exec 3>&-
echo "AgenticVM: desktop agent exited ($code)."
shutdown_guest
while :; do $BB sleep 60; done
