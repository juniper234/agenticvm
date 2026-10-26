#!/bin/busybox sh
# Tiny initramfs PID 1: immutable block root, RAM upper layer, then real init.
BB=/bin/busybox
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
$BB mount -t devtmpfs devtmpfs /dev || exit 1
exec </dev/console >/dev/console 2>&1
$BB mount -t proc proc /proc || exit 1
$BB mount -t sysfs sysfs /sys || exit 1
$BB --install -s /bin
echo 'AgenticVM: mounting immutable Debian desktop root.'
for module in @BOOT_MODULES@; do $BB insmod "/$module" || exit 1; done
count=0
while [ ! -b /dev/vda ]; do
    count=$((count + 1)); [ "$count" -lt 100 ] || exit 1
    $BB sleep 0.1
done
$BB mount -t ext2 -o ro /dev/vda /lower || exit 1
$BB mount -t tmpfs -o size=192m,mode=0755 tmpfs /overlay || exit 1
$BB mkdir -p /overlay/upper /overlay/work
$BB mount -t overlay overlay -o lowerdir=/lower,upperdir=/overlay/upper,workdir=/overlay/work /newroot || exit 1
# Boot-only UI updates may override this one guest-local page in the RAM upper
# layer. The block base stays read-only; no downloaded code or host mount runs.
if [ -f /assets/desktop-fixture.html ]; then
    $BB cp /assets/desktop-fixture.html /newroot/usr/share/agenticvm/www/index.html || exit 1
    $BB chmod 0644 /newroot/usr/share/agenticvm/www/index.html || exit 1
fi
$BB mkdir -p /newroot/run/agenticvm-root /newroot/run/agenticvm-overlay
$BB mount --move /dev /newroot/dev || exit 1
$BB mount --move /proc /newroot/proc || exit 1
$BB mount --move /sys /newroot/sys || exit 1
$BB mount --move /lower /newroot/run/agenticvm-root || exit 1
$BB mount --move /overlay /newroot/run/agenticvm-overlay || exit 1
exec $BB switch_root /newroot /sbin/agenticvm-init
