#!/bin/busybox sh
# Headless boot overlay. The shared Debian base remains immutable and unchanged.
BB=/bin/busybox
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
$BB mount -t devtmpfs devtmpfs /dev || exit 1
exec </dev/console >/dev/console 2>&1
$BB mount -t proc proc /proc || exit 1
$BB mount -t sysfs sysfs /sys || exit 1
$BB --install -s /bin
echo 'AgenticVM: mounting immutable Debian agent root.'
for module in @BOOT_MODULES@; do $BB insmod "/$module" || exit 1; done
count=0
while [ ! -b /dev/vda ]; do
    count=$((count + 1)); [ "$count" -lt 100 ] || exit 1
    $BB sleep 0.1
done
$BB mount -t ext2 -o ro /dev/vda /lower || exit 1
$BB mount -t tmpfs -o size=64m,mode=0755 tmpfs /overlay || exit 1
$BB mkdir -p /overlay/upper /overlay/work
$BB mount -t overlay overlay -o lowerdir=/lower,upperdir=/overlay/upper,workdir=/overlay/work /newroot || exit 1
$BB cp /assets/peer-init.sh /newroot/usr/sbin/agenticvm-peer-init || exit 1
$BB cp /assets/agentd /newroot/usr/local/bin/agentd || exit 1
$BB chmod 0755 /newroot/usr/sbin/agenticvm-peer-init /newroot/usr/local/bin/agentd
$BB mkdir -p /newroot/run/agenticvm-root /newroot/run/agenticvm-overlay
$BB mount --move /dev /newroot/dev || exit 1
$BB mount --move /proc /newroot/proc || exit 1
$BB mount --move /sys /newroot/sys || exit 1
$BB mount --move /lower /newroot/run/agenticvm-root || exit 1
$BB mount --move /overlay /newroot/run/agenticvm-overlay || exit 1
exec $BB switch_root /newroot /usr/sbin/agenticvm-peer-init
