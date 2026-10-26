#!/bin/busybox sh
# Explicit already-booting OS control: DHCP enabled, no agent/provisioner invoked.
BB=/bin/busybox
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
$BB mount -t devtmpfs devtmpfs /dev || exit 1
exec </dev/console >/dev/console 2>&1
$BB mount -t proc proc /proc || exit 1
$BB mount -t sysfs sysfs /sys || exit 1
$BB mkdir -p /run
modprobe e1000 || exit 1
modprobe af_packet || exit 1
ip link set lo up
ip link set eth0 up || exit 1
$BB udhcpc -i eth0 -f -n -q -t 10 -T 3 -s /dhcp-hook.sh || exit 1
echo BASIC_LINUX_DHCP_READY_NO_AGENT
while :; do $BB sleep 3; done
