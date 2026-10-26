#!/bin/busybox sh
# Downloaded RAM environment; no block device is mounted or written.
BB=/bin/busybox
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin LANG=C.UTF-8 HOME=/workspace
export MALLOC_ARENA_MAX=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
# Keep the original quantized buffers instead of allocating repacked copies.
export LLAMA_ARG_REPACK=0
umask 077
$BB mount -t devtmpfs devtmpfs /dev || exit 1
exec </dev/console >/dev/console 2>&1
$BB mount -t proc proc /proc || exit 1
$BB mount -t sysfs sysfs /sys || exit 1
$BB mkdir -p /run /dev/pts /dev/shm /tmp /workspace
$BB mount -t devpts -o gid=5,mode=0620 devpts /dev/pts || exit 1
$BB mount -t tmpfs -o size=32m,mode=1777,nosuid,nodev tmpfs /tmp || exit 1
$BB mount -t tmpfs -o size=16m,mode=1777,nosuid,nodev tmpfs /dev/shm || exit 1
$BB mount -t tmpfs -o size=512m,mode=0700,nosuid,nodev tmpfs /workspace || exit 1
chown 1000:1000 /workspace
printf '127.0.0.1 localhost\n' >/etc/hosts
: >/etc/resolv.conf
chmod 0644 /etc/hosts /etc/resolv.conf
ip link set lo up || exit 1
modprobe e1000 2>/dev/null
modprobe e1000e 2>/dev/null
modprobe virtio_net 2>/dev/null
modprobe af_packet || exit 1
ip link set eth0 up || exit 1
if [ -f /infrastructure ]; then
    ip addr add 192.0.2.5/24 dev eth0 || exit 1
    /usr/bin/python3 -I /realism-dhcp.py &
else
    # Linux obtains its own lease; the firmware lease is not assumed.
    $BB udhcpc -i eth0 -f -n -t 10 -T 3 -s /dhcp-hook.sh &
    dhcp_pid=$!
    attempts=0
    while [ ! -s /run/network-bound ]; do
        kill -0 "$dhcp_pid" || exit 1
        attempts=$((attempts + 1))
        [ "$attempts" -le 40 ] || exit 1
        $BB sleep 1
    done
    /usr/sbin/ldconfig || exit 1
    echo REALISM_AGENT_ABSENT_AT_BOOT
    if [ -f /probe-only ]; then
        echo REALISM_NETWORK_BOOT_EXECUTED
    else
        $BB su garden -s /bin/sh -c '/usr/bin/python3 -I /boot-provision.py' &
    fi
fi
printed=0
model_environment_observed=0
while :; do
    if [ "$model_environment_observed" = 0 ] && [ ! -f /probe-only ]; then
        for process in /proc/[0-9]*/comm; do
            [ "$(cat "$process" 2>/dev/null)" = llama-server ] || continue
            directory=${process%/comm}
            if $BB tr '\0' '\n' < "$directory/environ" | $BB grep -qx 'LLAMA_ARG_REPACK=0'; then
                echo REALISM_LFM_REPACK_DISABLED
                model_environment_observed=1
            fi
        done
    fi
    if [ "$printed" = 0 ] && [ -f /workspace/pxe-result.json ]; then
        printf 'PXE_TARGET_REPORT '
        cat /workspace/pxe-result.json
        printed=1
    fi
    $BB sleep 3
done
