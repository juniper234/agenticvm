#!/bin/busybox sh
case "$1" in
    deconfig) /bin/busybox ip addr flush dev "$interface" ;;
    bound|renew)
        # The finite lab approves one lease; no default gateway or DNS is used.
        [ "$ip" = 192.0.2.4 ] || exit 1
        if ! /bin/busybox ip addr show dev "$interface" | /bin/busybox grep -q "inet $ip/24"; then
            /bin/busybox ip addr flush dev "$interface" || exit 1
            /bin/busybox ip addr add "$ip/24" dev "$interface" || exit 1
        fi
        printf '%s\n' "$ip" >/run/network-bound
        printf 'REALISM_LINUX_DHCP_BOUND %s server=%s event=%s\n' "$ip" "$serverid" "$1" >/dev/console
        ;;
esac
