#!/bin/sh
set -eu
/usr/sbin/sysctl -w net.ipv4.ip_forward=1
if ! /usr/sbin/iptables -t nat -C POSTROUTING -s 10.78.0.0/24 -o eth0 -m comment --comment verz-bond -j MASQUERADE 2>/dev/null; then
    /usr/sbin/iptables -t nat -A POSTROUTING -s 10.78.0.0/24 -o eth0 -m comment --comment verz-bond -j MASQUERADE
fi
