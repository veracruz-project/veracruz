#!/bin/bash

ip tuntap add zeth mode tap
ip link set dev zeth up
ip link set dev zeth address 00:00:5e:00:53:ff
ip address add 193.0.2.2/24 dev zeth
ip route add 193.0.2.0/24 dev zeth 2>/dev/null
iptables -t nat -A POSTROUTING -j MASQUERADE -s 193.0.2.1

