#!/bin/bash
#
# Sets up a SLIP based network interfaces connected to a local NAT, this
# can then be used by the qemu_cortex_m3 board in Zephyr to emulate IP
# traffic over a serial connection
#
# ## Authors
#
# The Veracruz Development Team.
#
# ## Licensing and copyright notice
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
# information on licensing and copyright.
#

# setup slip/tap network
nohup /zephyr-workspace/tools/net-tools/loop-socat.sh >/dev/null 2>&1 &
nohup /zephyr-workspace/tools/net-tools/loop-slip-tap.sh >/dev/null 2>&1 &

# redirect tap traffic
iptables -t nat -A POSTROUTING -j MASQUERADE -s 192.0.2.1

# wait for dhcp
while ! ip addr show tap0 2>/dev/null | grep -q inet ; do sleep 0.1 ; done
echo "slip ready @ $(ip addr show tap0 | grep --color=never -oP '(?<=inet\s)[^ ]*')"

