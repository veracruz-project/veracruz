#!/bin/bash
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.
# 
# Arguments
# $1 - test program.
# $2 - waiting time before ^C.
echo "running trustzone test: '$1', waiting time: $2s"
rm -f /tmp/screenlog
rm -f /tmp/serial.log
screen -L -d -m -c screenrc -S qemu_screen ./tz_test.sh
sleep 25
screen -S qemu_screen -p 0 -X stuff "root\n"
sleep 5
screen -S qemu_screen -p 0 -X stuff "mkdir shared && mount -t 9p -o trans=virtio host shared\n"
sleep 5
screen -S qemu_screen -p 0 -X stuff "cd shared/test && . ./env.sh\n";
sleep 25
screen -S qemu_screen -p 0 -X stuff "./$1 --test-threads=1\n"
sleep $2
screen -S qemu_screen -p 0 -X stuff "^C"
sleep 5

{
    grep "test result: ok." /tmp/screenlog
} || {
    cat /tmp/screenlog 
    echo "Failed to find 'test result: ok.' in the screenlog"
    cat /tmp/screenlog
    false
}
