#!/bin/bash
set -xe

rm -rf /tmp/vc_test/
mkdir -p /tmp/vc_test/

mkdir -p /tmp/vc_test/shared/

rm -rf screenlog.0
rm -rf optee-qemuv8-3.4.0
rm -rf shared
mkdir -p /tmp/vc_test/shared/test/

(cd /tmp/vc_test/ && curl http://mesalock-linux.org/assets/optee-qemuv8-3.4.0.tar.gz | tar zxv)
#cp /work/rust-optee-trustzone-sdk/examples/hello_world/ta/target/aarch64-unknown-optee-trustzone/release/*.ta /tmp/vc_test/shared
#cp /work/rust-optee-trustzone-sdk/examples/hello_world/host/target/aarch64-unknown-linux-gnu/release/hello_world /tmp/vc_test/shared
cp ../mexico-city/target/aarch64-unknown-optee-trustzone/release/*.ta /tmp/vc_test/shared/test/
cp ./target/aarch64-unknown-linux-gnu/debug/veracruz_test-* /tmp/vc_test/shared/test
cp -r ../test-collateral/ /tmp/vc_test/shared/test_collateral/
cp ./optee-qemuv8.sh /tmp/vc_test/

cd /tmp/vc_test/
screen -L -d -m -S qemu_screen ./optee-qemuv8.sh
sleep 20
screen -S qemu_screen -p 0 -X stuff "root\n"
sleep 5
screen -S qemu_screen -p 0 -X stuff "mkdir shared && mount -t 9p -o trans=virtio host shared && cd shared\n"
sleep 5
screen -S qemu_screen -p 0 -X stuff "cp test/*.ta /lib/optee_armtz/\n"
sleep 5
screen -S qemu_screen -p 0 -X stuff "ls /lib/optee_armtz/\n"
sleep 2
screen -S qemu_screen -p 0 -X stuff "cd test && export RUST_BACKTRACE=1 && ./veracruz_test-651ad2b7d838f56c veracruz_single --nocapture\n"
sleep 10
screen -S qemu_screen -p 0 -X stuff "^C"
sleep 5

{
	grep -q "original value is 29" screenlog.0 &&
	grep -q "inc value is 129" screenlog.0 &&
	grep -q "dec value is 29" screenlog.0 &&
	grep -q "Success" screenlog.0
} || {
	cat -v screenlog.0
	cat -v /tmp/serial.log
	false
}

rm -rf screenlog.0
rm -rf optee-qemuv8-3.4.0
rm -rf shared
