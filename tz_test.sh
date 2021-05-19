#!/bin/bash
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.
cd /work/rust-optee-trustzone-sdk/optee-qemuv8-3.7.0
ln -sf /work/rust-optee-trustzone-sdk/optee-qemuv8-3.7.0/outbr/images/rootfs.cpio.gz out/bin
cd /work/rust-optee-trustzone-sdk/optee-qemuv8-3.7.0/out/bin && /work/rust-optee-trustzone-sdk/optee-qemuv8-3.7.0/qemu/aarch64-softmmu/qemu-system-aarch64 \
        -nodefaults \
		-nographic \
		-serial stdio -serial file:/tmp/serial.log \
		-smp 2 \
		-s -machine virt,secure=on -cpu cortex-a57 \
		-d unimp -semihosting-config enable,target=native \
		-m 1057 \
		-bios bl1.bin \
		-initrd rootfs.cpio.gz \
		-kernel Image -no-acpi \
		-append 'console=ttyAMA0,38400 keep_bootcon root=/dev/vda2' \
        -fsdev local,id=fsdev0,path=/tmp/vc_test/shared,security_model=none \
        -device virtio-9p-device,fsdev=fsdev0,mount_tag=host \
        -netdev user,id=vmnic \
        -device virtio-net-device,netdev=vmnic
