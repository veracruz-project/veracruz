# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.

sel4_kernel_platform := qemu-arm-virt

system := $(disposable_dir)/system

sel4_dts_path := $(sel4_src)/tools/dts/virt.dts

.PHONY: clean-plat
clean-plat:
	rm -f $(sel4_dts_path)

QEMU_BIN = qemu-system-aarch64
QEMU_BASE_FLAGS = -machine virt,virtualization=on,gic-version=2 \
		-cpu cortex-a57 -smp 4 -m 3072 \
		-semihosting-config enable=on,target=native \
		-device virtio-serial-device \
		-device virtconsole,chardev=charconsole0,id=console0 \
		-device virtio-net-device,netdev=netdev0 \
		-netdev user,id=netdev0
QEMU_RUN_FLAGS = \
		-chardev socket,server=on,host=localhost,port=1234,id=charconsole0 \
		-serial mon:stdio -nographic

.PHONY: run
run:
	$(QEMU_BIN) $(QEMU_BASE_FLAGS) $(QEMU_RUN_FLAGS) \
		-kernel $(elfloader)

.PHONY: debug
debug:
	$(QEMU_BIN) $(QEMU_BASE_FLAGS) $(QEMU_RUN_FLAGS) \
		-kernel $(elfloader)

$(sel4_dts_path): $(misc_build_dir)/$(sel4_kernel_platform).dtb
	dtc -I dtb -O dts -o $@ $<

$(misc_build_dir)/$(sel4_kernel_platform).dtb: | $(misc_build_dir)
	$(QEMU_BIN) $(QEMU_BASE_FLAGS) \
		-chardev socket,server=on,host=localhost,port=1234,id=charconsole0,wait=off \
		-machine dumpdtb=$@
