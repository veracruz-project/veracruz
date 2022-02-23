sel4_kernel_platform := qemu-arm-virt

system := $(disposable_dir)/system

sel4_dts_path := $(sel4_src)/tools/dts/virt.dts

.PHONY: build
build: elfloader system-dir

.PHONY: clean-plat
clean-plat:
	rm -f $(sel4_dts_path) system

.PHONY: run
run:
	ln -sf $(system) system
	qemu-system-aarch64 \
		-machine virt,virtualization=on,gic-version=2 -cpu cortex-a57 -smp 4 -m 3072 \
		-nographic \
		-semihosting-config enable=on,target=native \
		-device virtio-net-device,netdev=netdev0 \
		-serial mon:stdio \
		-netdev user,id=netdev0 \
		-kernel $(elfloader)

.PHONY: debug
debug:
	ln -sf $(system) system
	qemu-system-aarch64 \
		-machine virt,virtualization=on,gic-version=2 -cpu cortex-a57 -smp 4 -m 3072 \
		-nographic \
		-semihosting-config enable=on,target=native \
		-device virtio-net-device,netdev=netdev0 \
		-serial mon:stdio \
		-netdev user,id=netdev0 \
		-kernel $(elfloader)

sel4-configure: $(sel4_dts_path)

$(sel4_dts_path): $(misc_build_dir)/virt.dtb
	dtc -I dtb -O dts -o $@ $<

$(misc_build_dir)/virt.dtb: | $(misc_build_dir)
	qemu-system-aarch64 \
		-machine virt,virtualization=on,dumpdtb=$@,gic-version=2 -cpu cortex-a57 -smp 4 -m 3072 \
		-nographic \
		-semihosting-config enable=on,target=native \
		-device virtio-net-device,netdev=netdev0 \
		-device virtio-9p-device,mount_tag=share,fsdev=share \
		-netdev user,id=netdev0 \
		-fsdev local,id=share,security_model=none,readonly,path=.


system_files := \

system_files_with_prefix := $(addprefix $(system)/,$(system_files))

.PHONY: system-dir
system-dir: $(system_files_with_prefix)

$(system_files_with_prefix):
	install -D -T $< $@
