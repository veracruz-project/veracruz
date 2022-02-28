sel4_kernel_platform := qemu-arm-virt

system := $(disposable_dir)/system

sel4_dts_path := $(sel4_src)/tools/dts/virt.dts

.PHONY: build
build: elfloader system-dir

.PHONY: clean-plat
clean-plat:
	rm -f $(sel4_dts_path) system

QEMU_BIN = qemu-system-aarch64
QEMU_BASE_FLAGS = -machine virt,virtualization=on,gic-version=2 \
		-cpu cortex-a57 -smp 4 -m 3072 \
		-nographic -semihosting-config enable=on,target=native \
		-device virtio-serial-device
QEMU_RUN_FLAGS = -chardev socket,server,host=localhost,port=1234,id=charconsole0 \
		-device virtconsole,chardev=charconsole0,id=console0 \
		-serial mon:stdio

.PHONY: run
run:
	ln -sf $(system) system
	$(QEMU_BIN) $(QEMU_BASE_FLAGS) $(QEMU_RUN_FLAGS) \
		-kernel $(elfloader)

.PHONY: debug
debug:
	ln -sf $(system) system
	$(QEMU_BIN) $(QEMU_BASE_FLAGS) $(QEMU_RUN_FLAGS) \
		-kernel $(elfloader)

sel4-configure: $(sel4_dts_path)

$(sel4_dts_path): $(misc_build_dir)/virt.dtb
	dtc -I dtb -O dts -o $@ $<

$(misc_build_dir)/virt.dtb: | $(misc_build_dir)
	$(QEMU_BIN) $(QEMU_BASE_FLAGS) \
		-machine dumpdtb=$@

system_files := \

system_files_with_prefix := $(addprefix $(system)/,$(system_files))

.PHONY: system-dir
system-dir: $(system_files_with_prefix)

$(system_files_with_prefix):
	install -D -T $< $@
