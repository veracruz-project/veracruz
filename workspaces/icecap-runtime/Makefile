# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.

include ../common.mk

icecap_plat ?= qemu

WORKSPACE_DIR = $(abspath ..)
PROJECT = .
HOST_CC ?= gcc
LD = $(abspath $(shell RUSTC_BOOTSTRAP=1 cargo -Z unstable-options rustc --print target-libdir 2>/dev/null)/../bin/rust-lld)
CC = aarch64-linux-gnu-gcc
CXX = aarch64-linux-gnu-g++

deps := deps
src := src

icecap_src := icecap/src
python_src := $(icecap_src)/python
c_src := $(icecap_src)/c
rust_src := $(icecap_src)/rust

build_dir := build
target_dir := $(build_dir)/target
bin_dir := $(build_dir)/bin
sysroot_target_dir := $(build_dir)/sysroot-target
sysroot_dir := $(build_dir)/sysroot

kebab_to_caml = $(subst -,_,$(1))
capitalize = $(shell echo $(1) | tr '[:lower:]' '[:upper:]')
cargo_target_config_prefix = CARGO_TARGET_$(call capitalize,$(call kebab_to_caml,$(1)))_

sticky_dir := $(build_dir)/$(icecap_plat)/sticky
disposable_dir := $(build_dir)/$(icecap_plat)/disposable
rust_build_dir := $(sticky_dir)/target
c_build_dir := $(disposable_dir)/c
icedl_build_dir := $(disposable_dir)/icedl
misc_build_dir := $(disposable_dir)/misc
now := crates/icecap-runtime-manager/NOW

rust_icecap_bins := $(target_dir)/aarch64-icecap/$(PROFILE_PATH)
rust_dev_bins := $(rust_build_dir)/$(PROFILE_PATH)
rust_target := aarch64-icecap
rust_target_build = $(shell uname -m)-unknown-linux-gnu

sel4_src := $(deps)/seL4
sel4_tools_src := $(deps)/seL4_tools
sel4_build_dir := $(disposable_dir)/cmake/sel4
sel4_include_dir := $(sel4_build_dir)/install/libsel4/include
sel4_lib_dir := $(sel4_build_dir)/install/libsel4/lib

platform_info_h := $(misc_build_dir)/platform_info.h
object_sizes_yaml := $(misc_build_dir)/object_sizes.yaml

icedl_component_dir := $(icedl_build_dir)/components
icedl_firmware_dir := $(icedl_build_dir)/firmware
icedl_firmware_cdl := $(icedl_firmware_dir)/cdl/icecap.cdl
capdl_src := $(deps)/capdl
ifeq (,$(wildcard /usr/local/bin/parse-capDL))
capdl_tool := $(capdl_src)/capDL-tool/parse-capDL
else
capdl_tool := /usr/local/bin/parse-capDL
endif
capdl_loader := $(c_build_dir)/capdl-loader/install/bin/capdl-loader.elf
app_elf := $(misc_build_dir)/app.elf

elfloader_build_dir := $(disposable_dir)/cmake/elfloader
elfloader := $(elfloader_build_dir)/build/elfloader
elfloader_src := $(sel4_tools_src)/elfloader-tool

# FIXME
buildInputs = $(sel4_build_dir)/install/libsel4 \
	$(c_build_dir)/for-userspace/install

icecap_c_include_flags := $(foreach x,$(buildInputs),-I$(abspath $(x)/include))
icecap_c_lib_flags := $(foreach x,$(buildInputs),-L$(abspath $(x)/lib))

compiler_some_libc_include := $(wildcard /usr/lib/gcc*/aarch64-linux-gnu/*/include/)

.PHONY: none
none:

# NOTE this file must define:
#  variables:
#   - sel4_kernel_platform
#   - sel4_dts_path
#  rules:
#   - clean-plat
include mk/$(icecap_plat).mk

# NOTE this file must define:
#  variables:
#   - manifest_path
#   - cdl_script_path
#   - icedl_components
#   - project_feature_flags
include $(PROJECT)/icecap.mk

mk_dirs := $(sel4_build_dir) $(elfloader_build_dir) $(misc_build_dir)

$(mk_dirs):
		mkdir -p $@

# HACK
# Certificate expiry matters require the time in the host and realm to align
# roughly with the time that test cases are generated. The content of this file
# is embedded into both the host initramfs and the Runtime Manager to be used
# for setting the time at startup.
$(now):
		mkdir -p $(build_dir)
		date +%s | tr -d '\n' > $@

###########################################################################
# seL4
###########################################################################

t/sel4: $(sel4_dts_path) | $(sel4_build_dir)
	cmake -G Ninja \
		-DCMAKE_TOOLCHAIN_FILE=$(abspath $(sel4_src)/gcc.cmake) \
		-DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \
		-DCMAKE_INSTALL_PREFIX=$(abspath $(sel4_build_dir)/install) \
		-DHACK_SEL4_SRC=$(abspath $(sel4_src)) \
		-DHACK_SEL4_KERNEL_PLATFORM=$(sel4_kernel_platform) \
		-C $(abspath $(src)/cmake-config/seL4.cmake) \
		-S $(abspath $(sel4_src)) \
		-B $(abspath $(sel4_build_dir)/build)
	ninja -C $(abspath $(sel4_build_dir)/build) all kernel.elf sel4
	ninja -C $(abspath $(sel4_build_dir)/build) install
	install -D -T $(sel4_build_dir)/build/libsel4/libsel4.a \
		$(sel4_build_dir)/install/libsel4/lib/libsel4.a
	mkdir -p t && touch $@

###########################################################################
# IceCap user space
###########################################################################

t/userspace_c: t/sel4
	$(MAKE) -f $(c_src)/Makefile CROSS_COMPILE=aarch64-linux-gnu- \
		BUILD=$(c_build_dir)/for-userspace/build OUT=$(c_build_dir)/for-userspace/install \
		CFLAGS="-I$(sel4_include_dir) -I$(compiler_some_libc_include)" \
		ICECAP_RUNTIME_CONFIG_IN=/dev/null \
		ROOTS=$(c_src)/icecap-runtime/icecap.mk \
		ROOTS=" \
			$(c_src)/../../../src/c/libc-supplement/icecap.mk \
			$(c_src)/icecap-runtime/icecap.mk \
			$(c_src)/icecap-some-libc/icecap.mk \
			$(c_src)/icecap-utils/icecap.mk \
		" \
		install
	mkdir -p t && touch $@

###########################################################################
# IceCap sysroot
###########################################################################

t/sysroot-install: t/sysroot
	: # "tidy_dest $src $dst" removes files from $dst/ that are not
	: # found in $src/. It does not matter if the glob fails to match.
	tidy_dest() { \
	    for x in "$$2"/* ; do \
	        if ! [ -f "$$1"/"$${x##*/}" ] ; then \
	            rm -f "$$x" ; \
	        fi \
	    done \
	} ; \
	src=$(sysroot_target_dir)/aarch64-icecap/release/deps ; \
	dst=$(sysroot_dir)/lib/rustlib/aarch64-icecap/lib ; \
	mkdir -p $$dst ; \
	cp -u $$src/lib*.rlib $$dst/ ; \
	tidy_dest $$src $$dst ; \
	src=$(sysroot_target_dir)/release/deps ; \
	dst=$(sysroot_dir)/lib/rustlib/$(shell uname -m)-unknown-linux-gnu/lib/ ; \
	mkdir -p $$dst ; \
	cp -u $$src/*.so $$dst/ ; \
	tidy_dest $$src $$dst
	mkdir -p t && touch $@

sysroot_rustflags := \
	--cfg=icecap_plat=\"$(icecap_plat)\" \
	$(icecap_c_lib_flags) \
	-C force-unwind-tables=yes -C embed-bitcode=yes \
	-Z force-unstable-if-unmarked \
	--sysroot /dev/null

t/sysroot: t/userspace_c t/sel4
	RUSTC_BOOTSTRAP=1 \
	RUST_TARGET_PATH=$(abspath icecap/src/rust/support/targets) \
	$(call cargo_target_config_prefix,$(rust_target))RUSTFLAGS="$(sysroot_rustflags)" \
	$(call cargo_target_config_prefix,$(rust_target))LINKER="$(LD)" \
	BINDGEN_EXTRA_CLANG_ARGS="$(icecap_c_include_flags)" \
	__CARGO_DEFAULT_LIB_METADATA="icecap-sysroot" \
	cargo build \
		-Z unstable-options \
		-Z binary-dep-depinfo \
		--release $(V_FLAG) \
		--manifest-path sysroot/workspace/Cargo.toml \
		--target $(rust_target) \
		-j$$(nproc) \
		--target-dir $(sysroot_target_dir)
	mkdir -p t && touch $@

###########################################################################
# Veracruz part
###########################################################################

icecap_rustflags := \
	--cfg=icecap_plat=\"$(icecap_plat)\" \
	-l static=c-supplement \
	-l static=icecap-runtime \
	-l static=icecap-some-libc \
	-l static=icecap-utils \
	$(icecap_c_lib_flags) \
	--sysroot=$(abspath $(sysroot_dir))

t/rust-project: $(now) t/sysroot-install t/userspace_c t/sel4
	RUST_TARGET_PATH=$(abspath icecap/src/rust/support/targets) \
		cargo tree \
			--manifest-path $(manifest_path) --target $(rust_target) \
			-v --charset ascii -f "{p} {f}" \
			$(foreach x,$(icedl_components),-p $(x)) \
			$(project_feature_flags) > $(build_dir)/tree.txt ; \
	RUSTC_BOOTSTRAP=1 \
	RUST_TARGET_PATH=$(abspath icecap/src/rust/support/targets) \
	$(call cargo_target_config_prefix,$(rust_target))RUSTFLAGS="$(icecap_rustflags)" \
	$(call cargo_target_config_prefix,$(rust_target))LINKER="$(LD)" \
	CC_$(call kebab_to_caml,$(rust_target))="$(CC)" \
	CXX_$(call kebab_to_caml,$(rust_target))="$(CXX)" \
	BINDGEN_EXTRA_CLANG_ARGS="$(icecap_c_include_flags) -I$(compiler_some_libc_include) -I/usr/aarch64-linux-gnu/include" \
		cargo build \
			-Z unstable-options \
			--manifest-path $(manifest_path) \
			--target $(rust_target) \
			$(project_feature_flags) \
			$(foreach x,$(icedl_components),-p $(x)) \
			$(PROFILE_FLAG) $(V_FLAG) \
			-j$$(nproc) \
			--target-dir $(target_dir) \
			--out-dir $(bin_dir)
	mkdir -p t && touch $@

###########################################################################
# IceCap CDL
###########################################################################

$(object_sizes_yaml): t/sel4 | $(misc_build_dir)
		aarch64-linux-gnu-gcc -E -P - -I$(sel4_include_dir) < $(capdl_src)/object_sizes/object_sizes.yaml > $@

${rust_dev_bins}/icecap-serialize-runtime-config:
	RUSTC_BOOTSTRAP=1 \
		cargo build --manifest-path icecap/src/rust/crates/framework/base/icecap-runtime/config/cli/icecap-serialize-runtime-config/Cargo.toml \
			$(PROFILE_FLAG) --target-dir ${rust_build_dir}

icedl_components_prepared := \
        $(foreach x, \
                min full, \
                $(foreach y,$(icedl_components),$(icedl_component_dir)/$(y).$(x).elf) \
        )

$(foreach x,$(icedl_components), \
        $(patsubst %,$(rust_icecap_bins)/%.elf,$(x))): t/rust-project

$(icedl_component_dir)/%.full.elf: $(rust_icecap_bins)/%.elf
		install -D -T $< $@

$(icedl_component_dir)/%.min.elf: $(icedl_component_dir)/%.full.elf
		aarch64-linux-gnu-strip -s $< -o $@

$(icedl_firmware_cdl): \
			$(object_sizes_yaml) \
			$(icedl_components_prepared) \
			${rust_dev_bins}/icecap-serialize-runtime-config
		$(MAKE) $(icedl_components_prepared)
		PATH=$(rust_dev_bins):$$PATH \
		PYTHONPATH=$(python_src):$(capdl_src)/python-capdl-tool:$$PYTHONPATH \
				python3 $(cdl_script_path) \
						-p $(icecap_plat) \
						-c $(icedl_component_dir) \
						-s $(object_sizes_yaml) \
						-o $(abspath $(dir $@))

###########################################################################
# CapDL Loader
###########################################################################

$(capdl_tool):
	$(MAKE) -C $(capdl_src)/capDL-tool

$(icedl_firmware_dir)/src/capdl_spec.c: $(icedl_firmware_cdl) $(object_sizes_yaml) $(capdl_tool)
	mkdir -p $(dir $@)
	$(capdl_tool) --code-dynamic-alloc --object-sizes=$(object_sizes_yaml) --code=$@ $<

$(icedl_firmware_dir)/capdl.cpio: $(icedl_firmware_cdl)
	rm -rf $@.links
	cp -rL $(icedl_firmware_dir)/cdl/links $@.links
	(cd $@.links && find . -not -type d | cpio -o --reproducible -H newc > $(abspath $@))

$(icedl_firmware_dir)/capdl.o: $(icedl_firmware_dir)/capdl.cpio
	aarch64-linux-gnu-gcc -c $(c_src)/support/embedded-file.S -o $@ \
		-DSYMBOL=_capdl_archive -DFILE=$< -DSECTION=_archive_cpio

$(platform_info_h): t/sel4 | $(misc_build_dir)
	python3 $(sel4_tools_src)/cmake-tool/helpers/platform_sift.py --emit-c-syntax \
		$(sel4_build_dir)/build/gen_headers/plat/machine/platform_gen.yaml > $@

$(capdl_loader): $(icedl_firmware_dir)/src/capdl_spec.c $(icedl_firmware_dir)/capdl.o $(platform_info_h)
	$(MAKE) -f $(c_src)/Makefile CROSS_COMPILE=aarch64-linux-gnu- \
		BUILD=$(c_build_dir)/capdl-loader/build OUT=$(c_build_dir)/capdl-loader/install \
		CFLAGS="-I$(sel4_include_dir) -I$(c_build_dir)/capdl-loader/build/include -I$(compiler_some_libc_include)" \
		LDFLAGS="-T $(abspath $(c_src)/support/root-task-tls.lds") \
		ICECAP_RUNTIME_CONFIG_IN=$(src)/icecap-runtime-root-config.h \
		CAPDL_LOADER_EXTERNAL_SOURCE=$(capdl_src)/capdl-loader-app \
		CAPDL_LOADER_CONFIG_IN_H=/dev/null \
		CAPDL_LOADER_PLATFORM_INFO_H=$(platform_info_h) \
		CAPDL_LOADER_SPEC_SRC=$(icedl_firmware_dir)/src \
		CAPDL_LOADER_CPIO_O=$(icedl_firmware_dir)/capdl.o \
		ROOTS=" \
			$(c_src)/icecap-runtime/icecap.mk \
			$(c_src)/icecap-utils/icecap.mk \
			$(c_src)/icecap-some-libc/icecap.mk \
			$(c_src)/boot/cpio/icecap.mk \
			$(c_src)/boot/capdl-loader-shim/icecap.mk \
			$(c_src)/boot/capdl-loader-core/icecap.mk \
			$(c_src)/boot/capdl-loader/icecap.mk \
			" \
		install

###########################################################################
# ELF Loader
###########################################################################

$(app_elf): $(capdl_loader)
	install -D -T $< $@

sel4_cmake_config_prefixes := Kernel LibSel4 HardwareDebugAPI

$(misc_build_dir)/kernel-config.txt: t/sel4 | $(misc_build_dir)
	sed -n 's,^\([A-Za-z0-9][^:]*\):\([^=]*\)=\(.*\)$$,\1:\2=\3,p' $(sel4_build_dir)/build/CMakeCache.txt \
		| grep -e '$$.^' $(addprefix -e ^,$(sel4_cmake_config_prefixes)) \
		| sort \
		> $@

$(misc_build_dir)/kernel-config.cmake: $(misc_build_dir)/kernel-config.txt
	sed 's/^\([^:]*\):\([^=]*\)=\(.*\)$$/set(\1 "\3" CACHE \2 "")/' $< \
		> $@

$(misc_build_dir)/boot.cpio: t/sel4 $(app_elf)
	mkdir -p $@.links
	cp -rL $(sel4_build_dir)/install/bin/kernel.elf $(sel4_build_dir)/build/kernel.dtb $(app_elf) $@.links
	printf "kernel.elf\nkernel.dtb\napp.elf\n" | cpio -o -D $@.links --reproducible -H newc > $(abspath $@)

$(misc_build_dir)/boot.o: $(misc_build_dir)/boot.cpio
	aarch64-linux-gnu-gcc -c -x assembler-with-cpp $(c_src)/support/embedded-file.S -o $@ \
		-DSYMBOL=_archive_start -DFILE=$< -DSECTION=_archive_cpio

t/elfloader_c:
	$(MAKE) -f $(c_src)/Makefile CROSS_COMPILE=aarch64-linux-gnu- \
		BUILD=$(c_build_dir)/for-elfloader/build OUT=$(c_build_dir)/for-elfloader/install \
		ROOTS=$(c_src)/boot/cpio/icecap.mk \
		install
	mkdir -p t && touch $@

elfloader_extra_cpp_flags := \
	-I$(abspath $(sel4_include_dir)) \
	-I$(abspath $(c_build_dir)/for-elfloader/install/include)

elfloader_extra_c_flags_link := \
	-L$(abspath $(sel4_lib_dir)) \
	-L$(abspath $(c_build_dir)/for-elfloader/install/lib)

t/elfloader-configure: $(misc_build_dir)/boot.o $(misc_build_dir)/kernel-config.cmake t/elfloader_c | $(elfloader_build_dir)
	cmake -G Ninja \
		-DCMAKE_TOOLCHAIN_FILE=$(abspath $(sel4_src)/gcc.cmake) \
		-DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \
		-DHACK_SEL4_SRC=$(abspath $(sel4_src)) \
		-DHACK_KERNEL_CONFIG=$(abspath $(misc_build_dir)/kernel-config.cmake) \
		-C $(abspath $(src)/cmake-config/elfloader.cmake) \
		-S $(abspath $(elfloader_src)) \
		-B $(abspath $(elfloader_build_dir)/build) \
		-DPYTHON3=python3 \
		-DICECAP_HACK_EXTRA_CPP_FLAGS="$(elfloader_extra_cpp_flags)" \
		-DICECAP_HACK_EXTRA_C_FLAGS_LINK="$(elfloader_extra_c_flags_link)" \
		-DICECAP_HACK_CMAKE_HELPERS=$(abspath $(sel4_src)/tools/helpers.cmake) \
		-DICECAP_HACK_CMAKE_INTERNAL=$(abspath $(sel4_src)/tools/internal.cmake) \
		-DICECAP_HACK_CMAKE_TOOL_HELPERS_DIR=$(abspath $(sel4_tools_src)/cmake-tool/helpers) \
		-DICECAP_HACK_KERNEL_TOOLS=$(abspath $(sel4_src)/tools) \
		-DICECAP_HACK_KERNEL_DTB=$(abspath $(sel4_build_dir)/build/kernel.dtb) \
		-DICECAP_HACK_ARCHIVE_O=$(abspath $(misc_build_dir)/boot.o) \
		-Dplatform_yaml=$(abspath $(sel4_build_dir)/build/gen_headers/plat/machine/platform_gen.yaml)
	mkdir -p t && touch $@

t/elfloader-build: t/elfloader-configure
	ninja -C $(abspath $(elfloader_build_dir)/build) elfloader
	mkdir -p t && touch $@

$(elfloader_build_dir)/build/elfloader: t/elfloader-build

.PHONY: elfloader
elfloader: $(elfloader_build_dir)/build/elfloader css-icecap.bin

css-icecap.bin: $(elfloader_build_dir)/build/elfloader
	cp $< $@

.PHONY: build
build: elfloader

.PHONY: clean
clean:
	rm -rf css-icecap.bin $(build_dir) t
	cargo clean
