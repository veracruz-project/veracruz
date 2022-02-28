# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

include ../common.mk

PROJECT = .
ICECAP_PLAT ?= virt
HOST_CC ?= gcc
LD = $(abspath $(shell cargo -Z unstable-options rustc --print target-libdir 2>/dev/null)/../bin/rust-lld)
CC = aarch64-linux-gnu-gcc

icecap_plat := $(ICECAP_PLAT)

deps := deps
src := src

icecap_src := icecap/src
python_src := $(icecap_src)/python
c_src := $(icecap_src)/c
rust_src := $(icecap_src)/rust

build := build
build_dir := build
target_dir := $(build_dir)/target
bin_dir := $(build_dir)/bin
sysroot_target_dir := $(build_dir)/sysroot-target
sysroot_dir := $(build_dir)/sysroot

kebab_to_caml = $(subst -,_,$(1))
capitalize = $(shell echo $(1) | tr '[:lower:]' '[:upper:]')
cargo_target_config_prefix = CARGO_TARGET_$(call capitalize,$(call kebab_to_caml,$(1)))_

sticky_dir := $(build)/$(icecap_plat)/sticky
disposable_dir := $(build)/$(icecap_plat)/disposable
rust_build_dir := $(sticky_dir)/target
c_build_dir := $(disposable_dir)/c
icedl_build_dir := $(disposable_dir)/icedl
misc_build_dir := $(disposable_dir)/misc
now := crates/runtime-manager/NOW

rust_icecap_bins := $(target_dir)/aarch64-icecap/release
rust_dev_bins := $(rust_build_dir)/release
rust_target := aarch64-icecap
rust_target_build = $(shell uname -m)-unknown-linux-gnu

sel4_src := $(deps)/seL4
sel4_tools_src := $(deps)/seL4_tools
sel4_build_dir := $(disposable_dir)/cmake/sel4
sel4_include_dir := $(sel4_build_dir)/install/libsel4/include
sel4_lib_dir := $(sel4_build_dir)/install/libsel4/lib

object_sizes_yaml := $(misc_build_dir)/object_sizes.yaml

icedl_component_dir := $(icedl_build_dir)/components
icedl_firmware_dir := $(icedl_build_dir)/firmware
icedl_firmware_cdl := $(icedl_firmware_dir)/cdl/icecap.cdl
capdl_src := $(deps)/capdl
capdl_tool := $(capdl_src)/capDL-tool/parse-capDL
capdl_loader := $(c_build_dir)/capdl-loader/install/bin/capdl-loader.elf
app_elf := $(misc_build_dir)/app.elf
elfloader := $(elfloader_build_dir)/build/elfloader

# FIXME
buildInputs = $(sel4_build_dir)/install/libsel4 \
	$(c_build_dir)/for-userspace/install

icecap_c_include_flags := $(foreach x,$(buildInputs),-I$(abspath $(x)/include))
icecap_c_lib_flags := $(foreach x,$(buildInputs),-L$(abspath $(x)/lib))

compiler_some_libc_include := /usr/lib/gcc-cross/aarch64-linux-gnu/11/include/

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

.PHONY: sel4-configure
sel4-configure: $(sel4_build_dir)
		cmake -G Ninja \
				-DCMAKE_TOOLCHAIN_FILE=$(abspath $(sel4_src)/gcc.cmake) \
				-DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \
				-DCMAKE_INSTALL_PREFIX=$(abspath $(sel4_build_dir)/install) \
				-DHACK_SEL4_SRC=$(abspath $(sel4_src)) \
				-DHACK_SEL4_KERNEL_PLATFORM=$(sel4_kernel_platform) \
				-C $(abspath $(src)/cmake-config/seL4.cmake) \
				-S $(abspath $(sel4_src)) \
				-B $(abspath $(sel4_build_dir)/build)

.PHONY: sel4-build
sel4-build: sel4-configure
		ninja -C $(abspath $(sel4_build_dir)/build) all kernel.elf sel4

$(sel4_build_dir)/build/libsel4/libsel4.a: sel4-build

$(sel4_build_dir)/install/libsel4/lib/%: $(sel4_build_dir)/build/libsel4/%
		install -D -T $< $@

.PHONY: sel4-install
sel4-install: sel4-build $(sel4_build_dir)/install/libsel4/lib/libsel4.a
		ninja -C $(abspath $(sel4_build_dir)/build) install

.PHONY: sel4
sel4: sel4-install

###########################################################################
# IceCap user space
###########################################################################

.PHONY: userspace_c
userspace_c: sel4
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

###########################################################################
# IceCap sysroot
###########################################################################

.PHONY: sysroot-install
sysroot-install: sysroot
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

sysroot_rustflags := \
	--cfg=icecap_plat=\"$(ICECAP_PLAT)\" \
	$(icecap_c_lib_flags) \
	-C force-unwind-tables=yes -C embed-bitcode=yes \
	-Z force-unstable-if-unmarked \
	--sysroot /dev/null

.PHONY: sysroot
sysroot: userspace_c sel4
	RUST_TARGET_PATH=$(abspath icecap/src/rust/support/targets) \
	$(call cargo_target_config_prefix,$(rust_target))RUSTFLAGS="$(sysroot_rustflags)" \
	$(call cargo_target_config_prefix,$(rust_target))LINKER="$(LD)" \
	BINDGEN_EXTRA_CLANG_ARGS="$(icecap_c_include_flags)" \
	RUSTC_BOOTSTRAP=1 \
	__CARGO_DEFAULT_LIB_METADATA="icecap-sysroot" \
	cargo build \
		-Z unstable-options \
		-Z binary-dep-depinfo \
		--release \
		--manifest-path sysroot/workspace/Cargo.toml \
		--target $(rust_target) \
		-j$$(nproc) \
		--target-dir $(sysroot_target_dir)


###########################################################################
# Veracruz part
###########################################################################

icecap_rustflags := \
	--cfg=icecap_plat=\"$(ICECAP_PLAT)\" \
	-l static=c-supplement \
	-l static=icecap-runtime \
	-l static=icecap-some-libc \
	-l static=icecap-utils \
	$(icecap_c_lib_flags) \
	--sysroot=$(abspath $(sysroot_dir))

.PHONY: rust-project
rust-project: $(now) sysroot-install userspace_c sel4
	RUST_TARGET_PATH=$(abspath icecap/src/rust/support/targets) \
		cargo tree \
			--manifest-path Cargo.toml --target $(rust_target) \
			-v --charset ascii -f "{p} {f}" \
			$(foreach x,$(icedl_components),-p $(x)) \
			 --features icecap > $(build_dir)/tree.txt ; \
	RUST_TARGET_PATH=$(abspath icecap/src/rust/support/targets) \
	$(call cargo_target_config_prefix,$(rust_target))RUSTFLAGS="$(icecap_rustflags)" \
	$(call cargo_target_config_prefix,$(rust_target))LINKER="$(LD)" \
	CC_$(call kebab_to_caml,$(rust_target))="$(CC)" \
	BINDGEN_EXTRA_CLANG_ARGS="$(icecap_c_include_flags) -I$(compiler_some_libc_include) -I/usr/aarch64-linux-gnu/include" \
		cargo build \
			-Z unstable-options \
			--manifest-path Cargo.toml \
			--target $(rust_target) \
			$(foreach x,$(icedl_components),-p $(x)) \
			--features icecap \
			$(PROFILE_FLAG) \
			-j$$(nproc) \
			--target-dir $(target_dir) \
			--out-dir $(bin_dir)


###########################################################################
# IceCap CDL
###########################################################################

$(object_sizes_yaml): sel4 | $(misc_build_dir)
		aarch64-linux-gnu-gcc -E -P - -I$(sel4_include_dir) < $(capdl_src)/object_sizes/object_sizes.yaml > $@

${rust_dev_bins}/icecap-serialize-runtime-config:
		cargo build --manifest-path icecap/src/rust/crates/framework/base/icecap-runtime/config/cli/icecap-serialize-runtime-config/Cargo.toml \
			--release --target-dir ${rust_build_dir}

icedl_components_prepared := \
        $(foreach x, \
                min full, \
                $(foreach y,$(icedl_components),$(icedl_component_dir)/$(y).$(x).elf) \
        )

$(foreach x,$(icedl_components), \
        $(patsubst %,$(rust_icecap_bins)/%.elf,$(x))): rust-project

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
