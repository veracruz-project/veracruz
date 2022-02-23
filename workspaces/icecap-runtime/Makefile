# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

include ../common.mk

ICECAP_PLAT ?= virt
HOST_CC ?= gcc
CC = aarch64-linux-gnu-gcc

icecap_plat := $(ICECAP_PLAT)

deps := deps
src := src

icecap_src := icecap/src
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

rust_target := aarch64-icecap
rust_target_build = $(shell uname -m)-unknown-linux-gnu

sticky_dir := $(build)/$(icecap_plat)/sticky
disposable_dir := $(build)/$(icecap_plat)/disposable
rust_build_dir := $(sticky_dir)/target
c_build_dir := $(disposable_dir)/c
misc_build_dir := $(disposable_dir)/misc
now := crates/runtime-manager/NOW

sel4_src := $(deps)/seL4
sel4_tools_src := $(deps)/seL4_tools
sel4_build_dir := $(disposable_dir)/cmake/sel4
sel4_include_dir := $(sel4_build_dir)/install/libsel4/include
sel4_lib_dir := $(sel4_build_dir)/install/libsel4/lib

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

$(sel4_build_dir)/install/lib/%: $(sel4_build_dir)/build/libsel4/%
		install -D -T $< $@

.PHONY: sel4-install
sel4-install: sel4-build $(sel4_build_dir)/install/lib/libsel4.a
		ninja -C $(abspath $(sel4_build_dir)/build) install

.PHONY: sel4
sel4: sel4-install

###########################################################################


icecap_rustflags := \
	--cfg=icecap_plat=\"$(ICECAP_PLAT)\" \
	-l static=icecap-utils \
	$(icecap_c_lib_flags) \
	--sysroot=$(abspath $(sysroot_dir))

.PHONY: runtime-manager
runtime-manager: $(now) sysroot-install userspace_c sel4
	RUST_TARGET_PATH=$(abspath icecap/src/rust/support/targets) \
		cargo tree \
			--manifest-path Cargo.toml --target $(rust_target) \
			-p runtime_manager_enclave --features icecap \
			-v --charset ascii -f "{p} {f}" > $(build_dir)/tree.txt ; \
	RUST_TARGET_PATH=$(abspath icecap/src/rust/support/targets) \
	$(call cargo_target_config_prefix,$(rust_target))RUSTFLAGS="$(icecap_rustflags)" \
	$(call cargo_target_config_prefix,$(rust_target))LINKER="$(LD)" \
	CC_$(call kebab_to_caml,$(rust_target))="$(CC)" \
	BINDGEN_EXTRA_CLANG_ARGS="$(icecap_c_include_flags) -I$(compiler_some_libc_include) -I/usr/aarch64-linux-gnu/include" \
		cargo build \
			-Z unstable-options \
			--manifest-path Cargo.toml \
			--target $(rust_target) \
			-p runtime_manager_enclave --features icecap \
			$(PROFILE_FLAG) \
			-j$$(nproc) \
			--target-dir $(target_dir) \
			--out-dir $(bin_dir)

.PHONY: userspace_c
userspace_c: sel4
	$(MAKE) -f $(c_src)/Makefile CROSS_COMPILE=aarch64-linux-gnu- \
		BUILD=$(c_build_dir)/for-userspace/build OUT=$(c_build_dir)/for-userspace/install \
		CFLAGS="-I$(sel4_include_dir)" \
		ICECAP_RUNTIME_CONFIG_IN=/dev/null \
		ROOTS=$(c_src)/icecap-runtime/icecap.mk \
		ROOTS=" \
			$(c_src)/icecap-runtime/icecap.mk \
			$(c_src)/icecap-utils/icecap.mk \
		" \
		install

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
