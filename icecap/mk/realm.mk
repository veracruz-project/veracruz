# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

include mk/common.mk

rust_target := aarch64-icecap

icecap_c_include_flags := $(foreach x,$(buildInputs),-I$(abspath $(x)/include))
icecap_c_lib_flags := $(foreach x,$(buildInputs),-L$(abspath $(x)/lib))

icecap_rustflags := \
	--cfg=icecap_plat=\"$(ICECAP_PLAT)\" \
	-l static=icecap-utils \
	-l static=icecap-pure \
	-l static=c-supplement \
	$(icecap_c_lib_flags) \
	--sysroot=$(abspath $(sysroot_dir))

define realm_crate_body
	RUST_TARGET_PATH=$(abspath icecap/src/rust/support/targets) \
	$(call cargo_target_config_prefix,$(rust_target))RUSTFLAGS="$(icecap_rustflags)" \
	$(call cargo_target_config_prefix,$(rust_target))LINKER="$(LD)" \
	CC_$(call kebab_to_caml,$(rust_target))="$(CC)" \
	CC_$(call kebab_to_caml,$(rust_target_build))="$(HOST_CC)" \
	BINDGEN_EXTRA_CLANG_ARGS="$(icecap_c_include_flags)" \
		cargo build \
			-Z unstable-options \
			--manifest-path ../$(1)/Cargo.toml \
			--target $(rust_target) --features icecap \
			--release \
			-j$$(nproc) \
			--target-dir $(target_dir) \
			--out-dir $(bin_dir)
 endef

.PHONY: runtime-manager
runtime-manager: sysroot-install
	$(call realm_crate_body,runtime-manager)

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
	dst=$(sysroot_dir)/lib/rustlib/x86_64-unknown-linux-gnu/lib/ ; \
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
sysroot:
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
