.PHONY: all
all: sysroot

.PHONY: clean
clean:
	rm -rf target

rustflags = \
	--cfg=icecap_plat=\"virt\" \
	-L$(LIBSEL4)/lib -L$(ICECAP_RUNTIME)/lib \
	-C force-unwind-tables=yes -C embed-bitcode=yes \
    -Z force-unstable-if-unmarked \
    --sysroot /dev/null

cargo_config_env = \
	CARGO_TARGET_AARCH64_ICECAP_LINKER=rust-lld \
	CARGO_TARGET_AARCH64_ICECAP_RUSTFLAGS="$(rustflags)"

.PHONY: sysroot
sysroot:
	RUST_TARGET_PATH=$(abspath ../support/targets) \
	RUSTC_BOOTSTRAP=1 \
	$(cargo_config_env) \
	__CARGO_DEFAULT_LIB_METADATA="icecap-sysroot" \
	BINDGEN_EXTRA_CLANG_ARGS="-I$(LIBSEL4)/include" \
	cargo build \
		-Z unstable-options \
		-Z binary-dep-depinfo \
		--target aarch64-icecap \
		--release
