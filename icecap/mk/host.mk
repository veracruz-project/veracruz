# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

include mk/common.mk

rust_target := aarch64-unknown-linux-gnu

define host_crate_body
	$(call cargo_target_config_prefix,$(rust_target))LINKER="$(CC)" \
	CC_$(call kebab_to_caml,$(rust_target))="$(CC)" \
	CC_$(call kebab_to_caml,$(rust_target_build))="$(HOST_CC)" \
	PKG_CONFIG_ALLOW_CROSS=1 \
		cargo test --no-run \
			--manifest-path ../$(1)/Cargo.toml \
			--target $(rust_target) --features icecap \
			--release \
			-j$$(nproc) \
			--target-dir $(target_dir) \
			$(1)
	f="$$(find $(target_dir)/$(rust_target)/release/deps -executable -type f -name "$(call kebab_to_caml,$(1))-*" -printf "%T@ %p\n" \
		| sort -n \
		| tail -n 1 \
		| cut -d ' ' -f 2 \
	)" && \
		install -D -T "$$f" $(bin_dir)/$(1)
endef

.PHONY: inner-veracruz-server-test
inner-veracruz-server-test:
	$(call host_crate_body,veracruz-server-test)

.PHONY: inner-veracruz-test
inner-veracruz-test:
	$(call host_crate_body,veracruz-test)
