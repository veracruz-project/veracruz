# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

include ../../icecap/mk/common.mk

test_system := $(build_dir)/test-system
now := $(build_dir)/NOW

nix_build := nix-build
nix_shell := nix-shell --pure
nix_expression := ../../icecap/targets.nix
nix_attribute_path := $(ICECAP_PLAT)

inner_make_cmd = $(MAKE) -f mk/$(1).mk ICECAP_PLAT=$(ICECAP_PLAT) PROFILE=$(PROFILE) $@

# HACK
# Certificate expiry matters require the time in the host and realm to align
# roughly with the time that test cases are generated. The content of this file
# is embedded into both the host initramfs and the Runtime Manager to be used
# for setting the time at startup.
$(now): | $(build_dir)
	date +%s | tr -d '\n' > $@

# Work-around for relative path inclusion in source code
../../icecap/$(now): $(now)
	mkdir -p ../../icecap/$(build_dir)
	cp $< $@

# Explicitly update the time in the host and the realm at the cost of some rebuilding
.PHONY: update-time
update-time:
	rm -f $(now) ../../icecap/$(now)

.PHONY: runtime-manager
runtime-manager: $(now) ../../icecap/$(now)
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).env.realm --run '$(call inner_make_cmd,realm)'

.PHONY: sysroot
sysroot:
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).env.realm --run '$(call inner_make_cmd,realm)'

# Clean everything specific to the IceCap build, all of which is contained in this ./icecap directory
.PHONY: clean
clean:
	rm -rf $(build_dir)

.PHONY: clean-cargo-lock
clean-cargo-lock:
	rm -f Cargo.lock

.PHONY: doc
doc:
	cargo doc

.PHONY: fmt
fmt:
	cargo fmt

# This is a bit heavy-handed, but useful for achieving a clean slate for 'sdk' and 'test-collateral'
.PHONY: deep-clean
deep-clean: clean
	cd ../.. && git clean -Xdff \
		--exclude='!icecap/icecap/nixpkgs/' \
		--exclude='!icecap/icecap/nixpkgs/**' \
		--exclude='!icecap/docker/hacking/nix-root/' \
		--exclude='!icecap/docker/hacking/nix-root/**'
