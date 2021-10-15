# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

ICECAP_PLAT ?= virt

build_dir := build
generated_crates := $(build_dir)/crates
test_system := $(build_dir)/test-system
now := $(build_dir)/NOW

nix_build := nix-build
nix_shell := nix-shell --pure
nix_expression := targets.nix
nix_attribute_path := $(ICECAP_PLAT)

.PHONY: all
all:

$(build_dir):
	mkdir $@

.PHONY: crates
crates:
	$(nix_build) $(nix_expression) -A $(nix_attribute_path).$@ -o $(generated_crates)

# HACK
# The IceCap crates only exist in the context of the IceCap build. We bundle
# them all together by exposing them all through one crate called
# 'icecap-wrapper', located at ./crate-hack/crates/icecap-wrapper. Outside of
# the context of the IceCap build, this crate is a symlink to
# ./src/rust/crates/icecap-wrapper-dummy. Inside the context of the IceCap
# build, this crate is a symlink to ./build/crates/icecap-wrapper-dummy. This
# hack will be unecessary once we have per-isolate backend workspaces.
.PHONY: link-crates
link-crates: crates
	ln -sfT ../$(generated_crates) crates-hack/crates

.PHONY: unlink-crates
unlink-crates:
	ln -sfT dummy-crates crates-hack/crates

# HACK
# Certificate expiry matters require the time in the host and realm to align
# roughly with the time that test cases are generated. The content of this file
# is embedded into both the host initramfs and the Runtime Manager to be used
# for setting the time at startup.
$(now): | $(build_dir)
	date +%s | tr -d '\n' > $@

# Explicitly update the time in the host and the realm at the cost of some rebuilding
.PHONY: update-time
update-time:
	rm -f $(now)

.PHONY: runtime-manager
runtime-manager: $(now) link-crates
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

.PHONY: veracruz-server-test
veracruz-server-test:
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

.PHONY: veracruz-test
veracruz-test:
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

.PHONY: sdk
sdk:
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run "make -C ../sdk"

.PHONY: test-collateral
test-collateral: sdk
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run "make -C ../test-collateral TEE=icecap"

test_system_body = $(nix_build) $(nix_expression) -A $(nix_attribute_path).test-system -o $(test_system)

.PHONY: test-system
test-system: $(now) runtime-manager veracruz-server-test veracruz-test test-collateral
	$(test_system_body)

# Convenient shortcut
.PHONY: test-system-stale-test-collateral
test-system-stale-test-collateral: $(now) runtime-manager veracruz-server-test veracruz-test # implicit prerequisite: test-collateral
	$(test_system_body)

# Convenient shortcut
.PHONY: test-system-stale
test-system-stale: $(now) # implicit prerequisites: runtime-manager veracruz-server-test veracruz-test test-collateral
	$(test_system_body)

# Permission constraints required by the OpenSSH client cannot be expressed in Git or Nix
.PHONY: set-key-permissions
set-key-permissions:
	chmod 0400 nix/host/token-ssh-key.priv

run_tests_body = eval $$($(nix_build) $(nix_expression) -A $(nix_attribute_path).run-tests --no-out-link)

.PHONY: run-tests
run-tests: set-key-permissions $(now) runtime-manager veracruz-server-test veracruz-test test-collateral
	$(run_tests_body)

# Convenient shortcut
.PHONY: run-tests-stale-test-collateral
run-tests-stale-test-collateral: set-key-permissions $(now) runtime-manager veracruz-server-test veracruz-test # implicit prerequisite: test-collateral
	$(run_tests_body)

# Convenient shortcut
.PHONY: run-tests-stale
run-tests-stale: set-key-permissions $(now) # implicit prerequisites: runtime-manager veracruz-server-test veracruz-test test-collateral
	$(run_tests_body)

# Clean everything specific to the IceCap build, all of which is contained in this ./icecap directory
.PHONY: clean
clean: unlink-crates
	rm -rf $(build_dir)

# This is a bit heavy-handed, but useful for achieving a clean slate for the test resources too
.PHONY: deep-clean
deep-clean: clean
	cd .. && git clean -Xdff --exclude='!icecap/docker/hacking/nix-root'
