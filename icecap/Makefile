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
crates_dir := crates
dummy_crates_dir := dummy-crates

now := $(build_dir)/NOW

nix_build := nix-build
nix_shell := nix-shell --pure
nix_expression := targets.nix
nix_attribute_path := $(ICECAP_PLAT)

.PHONY: all
all:

.PHONY: clean
clean: unlink-crates
	rm -rf $(build_dir)

.PHONY: deep-clean
deep-clean: clean unlink-crates
	cd .. && git clean -xdff --exclude=icecap/docker/nix-root

.PHONY: link-crates
link-crates:
	ln -sfT $$($(nix_build) $(nix_expression) -A $(nix_attribute_path).crates) $(crates_dir)

.PHONY: unlink-crates
unlink-crates:
	ln -sfT $(dummy_crates_dir) $(crates_dir)

.PHONY: setup
setup: link-crates

.PHONY: runtime-manager
runtime-manager: $(now) setup
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

.PHONY: veracruz-server-test
veracruz-server-test: setup
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

.PHONY: veracruz-test
veracruz-test: setup
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

.PHONY: test-resources
test-resources:
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

.PHONY: test-system
test-system: $(now) runtime-manager veracruz-server-test veracruz-test test-resources
	$(nix_build) $(nix_expression) -A $(nix_attribute_path).$@

# convenient shortcut
.PHONY: test-system-stale
test-system-stale: $(now) # implicit prerequisites: runtime-manager veracruz-server-test veracruz-test test-resources
	$(nix_build) $(nix_expression) -A $(nix_attribute_path).test-system

# convenient shortcut
.PHONY: test-system-stale-test-resources
test-system-stale-test-resources: $(now) runtime-manager veracruz-server-test veracruz-test # implicit prerequisite: test-resources
	$(nix_build) $(nix_expression) -A $(nix_attribute_path).test-system

.PHONY: set-key-permissions
set-key-permissions:
	chmod 0400 nix/host/keys/client.priv

.PHONY: run-tests
run-tests: set-key-permissions $(now) runtime-manager veracruz-server-test veracruz-test test-resources
	script=$$($(nix_build) $(nix_expression) -A $(nix_attribute_path).$@ --no-out-link) && $$script

.PHONY: run-tests-stale
run-tests-stale: set-key-permissions $(now) # implicit prerequisites: runtime-manager veracruz-server-test veracruz-test test-resources
	script=$$($(nix_build) $(nix_expression) -A $(nix_attribute_path).run-tests --no-out-link) && $$script

# HACK for setting time in host and realm
$(now):
	mkdir -p $(dir $@)
	date +%s | tr -d '\n' > $@
