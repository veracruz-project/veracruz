ICECAP_PLAT ?= virt

crates_dir := crates
build_dir := build

now := $(build_dir)/NOW

nix_build := nix-build -j$(shell nproc)
nix_shell := nix-shell -j$(shell nproc) --pure
nix_expression := targets.nix
nix_attribute_path := $(ICECAP_PLAT)

.PHONY: all
all:

.PHONY: clean
clean:
	rm -rf $(crates_dir) $(build_dir)

.PHONY: setup
setup:
	$(nix_build) $(nix_expression) -A $(nix_attribute_path).crates -o $(crates_dir)

.PHONY: runtime-manager
runtime-manager: $(now) setup
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

.PHONY: veracruz-server-test
veracruz-server-test: setup
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

.PHONY: veracruz-test
veracruz-test: setup
	$(nix_shell) $(nix_expression) -A $(nix_attribute_path).$@ --run build

# must be run inside of container
.PHONY: test-resources
test-resources:
	$(MAKE) -C ../sdk
	TEE=icecap $(MAKE) -C ../test-collateral

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

# HACK for setting time in host and realm
$(now):
	mkdir -p $(dir $@)
	date +%s | tr -d '\n' > $@
