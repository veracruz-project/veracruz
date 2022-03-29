# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root director for licensing
# and copyright information.

.PHONY: all clean clean-cargo-lock doc fmt linux runtime-manager-enclave

default: all

WORKSPACE_DIR = $(abspath ..)

include $(WORKSPACE_DIR)/common.mk

all: linux

linux: runtime-manager-enclave css-linux.bin

runtime-manager-enclave:
	cargo build $(PROFILE_FLAG) $(V_FLAG) --features linux -p runtime_manager_enclave
	cp target/$(PROFILE_PATH)/runtime_manager_enclave .

css-linux.bin: runtime-manager-enclave
	cp target/$(PROFILE_PATH)/runtime_manager_enclave $@

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	@cargo clean
	@rm -f css-linux.bin

clean-cargo-lock:
	rm -f Cargo.lock
