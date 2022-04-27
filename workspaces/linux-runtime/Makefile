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

linux: runtime-manager-enclave

runtime-manager-enclave:
	cargo build $(PROFILE_FLAG) $(V_FLAG) --features linux -p runtime_manager_enclave

doc:
	cargo doc

clippy:
	cargo clippy $(PROFILE_FLAG) $(V_FLAG) \
		-p runtime_manager_enclave -p execution-engine \
		-p session-manager -p policy-utils -p platform-services \
		--features runtime_manager_enclave/linux \
		--features execution-engine/std \
		--features session-manager/std \
		--features policy-utils/std \
		--features platform-services/std \
		-- --no-deps 

fmt:
	cargo fmt

clean:
	@cargo clean

clean-cargo-lock:
	rm -f Cargo.lock
