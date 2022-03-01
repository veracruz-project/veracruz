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

.PHONY: all clean clean-cargo-lock doc fmt linux

default: all

WORKSPACE_DIR = $(abspath ..)

include $(WORKSPACE_DIR)/common.mk

############# Source code #################
SRC_DIR = $(abspath crates/runtime-manager)
COMMON_Src = $(SRC_DIR)/src/managers/*.rs
Linux_Src = $(COMMON_Src) $(SRC_DIR)/src/runtime_manager_linux.rs $(SRC_DIR)/src/main.rs

all: linux

linux: target/$(PROFILE_PATH)/runtime_manager_enclave \
	css-linux.bin

target/$(PROFILE_PATH)/runtime_manager_enclave: \
	Cargo.toml $(Linux_Src)
	cargo build $(PROFILE_FLAG) $(V_FLAG) --features linux \
		-p runtime_manager_enclave
	cp target/$(PROFILE_PATH)/runtime_manager_enclave .

css-linux.bin: target/$(PROFILE_PATH)/runtime_manager_enclave
	cp $< $@

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	@cargo clean
	@rm -f css-linux.bin

clean-cargo-lock:
	rm -f Cargo.lock
