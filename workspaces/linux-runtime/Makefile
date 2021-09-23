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

OUT_DIR ?= $(abspath crates/test-collateral)
FINAL_DIR ?= $(abspath .)
WORKSPACE_DIR = $(abspath ..)

all: linux wasm-files policy-files

include $(WORKSPACE_DIR)/shared.mk

MEASUREMENT_FILE = $(abspath css-linux.bin)
MEASUREMENT_PARAMETER = --css-file $(MEASUREMENT_FILE)

.PHONY: all clean linux wasm-files policy-files

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

############# Source code #################
SRC_DIR = $(abspath crates/runtime-manager)
COMMON_Src = $(SRC_DIR)/src/managers/*.rs

############# AWS Nitro Enclaves ###################
Linux_Src = $(COMMON_Src) $(SRC_DIR)/src/runtime_manager_linux.rs $(SRC_DIR)/src/main.rs

target/release/runtime_manager_enclave: Cargo.toml $(Linux_Src)
	cargo build --release --features linux

target/release/linux-root-enclave: Cargo.toml crates/linux-root-enclave/src/main.rs
	cargo build --release --features linux


linux: css-linux.bin target/release/linux-root-enclave

css-linux.bin: target/release/runtime_manager_enclave
	cp $< $@

clean:
	@cargo clean
	@rm -rf target
	@rm -f css-linux.bin
