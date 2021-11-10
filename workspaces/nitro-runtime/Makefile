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

OUT_DIR ?= $(abspath .)
FINAL_DIR ?= $(abspath .)
WORKSPACE_DIR = $(abspath ..)

ifeq ($(shell uname -m),aarch64)
	ARCH = aarch64
else
	ARCH = x86_64
endif

all: nitro wasm-files policy-files

include $(WORKSPACE_DIR)/shared.mk

MEASUREMENT_FILE = $(abspath PCR0)
MEASUREMENT_PARAMETER = --pcr-file $(MEASUREMENT_FILE)

.PHONY: all clean nitro

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

############# Source code #################
SRC_DIR = $(abspath crates/runtime-manager)
COMMON_Src = $(SRC_DIR)/src/managers/*.rs

############# AWS Nitro Enclaves ###################
Nitro_Src = $(COMMON_Src) $(SRC_DIR)/src/runtime_manager_nitro.rs $(SRC_DIR)/src/main.rs

nitro: runtime_manager.eif

css-nitro.bin: PCR0
	cp $< $@

runtime_manager.eif: target/$(ARCH)-unknown-linux-musl/release/runtime_manager_enclave crates/runtime-manager/Dockerfile
	rm -rf docker
	mkdir -p docker/target/$(ARCH)-unknown-linux-musl/release
	cp target/$(ARCH)-unknown-linux-musl/release/runtime_manager_enclave docker/target/$(ARCH)-unknown-linux-musl/release
	cp crates/runtime-manager/Dockerfile docker
	perl -i -pe "s/x86_64/$(ARCH)/" docker/Dockerfile
	nitro-cli build-enclave --docker-dir docker --docker-uri runtime_manager --output-file runtime_manager.eif > measurements.json
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0
	rm -rf docker

target/$(ARCH)-unknown-linux-musl/release/runtime_manager_enclave: Cargo.toml $(Nitro_Src)
	rustup target add $(ARCH)-unknown-linux-musl
	CC_$(ARCH)_unknown_linux_musl=musl-gcc \
	cargo build -Z package-features -Z unstable-options --bin runtime_manager_enclave \
	  --target $(ARCH)-unknown-linux-musl --release --features nitro \
	  -p runtime_manager_enclave --verbose

clean:
	@cargo clean
	@rm -rf target
	@rm -rf bin/
	@rm -f css-*.bin
