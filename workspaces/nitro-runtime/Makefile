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

.PHONY: all clean clean-cargo-lock default doc fmt nitro test-collateral

default: all

WORKSPACE_DIR = $(abspath ..)
OUT_DIR ?= $(WORKSPACE_DIR)/nitro-host/test-collateral
ARCH = $(shell uname -m)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

############# Source code #################
SRC_DIR = $(abspath crates/runtime-manager)
COMMON_Src = $(SRC_DIR)/src/managers/*.rs
Nitro_Src = $(COMMON_Src) $(SRC_DIR)/src/runtime_manager_nitro.rs $(SRC_DIR)/src/main.rs

all: nitro

nitro: runtime_manager.eif PCR0 css-nitro.bin

css-nitro.bin: PCR0
	cp $< $@

runtime_manager.eif PCR0: target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime_manager_enclave crates/runtime-manager/dockerdir/Dockerfile
	rm -rf docker
	mkdir -p docker
	cp target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime_manager_enclave docker
	cp crates/runtime-manager/dockerdir/Dockerfile docker
	perl -i -pe "s/x86_64/$(ARCH)/" docker/Dockerfile
	nitro-cli build-enclave --docker-dir docker --docker-uri runtime_manager --output-file runtime_manager.eif > measurements.json
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0
	rm -rf docker

target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime_manager_enclave: Cargo.toml $(Nitro_Src)
	rustup target add $(ARCH)-unknown-linux-musl
	CC_$(ARCH)_unknown_linux_musl=musl-gcc \
	cargo build --target $(ARCH)-unknown-linux-musl $(PROFILE_FLAG) $(V_FLAG) \
		--features nitro -p runtime_manager_enclave

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	@cargo clean
	@rm -f css-nitro.bin PCR0

clean-cargo-lock:
	rm -f Cargo.lock
