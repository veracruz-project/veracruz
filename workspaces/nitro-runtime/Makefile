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

.PHONY: all clean clean-cargo-lock default doc fmt clippy nitro test-collateral runtime-manager-enclave

default: all

WORKSPACE_DIR = $(abspath ..)
OUT_DIR ?= $(WORKSPACE_DIR)/nitro-host/test-collateral
ARCH = $(shell uname -m)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

all: nitro

nitro: runtime_manager.eif PCR0

runtime_manager.eif PCR0: target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime_manager_enclave crates/runtime-manager/dockerdir/Dockerfile
	rm -rf docker
	mkdir -p docker
	cp target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime_manager_enclave docker
	cp crates/runtime-manager/dockerdir/Dockerfile docker
	perl -i -pe "s/x86_64/$(ARCH)/" docker/Dockerfile
	nitro-cli build-enclave --docker-dir docker --docker-uri runtime_manager --output-file runtime_manager.eif > measurements.json
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0
	rm -rf docker

target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime_manager_enclave: runtime-manager-enclave

runtime-manager-enclave:
	rustup target add $(ARCH)-unknown-linux-musl
	CC_$(ARCH)_unknown_linux_musl=$(ARCH)-linux-musl-gcc \
	CXX_$(ARCH)_unknown_linux_musl=$(ARCH)-linux-musl-g++ \
	RUSTFLAGS="-C link-args=-Wl,--build-id=none" \
	cargo build --target $(ARCH)-unknown-linux-musl $(PROFILE_FLAG) $(V_FLAG) \
		--features nitro -p runtime_manager_enclave
	strip target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/runtime_manager_enclave

doc:
	cargo doc

clippy:
	rustup target add $(ARCH)-unknown-linux-musl
	CC_$(ARCH)_unknown_linux_musl=$(ARCH)-linux-musl-gcc \
	CXX_$(ARCH)_unknown_linux_musl=$(ARCH)-linux-musl-g++ \
	cargo clippy --target $(ARCH)-unknown-linux-musl $(PROFILE_FLAG) $(V_FLAG) \
		-p runtime_manager_enclave -p execution-engine \
		-p session-manager -p policy-utils -p platform-services \
		--features runtime_manager_enclave/nitro \
		--features execution-engine/nitro  \
		--features session-manager/nitro \
		--features policy-utils/std \
		--features platform-services/nitro \
		-- --no-deps

fmt:
	cargo fmt

clean:
	@cargo clean
	@rm -f PCR0

clean-cargo-lock:
	rm -f Cargo.lock
