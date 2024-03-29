# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.md` file in the Veracruz root director for licensing
# and copyright information.

.PHONY: all clean clean-cargo-lock clippy default doc fmt nitro nitro-runtime-manager

default: all

WORKSPACE_DIR = $(abspath ..)
OUT_DIR ?= $(WORKSPACE_DIR)/nitro-host/test-collateral
ARCH = $(shell uname -m)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

all: nitro

nitro: nitro-runtime-manager
	$(MAKE) nitro_runtime_manager.eif PCR0

nitro_runtime_manager.eif PCR0 &: target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/nitro_runtime_manager crates/nitro-runtime-manager/dockerdir/Dockerfile
	rm -rf docker
	mkdir -p docker
	cp target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/nitro_runtime_manager docker
	cp crates/nitro-runtime-manager/dockerdir/Dockerfile docker
	perl -i -pe "s/x86_64/$(ARCH)/" docker/Dockerfile
	nitro-cli build-enclave --docker-dir docker --docker-uri runtime_manager --output-file nitro_runtime_manager.eif > measurements.json
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0
	rm -rf docker

nitro-runtime-manager:
	rustup target add $(ARCH)-unknown-linux-musl
	cargo build --target $(ARCH)-unknown-linux-musl $(PROFILE_FLAG) $(V_FLAG)
	strip -p target/$(ARCH)-unknown-linux-musl/$(PROFILE_PATH)/nitro_runtime_manager

doc:
	cargo doc

clippy:
	rustup target add $(ARCH)-unknown-linux-musl
	cargo clippy --target $(ARCH)-unknown-linux-musl $(PROFILE_FLAG) $(V_FLAG) \
		-p nitro-runtime -p nitro_runtime_manager -p execution-engine \
		-p session-manager -p policy-utils -p platform-services \
		-- --no-deps

fmt:
	cargo fmt

clean:
	@cargo clean
	@rm -f PCR0

clean-cargo-lock:
	rm -f Cargo.lock
