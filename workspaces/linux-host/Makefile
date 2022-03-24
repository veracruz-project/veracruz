# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

.PHONY: all build clean clean-cargo-lock default doc fmt \
	test-dependencies test-collateral test-server test-client veracruz-test

default: build

WORKSPACE_DIR = $(abspath ..)
OUT_DIR ?= $(abspath test-collateral)
MEASUREMENT_FILE = $(abspath ../linux-runtime/css-linux.bin)
MEASUREMENT_PARAMETER = --css-file $(MEASUREMENT_FILE)
ENCLAVE_BINARY_PATH = $(abspath $(WORKSPACE_DIR)/linux-runtime/runtime_manager_enclave)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

CC = CC_x86_64_unknown_linux_gnu=gcc CC_aarch64_unknown_linux_gnu=gcc
RUNTIME_MANAGER_ENCLAVE = $(WORKSPACE_DIR)/linux-runtime/target/$(PROFILE_PATH)/runtime_manager_enclave
TEST_PARAMETERS = DATABASE_URL=$(PROXY_ATTESTATION_SERVER_DB) \
	VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR) \
	RUNTIME_MANAGER_ENCLAVE_PATH=$(RUNTIME_MANAGER_ENCLAVE)

all: build test-collateral

build:
	$(CC) \
		cargo build $(PROFILE_FLAG) \
		-p proxy-attestation-server \
		-p veracruz-client -p veracruz-server \
		--features proxy-attestation-server/linux \
		--features veracruz-client/linux \
		--features veracruz-server/linux \
		--features cli

.PHONY: $(MEASUREMENT_FILE)
$(MEASUREMENT_FILE):
	$(MAKE) -C ../linux-runtime linux

test-dependencies: test-collateral $(RUNTIME_MANAGER_ENCLAVE)

CARGO_TEST = $(CC) $(TEST_PARAMETERS) cargo test $(PROFILE_FLAG) --features linux

test-server: test-dependencies
	RUNTIME_ENCLAVE_BINARY_PATH=$(ENCLAVE_BINARY_PATH) $(CARGO_TEST) -p veracruz-server-test --no-run -- --nocapture
	RUNTIME_ENCLAVE_BINARY_PATH=$(ENCLAVE_BINARY_PATH) $(CARGO_TEST) -p veracruz-server-test -- --test-threads=1 --nocapture
	RUNTIME_ENCLAVE_BINARY_PATH=$(ENCLAVE_BINARY_PATH) $(CARGO_TEST) -p veracruz-server-test test_debug -- --ignored --test-threads=1

test-client: test-dependencies
	$(CARGO_TEST) -p veracruz-client --lib --features mock -- --test-threads=1

veracruz-test: test-dependencies
	$(CARGO_TEST) -p veracruz-test --no-run
	$(CARGO_TEST) -p veracruz-test -- --test-threads=1

$(RUNTIME_MANAGER_ENCLAVE):
	$(MAKE) -C ../linux-runtime linux

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock
