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

.PHONY: all build install clean clean-cargo-lock default doc fmt clippy \
				test-dependencies test-collateral test-server test-client veracruz-test \
				tests

default: build

tests: test-server test-client veracruz-test

WORKSPACE_DIR = $(abspath ..)
include $(WORKSPACE_DIR)/common.mk

OUT_DIR ?= $(abspath test-collateral)
RUNTIME_ENCLAVE_BINARY_PATH = $(WORKSPACE_DIR)/linux-runtime/target/$(PROFILE_PATH)/runtime_manager_enclave
MEASUREMENT_FILE = $(RUNTIME_ENCLAVE_BINARY_PATH)
MEASUREMENT_PARAMETER = --css-file $(MEASUREMENT_FILE)
include $(WORKSPACE_DIR)/shared.mk

CC = CC_x86_64_unknown_linux_gnu=gcc CC_aarch64_unknown_linux_gnu=gcc
TEST_PARAMETERS = DATABASE_URL=$(PROXY_ATTESTATION_SERVER_DB) \
	VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR) \
	RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH)

all: build test-collateral

build:
	RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH) \
	$(CC) \
		cargo build $(PROFILE_FLAG) $(V_FLAG) \
		-p proxy-attestation-server \
		-p veracruz-client -p veracruz-server \
		--features proxy-attestation-server/linux \
		--features veracruz-client/linux \
		--features veracruz-server/linux \
		--features cli

install:
	# create full names
	cp -f target/$(PROFILE_PATH)/proxy-attestation-server $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/veracruz-client $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/veracruz-server $(BIN_DIR)
	# create short names
	ln -sf $(BIN_DIR)/proxy-attestation-server $(BIN_DIR)/vc-pas
	ln -sf $(BIN_DIR)/veracruz-server $(BIN_DIR)/vc-server
	ln -sf $(BIN_DIR)/veracruz-client $(BIN_DIR)/vc-client

test-dependencies: test-collateral $(RUNTIME_ENCLAVE_BINARY_PATH)

CARGO_TEST = RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH) \
	$(CC) \
	$(TEST_PARAMETERS) \
	cargo test $(PROFILE_FLAG) --features linux

test-server: test-dependencies
	$(CARGO_TEST) -p veracruz-server-test --no-run -- --nocapture
	$(CARGO_TEST) -p veracruz-server-test -- --test-threads=1 --nocapture
	$(CARGO_TEST) -p veracruz-server-test test_debug -- --ignored --test-threads=1

test-client: test-dependencies
	$(CARGO_TEST) -p veracruz-client --lib -- --test-threads=1

veracruz-test: test-dependencies
	$(CARGO_TEST) -p veracruz-test --no-run
	$(CARGO_TEST) -p veracruz-test -- --test-threads=1

$(RUNTIME_ENCLAVE_BINARY_PATH):
	$(MAKE) -C ../linux-runtime linux

clippy: 
	cargo clippy $(PROFILE_FLAG) $(V_FLAG) --features linux -p veracruz-client -- --no-deps
	cargo clippy $(PROFILE_FLAG) $(V_FLAG) --features linux -p proxy-attestation-server -- --no-deps
	RUNTIME_ENCLAVE_BINARY_PATH=$(ENCLAVE_BINARY_PATH) cargo clippy $(PROFILE_FLAG) $(V_FLAG) --features linux -p veracruz-server -- --no-deps
	RUNTIME_ENCLAVE_BINARY_PATH=$(ENCLAVE_BINARY_PATH) cargo clippy --tests $(PROFILE_FLAG) $(V_FLAG) --features linux -p veracruz-test -- --no-deps
	RUNTIME_ENCLAVE_BINARY_PATH=$(ENCLAVE_BINARY_PATH) cargo clippy --tests $(PROFILE_FLAG) $(V_FLAG) --features linux -p veracruz-server-test -- --no-deps

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock
