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

.PHONY: all build install clean clean-cargo-lock default doc fmt \
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
	RUNTIME_ENCLAVE_BINARY_PATH=$(ENCLAVE_BINARY_PATH) \
	$(CC) \
		cargo build $(PROFILE_FLAG) $(V_FLAG) \
		-p proxy-attestation-server \
		-p veracruz-client -p veracruz-server \
		--features proxy-attestation-server/linux \
		--features veracruz-client/linux \
		--features veracruz-server/linux \
		--features cli

install: build
	# create full names
	cp -f target/$(PROFILE_PATH)/proxy-attestation-server $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/veracruz-client $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/veracruz-server $(BIN_DIR)
	# create short names
	ln -sf $(BIN_DIR)/proxy-attestation-server $(BIN_DIR)/vc-pas
	ln -sf $(BIN_DIR)/veracruz-server $(BIN_DIR)/vc-server
	ln -sf $(BIN_DIR)/veracruz-client $(BIN_DIR)/vc-client

.PHONY: $(MEASUREMENT_FILE)
$(MEASUREMENT_FILE):
	$(MAKE) -C ../linux-runtime linux

test-dependencies: test-collateral $(RUNTIME_MANAGER_ENCLAVE)

CARGO_TEST = RUNTIME_ENCLAVE_BINARY_PATH=$(ENCLAVE_BINARY_PATH) \
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
