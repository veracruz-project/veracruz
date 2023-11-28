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
RUNTIME_ENCLAVE_BINARY_PATH = $(WORKSPACE_DIR)/sev-runtime/target/x86_64-unknown-linux-musl/$(PROFILE_PATH)/sev-runtime-manager
MEASUREMENT_FILE = $(abspath ../sev-runtime/measurement)
sev_measurement := $(shell cat ${MEASUREMENT_FILE})
MEASUREMENT_PARAMETER = --sevsnp-hash ${sev_measurement}
#MEASUREMENT_PARAMETER = --sevsnp-hash 5ebf61a0eb2e0714ec14c355f45d7156c786726ee4878834ab7897055bb47a7f2df2332a43cc0359b7daa26f7318456d
include $(WORKSPACE_DIR)/shared.mk

CC = CC_x86_64_unknown_linux_gnu=gcc CC_aarch64_unknown_linux_gnu=gcc
TEST_PARAMETERS = VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR) \
	RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH)

CLIPPY_OPTIONS = --no-deps -A clippy::type_complexity -A clippy::module_inception -D warnings

all: build test-collateral

build:
	RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH) \
	$(CC) \
		cd crates/veracruz-client && cargo build $(PROFILE_FLAG) $(V_FLAG) && cd ../.. && \
		cd crates/sev-veracruz-server && cargo build $(PROFILE_FLAG) $(V_FLAG) && cd ../..

install:
	# create full names
	cp -f target/$(PROFILE_PATH)/veracruz-client $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/sev-veracruz-server $(BIN_DIR)
	# create short names
	ln -sf $(BIN_DIR)/sev-veracruz-server $(BIN_DIR)/vc-server
	ln -sf $(BIN_DIR)/veracruz-client $(BIN_DIR)/vc-client

test-dependencies: test-collateral $(RUNTIME_ENCLAVE_BINARY_PATH)

CARGO_TEST = RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH) \
	$(CC) \
	$(TEST_PARAMETERS) \
	cargo test $(PROFILE_FLAG) --features sev

test-server: test-dependencies
	cd crates/tests/ && $(CARGO_TEST) -p tests --no-run -- --nocapture
	RUST_LOG="server_test=info,error" $(CARGO_TEST) --features sev -p tests --test server_test -- --test-threads=1 --nocapture

test-client: test-dependencies
	cd crates/veracruz-client && $(CARGO_TEST) -p veracruz-client --lib -- --test-threads=1

veracruz-test: test-dependencies
	cd crates/tests/ && $(CARGO_TEST) -p tests --no-run -- --nocapture
	RUST_LOG="integration_test=info,error" $(CARGO_TEST) --features sev -p tests --test integration_test -- --test-threads=1 --nocapture

$(RUNTIME_ENCLAVE_BINARY_PATH):
	cd crates/sev-runtime-manager && cargo build

clippy: $(RUNTIME_ENCLAVE_BINARY_PATH)
	# workspace members and relevant dependencies
	RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH) \
	$(CC) \
		cargo clippy $(PROFILE_FLAG) $(V_FLAG) \
		-p veracruz-client \
		-p sev-veracruz-server -p io-utils -p transport-protocol \
		-p veracruz-utils  \
		--features io-utils/linux \
		--features psa-attestation/linux \
		--features veracruz-utils/linux \
		-- $(CLIPPY_OPTIONS)
	# workspace testing crates
	RUNTIME_ENCLAVE_BINARY_PATH=$(RUNTIME_ENCLAVE_BINARY_PATH) $(CC) $(TEST_PARAMETERS) \
		cargo clippy --tests \
		$(PROFILE_FLAG) -p tests \
		--features tests/sev \
		-- $(CLIPPY_OPTIONS)

fmt:
	cargo fmt

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock