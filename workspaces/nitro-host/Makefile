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

.PHONY: all build clean clean-cargo-lock doc fmt \
	test-client test-collateral test-dependencies test-server veracruz-test

default: build

WORKSPACE_DIR = $(abspath ..)
OUT_DIR ?= $(abspath test-collateral)
MEASUREMENT_FILE = $(abspath ../nitro-runtime/PCR0)
MEASUREMENT_PARAMETER = --pcr-file $(MEASUREMENT_FILE)
EIF_PATH = $(abspath $(WORKSPACE_DIR)/nitro-runtime/runtime_manager.eif)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

CC = CC_x86_64_unknown_linux_gnu=gcc CC_aarch64_unknown_linux_gnu=gcc
PROXY_ATTESTATION_SERVER_DB = proxy-attestation-server.db
TEST_PARAMETERS = DATABASE_URL=$(PROXY_ATTESTATION_SERVER_DB) \
	VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR) \

all: build test-collateral

build:
	$(CC) \
		cargo build $(PROFILE_FLAG) $(V_FLAG) \
		-p proxy-attestation-server \
		-p veracruz-client -p veracruz-server \
		--features proxy-attestation-server/nitro \
		--features veracruz-client/nitro \
		--features veracruz-server/nitro \
		--features cli

.PHONY: $(MEASUREMENT_FILE)
$(MEASUREMENT_FILE):
	$(MAKE) -C ../nitro-runtime nitro

test-dependencies: test-collateral $(PROXY_ATTESTATION_SERVER_DB)

CARGO_TEST = $(CC) $(TEST_PARAMETERS) cargo test $(PROFILE_FLAG) --features nitro

test-server: test-dependencies
	RUNTIME_MANAGER_EIF_PATH=$(EIF_PATH) $(CARGO_TEST) -p veracruz-server-test --features debug -- --test-threads=1
	RUNTIME_MANAGER_EIF_PATH=$(EIF_PATH) $(CARGO_TEST) -p veracruz-server-test test_debug --features debug -- --ignored --test-threads=1
	./nitro-terminate.sh

test-client: test-dependencies
	$(CARGO_TEST) -p veracruz-client --lib -- --test-threads=1

veracruz-test: test-dependencies
	RUNTIME_MANAGER_EIF_PATH=/work/veracruz/workspaces/nitro-runtime/runtime_manager.eif $(CARGO_TEST) -p veracruz-test -- --test-threads=1
	./nitro-terminate.sh

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock
