# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSE.md` file in the Veracruz root directory for
# licensing and copyright information.

.PHONY: all build build-tests clean clean-cargo-lock clippy default doc fmt \
	nitro-runtime test-client test-dependencies test-server tests veracruz-test

default: build

tests: test-server test-client veracruz-test

WORKSPACE_DIR = $(abspath ..)
OUT_DIR ?= $(abspath test-collateral)
MEASUREMENT_FILE = $(abspath ../nitro-runtime/PCR0)
MEASUREMENT_PARAMETER = --pcr-file $(MEASUREMENT_FILE)
EIF_PATH = $(abspath $(WORKSPACE_DIR)/nitro-runtime/nitro_runtime_manager.eif)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

TEST_PARAMETERS = VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR) \

CLIPPY_OPTIONS = --no-deps -A clippy::type_complexity -A clippy::module_inception -D warnings

all: build test-collateral

build:
	cargo build $(PROFILE_FLAG) $(V_FLAG)
	strip -p target/$(PROFILE_PATH)/veracruz-client target/$(PROFILE_PATH)/nitro-veracruz-server

measurement-file: nitro-runtime

nitro-runtime:
	$(MAKE) -C ../nitro-runtime nitro

test-dependencies: test-collateral nitro-runtime

CARGO_TEST = $(TEST_PARAMETERS) cargo test $(PROFILE_FLAG) --features nitro

build-tests:
	$(CARGO_TEST) --no-run

test-server: test-dependencies build-tests
	RUNTIME_MANAGER_EIF_PATH=$(EIF_PATH) $(CARGO_TEST) --test server_test -- --test-threads=1
	./nitro-terminate.sh

test-client: test-dependencies
	$(CARGO_TEST) -p veracruz-client --lib -- --test-threads=1

veracruz-test: test-dependencies build-tests
	RUNTIME_MANAGER_EIF_PATH=$(EIF_PATH) $(CARGO_TEST) --test integration_test -- --test-threads=1
	./nitro-terminate.sh

doc:
	cargo doc

fmt:
	cargo fmt

clippy: nitro-runtime
	# workspace members and relevant dependencies
	$(CC) cargo clippy $(PROFILE_FLAG) $(V_FLAG) \
		-p veracruz-client \
		-p nitro-veracruz-server -p io-utils -p transport-protocol \
		-p psa-attestation -p veracruz-utils \
		-- $(CLIPPY_OPTIONS)
	# workspace testing crates
	RUNTIME_MANAGER_EIF_PATH=$(EIF_PATH) $(CC) $(TEST_PARAMETERS) cargo clippy --tests \
		$(PROFILE_FLAG) -p tests  \
		-- $(CLIPPY_OPTIONS)

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock
