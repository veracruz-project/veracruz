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

.PHONY: all build build-tests build-veracruz-server-test clean \
	clean-cargo-lock clippy default doc fmt icecap-runtime \
	test-client test-dependencies test-server tests veracruz-test

default: build

tests: test-server test-client veracruz-test

tests-cca: test-server-cca

icecap_plat ?= qemu

WORKSPACE_DIR = $(abspath ..)
OUT_DIR ?= $(abspath test-collateral)
MEASUREMENT_FILE = $(abspath ../icecap-runtime/css-icecap.bin)
MEASUREMENT_PARAMETER = --css-file $(MEASUREMENT_FILE)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

# NOTE this file must define:
#  variables:
#   - host_feature_flags
#  rules:
#   - rustup-plat
include mk/$(icecap_plat).mk

VERACRUZ_ICECAP_QEMU_IMAGE = $(WORKSPACE_DIR)/icecap-runtime/build/$(icecap_plat)/disposable/cmake/elfloader/build/elfloader

VERACRUZ_ICECAP_LKVM_FIRMWARE_ADDRESS = $(shell cat /work/veracruz/workspaces/icecap-runtime/firmware_start)
VERACRUZ_ICECAP_LKVM_FIRMWARE_IMAGE = $(WORKSPACE_DIR)/icecap-runtime/css-icecap.bin
BUILD_PARAMETERS = VERACRUZ_ICECAP_QEMU_IMAGE=$(VERACRUZ_ICECAP_QEMU_IMAGE)

TEST_PARAMETERS = VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR)

QEMU_TEST_PARAMETERS = VERACRUZ_ICECAP_QEMU_IMAGE=$(VERACRUZ_ICECAP_QEMU_IMAGE) \
	$(TEST_PARAMETERS)

CCA_TEST_PARAMETERS = VERACRUZ_ICECAP_LKVM_FIRMWARE_ADDRESS=$(VERACRUZ_ICECAP_LKVM_FIRMWARE_ADDRESS) \
	$(TEST_PARAMETERS)

CLIPPY_OPTIONS = --no-deps -A clippy::type_complexity -A clippy::module_inception -D warnings

all: build test-collateral

build: rustup-plat icecap-runtime
	$(COMPILERS) $(BUILD_PARAMETERS) \
		cargo build $(PROFILE_FLAG) $(host_feature_flags) $(V_FLAG)

build-cca: rustup-plat
	$(COMPILERS) \
		cargo build $(PROFILE_FLAG) \
		-p proxy-attestation-server \
		-p veracruz-client -p veracruz-server \
		--features proxy-attestation-server/icecap \
		--features veracruz-client/icecap \
		--features veracruz-server/icecap-cca \
		--features cli \
		$(host_feature_flags) \
		$(V_FLAG)

build-veracruz-server-test: rustup-plat $(VERACRUZ_ICECAP_QEMU_IMAGE)
	$(COMPILERS) $(BUILD_PARAMETERS) \
		cargo test --no-run $(PROFILE_FLAG) \
		$(host_feature_flags) \
		$(V_FLAG)
	cp $$( \
		$(COMPILERS) $(BUILD_PARAMETERS) \
			cargo test --no-run $(PROFILE_FLAG) \
			$(host_feature_flags) \
			$(V_FLAG) \
			--message-format=json | jq -r '.executable | select(.)' \
		) target/release/veracruz-server-test

measurement-file: icecap-runtime

icecap-runtime:
	$(MAKE) -C ../icecap-runtime elfloader css-icecap.bin ICECAP_PLAT=$(icecap_plat)

test-dependencies: test-collateral icecap-runtime

CARGO_TEST = $(COMPILERS) $(QEMU_TEST_PARAMETERS) cargo test $(PROFILE_FLAG) \
	--features icecap

CCA_CARGO_TEST = $(COMPILERS)  $(CCA_TEST_PARAMETERS) cargo test $(PROFILE_FLAG) \
	$(host_feature_flags) --features icecap-cca

build-tests:
	$(CARGO_TEST) --no-run

test-server: test-dependencies build-tests
	$(CARGO_TEST) -p tests --test server_test -- --test-threads=1 --nocapture

build-tests-cca:
	$(CCA_CARGO_TEST) --no-run

test-server-cca: test-collateral
	$(CCA_CARGO_TEST) -p tests --test server_test --no-run -- --test-threads=1 --nocapture

test-client: test-dependencies
	$(CARGO_TEST) -p veracruz-client --lib -- --test-threads=1

veracruz-test: test-dependencies build-tests
	$(CARGO_TEST) --test integration_test -- --test-threads=1

doc:
	cargo doc

fmt:
	cargo fmt

clippy: rustup-plat icecap-runtime
	# workspace members and relevant dependencies
	$(BUILD_PARAMETERS) $(COMPILERS) \
	cargo clippy $(PROFILE_FLAG) \
		-p veracruz-client \
		-p veracruz-server -p io-utils -p transport-protocol \
		-p psa-attestation -p veracruz-utils \
		--features veracruz-client/icecap \
		--features veracruz-server/icecap \
		--features transport-protocol/icecap \
		--features io-utils/icecap \
		--features psa-attestation/icecap \
		--features veracruz-utils/icecap \
		-- $(CLIPPY_OPTIONS)
	# workspace testing crates
	$(COMPILERS) $(QEMU_TEST_PARAMETERS) cargo clippy --tests \
		$(PROFILE_FLAG) -p tests \
		--features tests/icecap \
		-- $(CLIPPY_OPTIONS)

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock
