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

.PHONY: all build clean clean-cargo-lock default doc fmt clippy \
	test-dependencies test-collateral test-server test-client veracruz-test \
	tests

default: build

tests: test-server test-client veracruz-test

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

BUILD_PARAMETERS = VERACRUZ_ICECAP_QEMU_IMAGE=$(VERACRUZ_ICECAP_QEMU_IMAGE)
TEST_PARAMETERS = VERACRUZ_ICECAP_QEMU_IMAGE=$(VERACRUZ_ICECAP_QEMU_IMAGE) \
	VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR)

CLIPPY_OPTIONS = --no-deps -A clippy::type_complexity -A clippy::module_inception -D warnings

all: build test-collateral

build: rustup-plat $(VERACRUZ_ICECAP_QEMU_IMAGE)
	$(COMPILERS) $(BUILD_PARAMETERS) \
		cargo build $(PROFILE_FLAG) $(host_feature_flags) $(V_FLAG)

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

.PHONY: $(MEASUREMENT_FILE)
$(MEASUREMENT_FILE):
	$(MAKE) -C ../icecap-runtime elfloader css-icecap.bin ICECAP_PLAT=$(ICECAP_PLAT)

test-dependencies: test-collateral $(VERACRUZ_ICECAP_QEMU_IMAGE)

CARGO_TEST = $(COMPILERS) $(TEST_PARAMETERS) cargo test $(PROFILE_FLAG)

test-server: test-dependencies
	$(CARGO_TEST) --test server_test -- --test-threads=1 --nocapture

test-client: test-dependencies
	$(CARGO_TEST) -p veracruz-client --lib -- --test-threads=1

veracruz-test: test-dependencies
	$(CARGO_TEST) --test integration_test -- --test-threads=1

$(VERACRUZ_ICECAP_QEMU_IMAGE):
	$(MAKE) -C ../icecap-runtime elfloader ICECAP_PLAT=$(ICECAP_PLAT)

doc:
	cargo doc

fmt:
	cargo fmt

clippy: rustup-plat $(VERACRUZ_ICECAP_QEMU_IMAGE)
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
	$(COMPILERS) $(TEST_PARAMETERS) cargo clippy --tests \
		$(PROFILE_FLAG) -p tests \
		--features tests/icecap \
		-- $(CLIPPY_OPTIONS)

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock
