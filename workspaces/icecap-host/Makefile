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

.PHONY: all build clean clean-cargo-lock default doc clippy fmt clippy \
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

COMPILERS ?= CC_x86_64_unknown_linux_gnu=gcc CC_aarch64_unknown_linux_gnu=gcc

VERACRUZ_ICECAP_QEMU_IMAGE = $(WORKSPACE_DIR)/icecap-runtime/build/$(icecap_plat)/disposable/cmake/elfloader/build/elfloader

BUILD_PARAMETERS = VERACRUZ_ICECAP_QEMU_IMAGE=$(VERACRUZ_ICECAP_QEMU_IMAGE)
TEST_PARAMETERS = VERACRUZ_ICECAP_QEMU_IMAGE=$(VERACRUZ_ICECAP_QEMU_IMAGE) \
	DATABASE_URL=$(PROXY_ATTESTATION_SERVER_DB) \
	VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR)

all: build test-collateral

build: rustup-plat $(VERACRUZ_ICECAP_QEMU_IMAGE)
	$(COMPILERS) $(BUILD_PARAMETERS) \
		cargo build $(PROFILE_FLAG) \
		-p proxy-attestation-server \
		-p veracruz-client -p veracruz-server \
		--features proxy-attestation-server/icecap \
		--features veracruz-client/icecap \
		--features veracruz-server/icecap \
		--features cli \
		$(host_feature_flags) \
		$(V_FLAG)

build-veracruz-server-test: rustup-plat $(VERACRUZ_ICECAP_QEMU_IMAGE)
	$(COMPILERS) $(BUILD_PARAMETERS) \
		cargo test --no-run $(PROFILE_FLAG) \
		-p veracruz-server-test \
		--features icecap \
		$(host_feature_flags) \
		$(V_FLAG)
	cp $$( \
		$(COMPILERS) $(BUILD_PARAMETERS) \
			cargo test --no-run $(PROFILE_FLAG) \
			-p veracruz-server-test \
			--features icecap \
			$(host_feature_flags) \
			$(V_FLAG) \
			--message-format=json | jq -r '.executable | select(.)' \
		) target/release/veracruz-server-test

.PHONY: $(MEASUREMENT_FILE)
$(MEASUREMENT_FILE):
	$(MAKE) -C ../icecap-runtime elfloader css-icecap.bin ICECAP_PLAT=$(ICECAP_PLAT)

test-dependencies: test-collateral $(VERACRUZ_ICECAP_QEMU_IMAGE)

CARGO_TEST = $(COMPILERS) $(TEST_PARAMETERS) cargo test $(PROFILE_FLAG) \
	--features icecap

test-server: test-dependencies
	$(CARGO_TEST) -p veracruz-server-test --no-run -- --nocapture
	$(CARGO_TEST) -p veracruz-server-test -- --test-threads=1 --nocapture
	$(CARGO_TEST) -p veracruz-server-test test_debug -- --ignored --test-threads=1

test-client: test-dependencies
	$(CARGO_TEST) -p veracruz-client --lib -- --test-threads=1

veracruz-test: test-dependencies
	$(CARGO_TEST) -p veracruz-test --no-run
	$(CARGO_TEST) -p veracruz-test -- --test-threads=1

$(VERACRUZ_ICECAP_QEMU_IMAGE):
	$(MAKE) -C ../icecap-runtime elfloader ICECAP_PLAT=$(ICECAP_PLAT)

doc:
	cargo doc

fmt:
	cargo fmt

clippy:
	# workspace members and relevant dependencies
	$(BUILD_PARAMETERS) $(COMPILERS) cargo clippy $(PROFILE_FLAG) \
		-p proxy-attestation-server -p veracruz-client \
		-p veracruz-server -p io-utils -p transport-protocol \
		-p psa-attestation -p veracruz-utils \
		--features proxy-attestation-server/icecap \
		--features veracruz-client/icecap \
		--features veracruz-server/icecap \
		--features transport-protocol/icecap \
		--features io-utils/icecap \
		--features psa-attestation/icecap \
		--features veracruz-utils/icecap \
		-- --no-deps
	# workspace testing crates
	$(COMPILERS) $(TEST_PARAMETERS) cargo clippy --tests \
		$(PROFILE_FLAG) -p veracruz-test -p veracruz-server-test \
		--features veracruz-test/icecap \
		--features veracruz-server-test/icecap \
		-- --no-deps

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock
