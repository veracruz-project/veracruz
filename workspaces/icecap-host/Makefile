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

ICECAP_PLAT ?= virt
WORKSPACE_DIR = $(abspath ..)
OUT_DIR ?= $(abspath test-collateral)
MEASUREMENT_FILE = $(abspath ../icecap-runtime/css-icecap.bin)
MEASUREMENT_PARAMETER = --css-file $(MEASUREMENT_FILE)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

COMPILERS = CC_x86_64_unknown_linux_gnu=gcc CC_aarch64_unknown_linux_gnu=gcc

RUNTIME_MANAGER_ENCLAVE = $(WORKSPACE_DIR)/icecap-runtime/build/virt/disposable/cmake/elfloader/build/elfloader
TEST_PARAMETERS = DATABASE_URL=$(PROXY_ATTESTATION_SERVER_DB) \
	VERACRUZ_POLICY_DIR=$(OUT_DIR) \
	VERACRUZ_TRUST_DIR=$(OUT_DIR) \
	VERACRUZ_PROGRAM_DIR=$(OUT_DIR) \
	VERACRUZ_DATA_DIR=$(OUT_DIR) \
	RUNTIME_MANAGER_ENCLAVE_PATH=$(RUNTIME_MANAGER_ENCLAVE)

all: build test-collateral

build:
	$(COMPILERS) RUST_BACKTRACE=full \
		cargo build $(PROFILE_FLAG) \
		-p proxy-attestation-server \
		-p veracruz-client -p veracruz-server \
		--features proxy-attestation-server/icecap \
		--features veracruz-client/icecap \
		--features veracruz-server/icecap \
		--features cli $(V_FLAG)

.PHONY: $(MEASUREMENT_FILE)
$(MEASUREMENT_FILE):
	$(MAKE) -C ../icecap-runtime elfloader css-icecap.bin ICECAP_PLAT=$(ICECAP_PLAT)

test-dependencies: test-collateral $(LINUX_ROOT_ENCLAVE) $(RUNTIME_MANAGER_ENCLAVE)

CARGO_TEST = $(COMPILERS) $(TEST_PARAMETERS) cargo test $(PROFILE_FLAG) --features icecap

test-server: test-dependencies
	$(CARGO_TEST) -p veracruz-server-test --no-run -- --nocapture
	$(CARGO_TEST) -p veracruz-server-test -- --test-threads=1 --nocapture
	$(CARGO_TEST) -p veracruz-server-test test_debug -- --ignored --test-threads=1

test-client: test-dependencies
	$(CARGO_TEST) -p veracruz-client --lib --features mock -- --test-threads=1

veracruz-test: test-dependencies
	$(CARGO_TEST) -p veracruz-test --no-run
	$(CARGO_TEST) -p veracruz-test -- --test-threads=1

$(RUNTIME_MANAGER_ENCLAVE):
	$(MAKE) -C ../icecap-runtime elfloader ICECAP_PLAT=$(ICECAP_PLAT)

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
	rm -rf $(OUT_DIR)

clean-cargo-lock:
	rm -f Cargo.lock
