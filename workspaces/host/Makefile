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

.PHONY: all install clean clean-cargo-lock clean-datasets datasets doc fmt

WORKSPACE_DIR = $(abspath ..)
include $(WORKSPACE_DIR)/common.mk

all: crates/sdk/wasm-checker/bin/wasm-checker
	cargo build $(PROFILE_FLAG) $(V_FLAG)

install:
	# create full names
	cp -f target/$(PROFILE_PATH)/freestanding-execution-engine $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/generate-policy $(BIN_DIR)
	cp -f crates/sdk/wasm-checker/bin/wasm-checker $(BIN_DIR)
	# create short names
	ln -sf $(BIN_DIR)/freestanding-execution-engine $(BIN_DIR)/vc-fee
	ln -sf $(BIN_DIR)/generate-policy $(BIN_DIR)/vc-pgen
	ln -sf $(BIN_DIR)/wasm-checker $(BIN_DIR)/vc-wc


crates/sdk/wasm-checker/bin/wasm-checker:
	$(MAKE) -C crates/sdk/wasm-checker

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean

clean-cargo-lock:
	rm -f Cargo.lock
