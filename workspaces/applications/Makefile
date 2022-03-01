# Applications Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

.PHONY: all clean clean-cargo-lock doc fmt

WORKSPACE_DIR = $(abspath ..)
include $(WORKSPACE_DIR)/common.mk

all:
	rustup target add wasm32-wasi
	cargo build --target wasm32-wasi $(PROFILE_FLAG) $(V_FLAG)

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean

clean-cargo-lock:
	rm -f Cargo.lock
