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

.PHONY: all doc clean fmt

all: crates/sdk/wasm-checker/bin/wasm-checker
	cargo build --release

crates/sdk/wasm-checker/bin/wasm-checker:
	$(MAKE) -C crates/sdk/wasm-checker

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
	rm -f Cargo.lock
