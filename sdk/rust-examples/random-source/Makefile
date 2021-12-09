# Example Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

VERACRUZ_TARGET_PATH = $(shell cd ../../../ && pwd)

.PHONY: all doc clean quick-clean fmt fmt-check

all:
	cargo build --target wasm32-wasi --release

doc:
	cargo doc

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

clean:
	cargo clean
	rm -f Cargo.lock

quick-clean:
	cargo clean
