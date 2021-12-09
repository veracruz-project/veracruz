# Makefile to build freestanding-execution-engine
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

.PHONY: all clean clean-cargo-lock quick-clean doc fmt fmt-check update

all:
	cargo build --release

doc:
	cargo doc

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

clean:
	cargo clean

clean-cargo-lock:
	rm -f Cargo.lock

quick-clean:
	cargo clean

update:
	cargo update
