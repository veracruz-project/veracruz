# Makefile for the Veracruz JSON policy generation utility.
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSE.md` file in the Veracruz root directory for
# licensing and copyright information.

.PHONY: all doc clean quick-clean fmt fmt-check update

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
	rm -f Cargo.lock

quick-clean:
	cargo clean

update:
	cargo update
