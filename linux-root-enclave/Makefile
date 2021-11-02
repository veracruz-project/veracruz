# Makefile for the Linux root enclave (application).
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

.PHONY: linux fmt clean

linux:
	cargo build --release

fmt:
	cargo fmt

clean:
	cargo clean
	$(RM) -f Cargo.lock
