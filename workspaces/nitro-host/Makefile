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

all:
	rustup target add x86_64-unknown-linux-musl
	cargo build --release \
		--features proxy-attestation-server/nitro \
		--features veracruz-client/nitro \
		--features veracruz-server/nitro \
		--features veracruz-server-test/nitro \
		--features veracruz-test/nitro \
		--features cli

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
