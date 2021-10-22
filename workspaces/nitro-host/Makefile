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
CC = CC_x86_64_unknown_linux_gnu=gcc CC_aarch64_unknown_linux_gnu=gcc

all:
	rustup target add x86_64-unknown-linux-musl
	$(CC) cargo build --release \
		--features proxy-attestation-server/nitro \
		--features veracruz-client/nitro \
		--features veracruz-server/nitro \
		--features veracruz-server-test/nitro \
		--features veracruz-test/nitro \
		--features cli -v

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
