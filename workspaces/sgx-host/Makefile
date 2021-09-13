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
	RUSTFLAGS="-L/work/sgxsdk/lib64 -L/work/sgxsdk/sdk_libs" \
		cargo build --release \
		--features proxy-attestation-server/sgx \
		--features veracruz-client/sgx \
		--features veracruz-server/sgx \
		--features cli

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
