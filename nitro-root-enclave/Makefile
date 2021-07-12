# This makefile is used to generate the AWS Nitro Enclave for the Veracruz root
# enclave
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

all: nitro_root_enclave.eif

target/x86_64-unknown-linux-musl/release/nitro-root-enclave: Cargo.toml src/*.rs
	cargo build --target x86_64-unknown-linux-musl --release

nitro_root_enclave.eif: target/x86_64-unknown-linux-musl/release/nitro-root-enclave Dockerfile
	nitro-cli build-enclave --docker-dir . --docker-uri nitro_root_enclave --output-file nitro_root_enclave.eif > measurements.json
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0

.PHONY:
clean:
	rm -f PCR0
	rm -f nitro_root_enclave.eif
	cargo clean
