# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root director for licensing
# and copyright information.

OUT_DIR?=.
FINAL_DIR?=.

.PHONY: all clean nitro

all: nitro

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

############# Source code #################

COMMON_Src = crates/runtime-manager/src/managers/*.rs


############# AWS Nitro Enclaves ###################
Nitro_Src = $(COMMON_Src) crates/runtime-manager/src/runtime_manager_nitro.rs \
	crates/runtime-manager/src/main.rs

nitro: runtime_manager.eif

css-nitro.bin: PCR0
	cp $< $@

runtime_manager.eif: target/x86_64-unknown-linux-musl/release/runtime_manager_enclave crates/runtime-manager/Dockerfile
	cp crates/runtime-manager/Dockerfile .
	nitro-cli build-enclave --docker-dir . --docker-uri runtime_manager --output-file runtime_manager.eif > measurements.json
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0

target/x86_64-unknown-linux-musl/release/runtime_manager_enclave: Cargo.toml $(Nitro_Src)
	cargo build -Z package-features -Z unstable-options --bin runtime_manager_enclave \
	--target x86_64-unknown-linux-musl --release --features nitro \
	-p runtime_manager_enclave --verbose

clean:
	@cargo clean
	@rm -rf target
	@rm -rf bin/
	@rm -f css-*.bin
