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

.PHONY: all linux clean quick-clean fmt fmt-check deprecated nitro update


all: deprecated

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

deprecated:
	@echo $(WARNING_COLOR)"Please explicitly choose target: linux, nitro." $(RESET_COLOR)

############# Source code #################

COMMON_Src = src/managers/*.rs

css-nitro.bin: PCR0
	cp $< $@

css-icecap.bin:
	touch $@

css-linux.bin: target/release/runtime_manager_enclave
	cp $< $@


############# AWS Nitro Enclaves ###################
Nitro_Src = $(COMMON_Src) src/runtime_manager_nitro.rs src/main.rs

nitro: runtime_manager.eif

runtime_manager.eif: target/x86_64-unknown-linux-musl/release/runtime_manager_enclave dockerdir/Dockerfile
	ln -f target/x86_64-unknown-linux-musl/release/runtime_manager_enclave dockerdir/
	nitro-cli build-enclave --docker-dir dockerdir --docker-uri runtime_manager --output-file $@.new > measurements.json
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0
	mv $@.new $@

target/x86_64-unknown-linux-musl/release/runtime_manager_enclave: Cargo.toml $(Nitro_Src)
	cargo build --target x86_64-unknown-linux-musl --release --features nitro

####### Linux (AArch64 and X64) processes  #########
Linux_Src = $(COMMON_Src) src/runtime_manager_linux.rs src/main.rs

target/release/runtime_manager_enclave: Cargo.toml $(Linux_Src)
	cargo build --release --features linux

linux: target/release/runtime_manager_enclave

####### Utility targets #######

clean:
	@cargo clean
	@xargo clean
	@rm -rf ./target
	@rm -f ./runtime_manager_t.? ./runtime_manager_u.?
	@rm -f $(OUT_DIR)/runtime_manager_enclave
	@rm -f $(RustEnclave_Name)
	@rm -rf ./bin/
	@rm -f ./css-*.bin

quick-clean:
	@cargo clean
	@xargo clean
	@rm -rf ./target
	@rm -f ./runtime_manager_t.? ./runtime_manager_u.?
	@rm -f $(OUT_DIR)/runtime_manager_enclave
	@rm -f $(RustEnclave_Name)
	@rm -rf ./bin/
	@rm -f ./css-*.bin

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

update:
	cargo update
