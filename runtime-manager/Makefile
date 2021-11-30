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

.PHONY: all linux clean deprecated nitro

all: deprecated

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

deprecated:
	@echo $(WARNING_COLOR)"Please explicitly choose target: linux, nitro." $(RESET_COLOR)

############# Source code #################

COMMON_Src = src/managers/*.rs

############# Files generated from the EDL File ###############
EDL_Files := $(OUT_DIR)/runtime_manager_t.c $(OUT_DIR)/runtime_manager_t.h $(OUT_DIR)/runtime_manager_u.c $(OUT_DIR)/runtime_manager_u.h

RustEnclave_Link_Libs = -L$(CUSTOM_LIBRARY_PATH) -L$(OUT_DIR) -lruntime_manager_enclave
RustEnclave_Link_Flags = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-Wl,--whole-archive -Wl,--no-whole-archive \
	-Wl,--start-group $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=./Enclave.lds

RustEnclave_Name := $(OUT_DIR)/runtime_manager.so


$(RustEnclave_Name): $(OUT_DIR)/runtime_manager_t.o 
	@$(CXX) $(OUT_DIR)/runtime_manager_t.o -o $@ -L$(OUT_DIR) $(RustEnclave_Link_Flags)
	@echo $(INFO_COLOR) "LINK =>  $@" $(RESET_COLOR)

$(RuntimeManager_u_Object): $(OUT_DIR)/runtime_manager_u.o
	$(AR) rcsD $@ $(OUT_DIR)/runtime_manager_u.o
	@echo $(INFO_COLOR) "AR => $@" $(RESET_COLOR)

css-nitro.bin: PCR0
	cp $< $@

css-icecap.bin:
	touch $@

css-linux.bin: target/release/runtime_manager_enclave
	cp $< $@


############# AWS Nitro Enclaves ###################
Nitro_Src = $(COMMON_Src) src/runtime_manager_nitro.rs src/main.rs

nitro: runtime_manager.eif

runtime_manager.eif: target/x86_64-unknown-linux-musl/release/runtime_manager_enclave Dockerfile
	nitro-cli build-enclave --docker-dir . --docker-uri runtime_manager --output-file runtime_manager.eif > measurements.json
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0

target/x86_64-unknown-linux-musl/release/runtime_manager_enclave: Cargo.toml $(Nitro_Src)
	cargo build --target x86_64-unknown-linux-musl --release --features nitro

####### Linux (AArch64 and X64) processes  #########
Linux_Src = $(COMMON_Src) src/runtime_manager_linux.rs src/main.rs

target/release/runtime_manager_enclave: Cargo.toml $(Linux_Src)
	cargo build --release --features linux

linux: target/release/runtime_manager_enclave

clean:
	@cargo clean
	@xargo clean
	@rm -rf target
	@rm -f runtime_manager_t.? runtime_manager_u.?
	@rm -f $(FINAL_DIR)/$(Signed_RustEnclave_RootName)
	@rm -f $(OUT_DIR)/stripped_ta
	@rm -f $(OUT_DIR)/runtime_manager_enclave
	@rm -f $(RustEnclave_Name)
	@rm -rf bin/
	@rm -f css-*.bin
