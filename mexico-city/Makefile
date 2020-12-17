# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root director for licensing
# and copyright information.

OUT_DIR?=.
FINAL_DIR?=.

.PHONY: all sgx trustzone clean deprecated nitro

all: deprecated sgx

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

deprecated:
	@echo $(WARNING_COLOR)"The default target, compiling sgx, is deprecated. Please explicitly choose target, sgx or trustzone." $(RESET_COLOR)

############# SGX #################
Signed_RustEnclave_RootName := mexicocity.signed.so
Signed_RustEnclave_Name := $(OUT_DIR)/$(Signed_RustEnclave_RootName)
Untrusted_Lib_Name := $(OUT_DIR)/libmexico_city_u.a
SGX_Enclave_Name ?= $(OUT_DIR)/libmexico_city_enclave.a

$(FINAL_DIR)/$(Signed_RustEnclave_RootName): $(Signed_RustEnclave_Name)
	cp $< $@

.PHONY: all clean format

sgx: $(FINAL_DIR)/$(Signed_RustEnclave_RootName) $(SGX_Enclave_Name) $(Signed_RustEnclave_Name) $(Untrusted_Lib_Name)

css.bin: $(Signed_RustEnclave_Name)

############# Source code #################

COMMON_Src = src/managers/*.rs

############# Files generated from the EDL File ###############
EDL_Files := mexico_city_t.c mexico_city_t.h mexico_city_u.c mexico_city_u.h

SGX_SDK ?= /work/sgxsdk

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
RUST_SGX_SDK_PATH = ../third-party/rust-sgx-sdk

$(EDL_Files): $(SGX_EDGER8R) mexico_city.edl
	$(SGX_EDGER8R) --use-prefix --trusted mexico_city.edl --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_SDK_PATH)/edl --trusted-dir .
	$(SGX_EDGER8R) --use-prefix --untrusted mexico_city.edl --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_SDK_PATH)/edl --untrusted-dir .
	@echo $(INFO_COLOR) "GEN => $(EDL_Files)" $(RESET_COLOR)

SGX_COMMON_CFLAGS += -O0 -g
CUSTOM_EDL_PATH :=$(RUST_SGX_SDK_PATH)/edl
MexicoCity_Include_Paths := -I ./src -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
MexicoCity_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(MexicoCity_Include_Paths)
$(OUT_DIR)/mexico_city_u.o: $(EDL_Files)
	@$(CC) $(MexicoCity_C_Flags) -c ./mexico_city_u.c -o $@
	@echo $(INFO_COLOR) "CC => $<" $(RESET_COLOR)

CUSTOM_COMMON_PATH := $(RUST_SGX_SDK_PATH)/common
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ,
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(RustEnclave_Include_Paths)
$(OUT_DIR)/mexico_city_t.o: $(EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c ./mexico_city_t.c -o $@
	@echo $(INFO_COLOR) "CC >= $<" $(RESET_COLOR)
$(Untrusted_Lib_Name): $(OUT_DIR)/mexico_city_u.o
	$(AR) rcsD $@ $(OUT_DIR)/mexico_city_u.o
	@echo $(INFO_COLOR) "AR >= $<" $(RESET_COLOR)

RustEnclave_Link_Libs = -L$(CUSTOM_LIBRARY_PATH) -L$(OUT_DIR) -lmexico_city_enclave 
RustEnclave_Link_Flags = $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tservice -lsgx_tcrypto $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=./Enclave.lds

RustEnclave_Name := $(OUT_DIR)/mexicocity.so


$(RustEnclave_Name): $(OUT_DIR)/mexico_city_t.o $(SGX_Enclave_Name)
	@$(CXX) $(OUT_DIR)/mexico_city_t.o -o $@ -L$(OUT_DIR) $(RustEnclave_Link_Flags)
	@echo $(INFO_COLOR) "LINK =>  $@" $(RESET_COLOR)

$(Signed_RustEnclave_Name): $(RustEnclave_Name) $(SGX_Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key ./Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config ./Enclave.config.xml -cssfile css.bin
	@echo $(INFO_COLOR) "SIGN =>  $@" $(RESET_COLOR)

$(MexicoCity_u_Object): $(OUT_DIR)/mexico_city_u.o
	$(AR) rcsD $@ $(OUT_DIR)/mexico_city_u.o
	@echo $(INFO_COLOR) "AR => $@" $(RESET_COLOR)

SGX_Src =  $(COMMON_Src) src/lib.rs src/mc_sgx.rs
SGX_Target_Path ?= ../third-party/rust-sgx-sdk/xargo

$(SGX_Enclave_Name): $(SGX_Src)
	@echo $(INFO_COLOR) "compiling $(SGX_Enclave_Name)" $(RESET_COLOR)
ifeq ($(XARGO_SGX), 1)
	@SGX_TARGET_PATH=$(SGX_Target_Path) xargo build --target x86_64-unknown-linux-sgx --release
else
	@cargo build --lib --features sgx --release --out-dir $(OUT_DIR) -Z unstable-options
endif

############# TrustZone #################
TZ_Src =  $(COMMON_Src) src/mc_tz.rs src/main.rs
# OPTEE_DIR and OPTEE_OS_DIR can be imported from the environment
OPTEE_DIR ?= /work/rust-optee-trustzone-sdk/optee
OPTEE_OS_DIR ?= $(OPTEE_DIR)/optee_os
TZ_UUID_PATH ?= ../mexico_city_uuid.txt
TZ_UUID = $(shell cat "${TZ_UUID_PATH}")

TZ_TA_SIGN_KEY = $(OPTEE_OS_DIR)/out/arm/export-ta_arm64/keys/default_ta.pem
TZ_SIGN := python2 $(OPTEE_OS_DIR)/out/arm/export-ta_arm64/scripts/sign.py
OPTEE_BIN := $(OPTEE_DIR)/toolchains/aarch64/bin
TZ_OBJCOPY := $(OPTEE_BIN)/aarch64-linux-gnu-objcopy
TZ_TARGET := aarch64-unknown-optee-trustzone

trustzone: $(FINAL_DIR)/$(TZ_UUID).ta

$(FINAL_DIR)/$(TZ_UUID).ta: $(OUT_DIR)/$(TZ_UUID).ta
	cp $< $@

$(OUT_DIR)/$(TZ_UUID).ta: $(OUT_DIR)/stripped_ta $(TZ_TA_SIGN_KEY) $(TZ_UUID_PATH)
	@$(TZ_SIGN) --uuid $(TZ_UUID) --key $(TZ_TA_SIGN_KEY) --in $(OUT_DIR)/stripped_ta --out $(OUT_DIR)/$(TZ_UUID).ta
	@echo $(INFO_COLOR)"SIGN  =>  $(TZ_UUID)" $(RESET_COLOR)

$(OUT_DIR)/stripped_ta: $(OUT_DIR)/mexico_city_enclave
	@$(TZ_OBJCOPY) --strip-unneeded $(OUT_DIR)/mexico_city_enclave $(OUT_DIR)/stripped_ta
	@echo $(INFO_COLOR)"STRIP =>  mexico_city_enclave ---> stripped_ta" $(RESET_COLOR)

$(OUT_DIR)/mexico_city_enclave: $(TZ_Src)
	@echo $(INFO_COLOR)"CARGO <=  $(TZ_Src)" $(RESET_COLOR)
	@xargo build --target $(TZ_TARGET) --features tz --release --verbose --out-dir $(OUT_DIR) -Z unstable-options
	@echo $(INFO_COLOR)"GEN   =>  mexico_city_enclave" $(RESET_COLOR)


############# AWS Nitro Enclaves ###################
Nitro_Src = $(COMMON_Src) src/mc_nitro.rs src/main.rs

nitro: mexico_city.eif

mexico_city.eif: target/x86_64-unknown-linux-musl/release/mexico_city_enclave Dockerfile
	nitro-cli build-enclave --docker-dir . --docker-uri mexico_city --output-file mexico_city.eif > measurements.json
	cat measurements.json | jq -r '.Measurements.PCR0' > PCR0

target/x86_64-unknown-linux-musl/release/mexico_city_enclave: Cargo.toml $(Nitro_Src)
	cargo build --target x86_64-unknown-linux-musl --release --features nitro

clean:
	@cargo clean
	@xargo clean
	@rm -rf target
	@rm -f mexico_city_t.? mexico_city_u.?
	@rm -f $(FINAL_DIR)/$(Signed_RustEnclave_RootName)
	@rm -f $(SGX_Enclave_Name)
	@rm -f $(FINAL_DIR)/$(TZ_UUID).ta 
	@rm -f $(OUT_DIR)/$(TZ_UUID).ta 
	@rm -f $(OUT_DIR)/stripped_ta
	@rm -f $(OUT_DIR)/mexico_city_enclave
	@rm -rf bin/
	@rm -f css.bin
