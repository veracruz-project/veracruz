#@file  Makefile
# @author Derek Miller, Arm Research.
# @date   June 2019.
#
# @section LICENSE
#
# Copyright (c) Arm Limited, 2019.  All rights reserved.
#
OUT_DIR?=.
FINAL_DIR?=.
Signed_RustEnclave_RootName = trustzone_root_enclave.signed.so
Signed_RustEnclave_Name := $(OUT_DIR)/$(Signed_RustEnclave_RootName)
Untrusted_Lib_Name := $(OUT_DIR)/libtrustzone_root_enclave_u.a
SGX_Enclave_Name ?= $(OUT_DIR)/libtrustzone_root_enclave_t.a

.PHONY: all clean

all:$(FINAL_DIR)/$(SignedRustEnclave_RootName) $(SGX_Enclave_Name) $(Signed_RustEnclave_Name) $(Untrusted_Lib_Name)

$(FINAL_DIR)/$(SignedRustEnclave_RootName): $(Signed_RustEnclave_Name)
	cp $< $@

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"
############# Source code #################

COMMON_Src = src/lib.rs

############# Files generated from the EDL File ###############
EDL_Files := trustzone_root_enclave_t.c trustzone_root_enclave_t.h trustzone_root_enclave_u.c trustzone_root_enclave_u.h

SGX_SDK ?= /work/sgxsdk

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
RUST_SGX_SDK_PATH = ../third-party/rust-sgx-sdk

$(EDL_Files): $(SGX_EDGER8R) trustzone_root_enclave.edl
	@$(SGX_EDGER8R) --use-prefix --trusted trustzone_root_enclave.edl --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_SDK_PATH)/edl --trusted-dir .
	@$(SGX_EDGER8R) --use-prefix --untrusted trustzone_root_enclave.edl --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_SDK_PATH)/edl --untrusted-dir .
	@echo $(INFO_COLOR) "GEN => $(EDL_Files)" $(RESET_COLOR)

SGX_COMMON_CFLAGS += -O0 -g
CUSTOM_EDL_PATH :=$(RUST_SGX_SDK_PATH)/edl
Sinaloa_Include_Paths := -I ./src -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
Sinaloa_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Sinaloa_Include_Paths)
$(OUT_DIR)/trustzone_root_enclave_u.o: $(EDL_Files)
	@$(CC) $(Sinaloa_C_Flags) -c ./trustzone_root_enclave_u.c -o $@
	@echo $(INFO_COLOR) "CC => $<" $(RESET_COLOR)

CUSTOM_COMMON_PATH := $(RUST_SGX_SDK_PATH)/common
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ,
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(RustEnclave_Include_Paths)
$(OUT_DIR)/trustzone_root_enclave_t.o: $(EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c ./trustzone_root_enclave_t.c -o $@
	@echo "CC >= $<"
$(Untrusted_Lib_Name): $(OUT_DIR)/trustzone_root_enclave_u.o
	@$(AR) rcsD $@ $(OUT_DIR)/trustzone_root_enclave_u.o
	echo $(INFO_COLOR) "LINK => $@" $(RESET_COLOR)

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -L$(OUT_DIR) -ltrustzone_root_enclave
RustEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tservice -lsgx_tcrypto $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=./Enclave.lds

RustEnclave_Name := $(OUT_DIR)/trustzone_root_enclave.so


$(RustEnclave_Name): $(OUT_DIR)/trustzone_root_enclave_t.o $(SGX_Enclave_Name)
	@echo $(INFO_COLOR) "LINK =>  $@" $(RESET_COLOR)
	$(CXX) $(OUT_DIR)/trustzone_root_enclave_t.o -o $@ -L$(OUT_DIR) $(RustEnclave_Link_Flags)

$(Signed_RustEnclave_Name): $(RustEnclave_Name) $(SGX_Enclave_Name)
	@echo $(INFO_COLOR) "SIGN =>  $@" $(RESET_COLOR)
	@$(SGX_ENCLAVE_SIGNER) sign -key ./Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config ./Enclave.config.xml -cssfile css.bin

$(TrustZone_Root_Enclave_u_Object): $(OUT_DIR)/trustzone_root_enclave_u.o
	@$(AR) rcsD $@ $(OUT_DIR)/trustzone_root_enclave_u.o
	echo $(INFO_COLOR) "LINK => $@" $(RESET_COLOR)
############# SGX #################
SGX_Src =  $(COMMON_Src) src/lib.rs
SGX_Target_Path ?= ../third-party/rust-sgx-sdk/xargo

$(SGX_Enclave_Name): $(SGX_Src)
	@echo $(INFO_COLOR) "compiling $(SGX_Src)" $(RESET_COLOR)
ifeq ($(XARGO_SGX), 1)
	SGX_TARGET_PATH=$(SGX_Target_Path) xargo build --target x86_64-unknown-linux-sgx --release
else
	cargo build --lib --release --out-dir $(OUT_DIR) -Z unstable-options
endif

clean:
	@echo $(INFO_COLOR) "Cleaning..." $(RESET_COLOR)
	@cargo clean
	@xargo clean
	@rm -rf target
	@rm -f trustzone_root_enclave_t.? trustzone_root_enclave_u.?
	@rm -f *.so
	@rm -f ccs.bin
