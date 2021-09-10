# Makefile
#
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root director for licensing
# and copyright information.

OUT_DIR ?= .
SRC_DIR ?= crates/runtime-manager
FINAL_DIR ?= .

.PHONY: all sgx clean

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

all: sgx

############# SGX #################
Signed_RustEnclave_RootName := runtime_manager.signed.so
Signed_RustEnclave_Name := $(OUT_DIR)/$(Signed_RustEnclave_RootName)
Untrusted_Lib_Name := $(OUT_DIR)/libruntime_manager_u.a
SGX_Enclave_Name ?= $(OUT_DIR)/libruntime_manager_enclave.a

$(FINAL_DIR)/$(Signed_RustEnclave_RootName): $(Signed_RustEnclave_Name)
	cp $< $@


# TODO: Bring the rest of the SGX compilation

sgx: $(FINAL_DIR)/$(Signed_RustEnclave_RootName) $(SGX_Enclave_Name) $(Signed_RustEnclave_Name) $(Untrusted_Lib_Name)

# Note: css-sgx.bin will be generated as a side effect of the dependency $(Signed_RustEnclave_Name)
css-sgx.bin: $(Signed_RustEnclave_Name)

############# Source code #################

COMMON_Src = $(SRC_DIR)/src/managers/*.rs

############# Files generated from the EDL File ###############
EDL_Files := $(OUT_DIR)/runtime_manager_t.c $(OUT_DIR)/runtime_manager_t.h $(OUT_DIR)/runtime_manager_u.c $(OUT_DIR)/runtime_manager_u.h

SGX_SDK ?= /work/sgxsdk

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
RUST_SGX_SDK_PATH = crates/third-party/rust-sgx-sdk

$(EDL_Files): $(SGX_EDGER8R) $(SRC_DIR)/runtime_manager.edl
	$(SGX_EDGER8R) --use-prefix --trusted $(SRC_DIR)/runtime_manager.edl --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_SDK_PATH)/edl --trusted-dir .
	$(SGX_EDGER8R) --use-prefix --untrusted $(SRC_DIR)/runtime_manager.edl --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_SDK_PATH)/edl --untrusted-dir .
	# cp -u runtime_manager_t.c $(OUT_DIR)
	# cp -u runtime_manager_u.c $(OUT_DIR)
	# cp -u runtime_manager_u.h $(OUT_DIR)
	# cp -u runtime_manager_t.h $(OUT_DIR)
	@echo $(INFO_COLOR) "GEN => $(EDL_Files)" $(RESET_COLOR)

SGX_COMMON_CFLAGS += -O0 -g
CUSTOM_EDL_PATH :=$(RUST_SGX_SDK_PATH)/edl
RuntimeManager_Include_Paths := -I ./src -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
RuntimeManager_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(RuntimeManager_Include_Paths)
$(OUT_DIR)/runtime_manager_u.o: $(EDL_Files)
	@$(CC) $(RuntimeManager_C_Flags) -c $(OUT_DIR)/runtime_manager_u.c -o $@
	@echo $(INFO_COLOR) "CC => $<" $(RESET_COLOR)

CUSTOM_COMMON_PATH := $(RUST_SGX_SDK_PATH)/common
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ,
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(RustEnclave_Include_Paths)
$(OUT_DIR)/runtime_manager_t.o: $(EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c ./runtime_manager_t.c -o $@
	@echo $(INFO_COLOR) "CC >= $<" $(RESET_COLOR)
$(Untrusted_Lib_Name): $(OUT_DIR)/runtime_manager_u.o
	$(AR) rcsD $@ $(OUT_DIR)/runtime_manager_u.o
	@echo $(INFO_COLOR) "AR >= $<" $(RESET_COLOR)

RustEnclave_Link_Libs = -L$(CUSTOM_LIBRARY_PATH) -L$(OUT_DIR) -lruntime_manager_enclave 
RustEnclave_Link_Flags = $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tservice -lsgx_tcrypto $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=$(SRC_DIR)/Enclave.lds

RustEnclave_Name := $(OUT_DIR)/runtime_manager.so


$(RustEnclave_Name): $(OUT_DIR)/runtime_manager_t.o $(SGX_Enclave_Name)
	@$(CXX) $(OUT_DIR)/runtime_manager_t.o -o $@ -L$(OUT_DIR) $(RustEnclave_Link_Flags)
	@echo $(INFO_COLOR) "LINK =>  $@" $(RESET_COLOR)

$(Signed_RustEnclave_Name): $(RustEnclave_Name) $(SGX_Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(SRC_DIR)/Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config $(SRC_DIR)/Enclave.config.xml -cssfile css-sgx.bin
	@echo $(INFO_COLOR) "SIGN =>  $@" $(RESET_COLOR)

$(RuntimeManager_u_Object): $(OUT_DIR)/runtime_manager_u.o
	$(AR) rcsD $@ $(OUT_DIR)/runtime_manager_u.o
	@echo $(INFO_COLOR) "AR => $@" $(RESET_COLOR)

SGX_Src =  $(COMMON_Src) $(SRC_DIR)/src/lib.rs $(SRC_DIR)/src/runtime_manager_sgx.rs
SGX_Target_Path ?= crates/third-party/rust-sgx-sdk/xargo

$(SGX_Enclave_Name): $(SGX_Src)
	@echo $(INFO_COLOR) "compiling $(SGX_Enclave_Name)" $(RESET_COLOR)

ifeq ($(XARGO_SGX), 1)
	@SGX_TARGET_PATH=$(SGX_Target_Path) xargo build --target x86_64-unknown-linux-sgx --release
else
	# RUSTFLAGS="-L/work/sgxsdk/lib64 -L/work/sgxsdk/sdk_libs" cargo build --lib --release -p runtime-manager-bind
	RUSTFLAGS="-L/work/sgxsdk/lib64 -L/work/sgxsdk/sdk_libs" \
		cargo build -Z package-features -Z unstable-options --release --lib \
		--features sgx -p runtime_manager_enclave --out-dir $(OUT_DIR)
endif

clean:
	@cargo clean
	@xargo clean
	@rm -rf target
	@rm -f runtime_manager_t.? runtime_manager_u.? libruntime_manager_u.?
	@rm -f $(FINAL_DIR)/$(Signed_RustEnclave_RootName)
	@rm -f $(SGX_Enclave_Name)
	@rm -f $(RustEnclave_Name)
	@rm -rf bin/
	@rm -f css-*.bin
