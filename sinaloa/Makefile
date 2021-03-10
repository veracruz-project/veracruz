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

.PHONY: all policy-files sgx trustzone deprecated

all: deprecated sgx

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

deprecated:
	@echo $(WARNING_COLOR)"The default target, compiling sgx, is deprecated. Please explicitly choose target, sgx or trustzone."$(RESET_COLOR)

################## sgx ###################
SGX_SDK ?= /work/sgxsdk

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
RUST_SGX_SDK_PATH = ../third-party/rust-sgx-sdk

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif


ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

CUSTOM_LIBRARY_PATH := ./lib
CUSTOM_BIN_PATH := ./bin
CUSTOM_COMMON_PATH := $(RUST_SGX_SDK_PATH)/common


Sinaloa_Rust_Flags :=
Sinaloa_SRC_Files := $(shell find src/ -type f -name '*.rs') $(shell find src/ -type f -name 'Cargo.toml')
Sinaloa_Include_Paths := -I ./src -I$(SGX_SDK)/include
Sinaloa_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Sinaloa_Include_Paths)

Sinaloa_Rust_Path := ./target/debug
Sinaloa_Name := $(CUSTOM_BIN_PATH)/libsinaloa.rlib

######## Enclave Settings ########

Crypto_Library_Name := sgx_tcrypto

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lruntime_manager_enclave -L$(RUNTIME_MANAGER_PATH)/lib/
Signed_RustEnclave_Name := $(CUSTOM_BIN_PATH)/runtime_manager.signed.so

sgx: $(Sinaloa_Name)

$(CUSTOM_LIBRARY_PATH): 
	mkdir -p $@

$(Sinaloa_Name): $(Sinaloa_SRC_Files) $(CUSTOM_LIBRARY_PATH)
	@SGX_SDK=$(SGX_SDK) cargo build $(Sinaloa_Rust_Flags) --features sgx
	@echo $(INFO_COLOR)"CARGO =>  $@"$(RESET_COLOR)


################## trustzone ###################
trustzone: $(Sinaloa_SRC_Files)
	cargo build --features tz --target aarch64-unknown-linux-gnu --release 
	@echo $(INFO_COLOR)"CARGO => $^"$(RESET_COLOR)

.PHONY: clean
clean:
	@rm -f $(Sinaloa_Name) \
		$(RUNTIME_MANAGER_PATH)/*_t.* *_u.* lib/*.a ./bin/libsinaloa_lib.rlib \
		Cargo.lock
	@rm -rf target lib
	@cargo clean
