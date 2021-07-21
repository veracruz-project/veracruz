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

.PHONY: all policy-files sgx trustzone linux-aarch64 linux-x64 deprecated

all: deprecated sgx

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

deprecated:
	@echo $(WARNING_COLOR)"The default target, compiling sgx, is deprecated. Please explicitly choose target, sgx, trustzone, linux-aarch64, or linux-x64."$(RESET_COLOR)

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


Veracruz_Server_Rust_Flags :=
Veracruz_Server_SRC_Files := $(shell find src/ -type f -name '*.rs') $(shell find src/ -type f -name 'Cargo.toml')
Veracruz_Server_Include_Paths := -I ./src -I$(SGX_SDK)/include
Veracruz_Server_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Veracruz_Server_Include_Paths)

Veracruz_Server_Rust_Path := ./target/debug
Veracruz_Server_Name := $(CUSTOM_BIN_PATH)/libveracruz_server.rlib

######## Enclave Settings ########

Crypto_Library_Name := sgx_tcrypto

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lruntime_manager_enclave -L$(RUNTIME_MANAGER_PATH)/lib/
Signed_RustEnclave_Name := $(CUSTOM_BIN_PATH)/runtime_manager.signed.so

sgx: $(Veracruz_Server_Name)

$(CUSTOM_LIBRARY_PATH): 
	mkdir -p $@

$(Veracruz_Server_Name): $(Veracruz_Server_SRC_Files) $(CUSTOM_LIBRARY_PATH)
	@SGX_SDK=$(SGX_SDK) cargo build $(Veracruz_Server_Rust_Flags) --features sgx
	@echo $(INFO_COLOR)"CARGO =>  $@"$(RESET_COLOR)


################## trustzone ###################
trustzone: $(Veracruz_Server_SRC_Files)
	cargo build --features tz --target aarch64-unknown-linux-gnu --release 
	@echo $(INFO_COLOR)"CARGO => $^"$(RESET_COLOR)

################## Linux ###################

linux-aarch64: $(Veracruz_Server_SRC_Files)
	cargo build --features linux --target aarch64-unknown-linux-gnu --release
	@echo $(INFO_COLOR)"CARGO => $^"$(RESET_COLOR)

linux-x64: $(Veracruz_Server_SRC_Files)
	cargo build --features linux --target x86_64-unknown-linux-gnu --release
	@echo $(INFO_COLOR)"CARGO => $^"$(RESET_COLOR)

.PHONY: clean
clean:
	@rm -f $(Veracruz_Server_Name) \
		$(RUNTIME_MANAGER_PATH)/*_t.* *_u.* lib/*.a ./bin/libveracruz_server_lib.rlib \
		Cargo.lock
	@rm -rf target lib
	@cargo clean
