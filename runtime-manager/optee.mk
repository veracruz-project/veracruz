OPTEE_DIR ?= /work/rust-optee-trustzone-sdk
OPTEE_OS_DIR ?= $(OPTEE_DIR)/optee_os
UUID ?= $(shell cat "../runtime-manager-uuid.txt")

TA_SIGN_KEY ?= $(OPTEE_OS_DIR)/out/arm/export-ta_arm64/keys/default_ta.pem
SIGN := python2 $(OPTEE_OS_DIR)/out/arm/export-ta_arm64/scripts/sign.py
OPTEE_BIN := $(OPTEE_DIR)/toolchains/aarch64/bin
OBJCOPY := $(OPTEE_BIN)/aarch64-linux-gnu-objcopy
TARGET := aarch64-unknown-optee-trustzone


OUT_DIR := $(CURDIR)/target/$(TARGET)/release

all: runtime_manager_enclave strip sign

runtime_manager_enclave:
	@xargo build --target $(TARGET) --features tz --release --verbose

strip:
	@$(OBJCOPY) --strip-unneeded $(OUT_DIR)/runtime_manager_enclave $(OUT_DIR)/stripped_ta

sign:
	@$(SIGN) --uuid $(UUID) --key $(TA_SIGN_KEY) --in $(OUT_DIR)/stripped_ta --out $(OUT_DIR)/$(UUID).ta
	@echo "SIGN =>  ${UUID}"

clean:
	@xargo clean
