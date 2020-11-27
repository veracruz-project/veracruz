# Makefile for building jalisco
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.
 
.PHONY: all trustzone clean format

OUT_DIR?=.
FINAL_DIR?=.

all: trustzone

WARNING_COLOR := "\e[1;33m"
INFO_COLOR := "\e[1;32m"
RESET_COLOR := "\e[0m"

############# TrustZone #################
TZ_Src =  $(COMMON_Src) src/*.rs
# OPTEE_DIR and OPTEE_OS_DIR can be imported from the environment
OPTEE_DIR ?= /work/rust-optee-trustzone-sdk/optee
OPTEE_OS_DIR ?= $(OPTEE_DIR)/optee_os
TZ_UUID_PATH ?= ../jalisco_uuid.txt
TZ_UUID = $(shell cat "${TZ_UUID_PATH}")

TZ_TA_SIGN_KEY = $(OPTEE_OS_DIR)/out/arm/export-ta_arm64/keys/default_ta.pem
TZ_SIGN := python2 $(OPTEE_OS_DIR)/out/arm/export-ta_arm64/scripts/sign.py
OPTEE_BIN := $(OPTEE_DIR)/toolchains/aarch64/bin
TZ_OBJCOPY := $(OPTEE_BIN)/aarch64-linux-gnu-objcopy
TZ_TARGET := aarch64-unknown-optee-trustzone
#OUT_DIR := $(CURDIR)/target/$(TZ_TARGET)/release

trustzone: $(FINAL_DIR)/$(TZ_UUID).ta

$(FINAL_DIR)/$(TZ_UUID).ta: $(OUT_DIR)/$(TZ_UUID).ta
	cp $< $@

$(OUT_DIR)/$(TZ_UUID).ta: $(OUT_DIR)/stripped_ta $(TZ_TA_SIGN_KEY) $(TZ_UUID_PATH)
	@$(TZ_SIGN) --uuid $(TZ_UUID) --key $(TZ_TA_SIGN_KEY) --in $(OUT_DIR)/stripped_ta --out $@
	@echo $(INFO_COLOR)"SIGN  =>  $(TZ_UUID)" $(RESET_COLOR)

$(OUT_DIR)/stripped_ta: $(OUT_DIR)/jalisco
	@$(TZ_OBJCOPY) --strip-unneeded $(OUT_DIR)/jalisco $(OUT_DIR)/stripped_ta
	@echo $(INFO_COLOR)"STRIP =>  jalisco ---> stripped_ta" $(RESET_COLOR)

$(OUT_DIR)/jalisco: $(TZ_Src)
	@echo $(INFO_COLOR)"XARGO <=  $(TZ_Src)" $(RESET_COLOR)
	@xargo build --target $(TZ_TARGET) --release -vv --out-dir $(OUT_DIR) -Z unstable-options
	@echo $(INFO_COLOR)"GEN   =>  jalisco" $(RESET_COLOR)

clean:
	@cargo clean
	@rm -rf lib
	@xargo clean
	@rm -rf target
	@rm -rf $(FINAL_DIR)/$(TZ_UUID).ta
	@rm -f $(OUT_DIR)/$(TZ_UUID).ta 
	@rm -f $(OUT_DIR)/stripped_ta
	@rm -f $(OUT_DIR)/jalisco
