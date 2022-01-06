OUT_DIR ?= $(abspath test-collateral)
WORKSPACE_DIR = $(abspath ..)
MEASUREMENT_FILE = $(abspath css-icecap.bin)
MEASUREMENT_PARAMETER = --css-file $(MEASUREMENT_FILE)

include $(WORKSPACE_DIR)/common.mk
include $(WORKSPACE_DIR)/shared.mk

.PHONY: clean

$(MEASUREMENT_FILE):
	touch $@

clean:
	rm -rf $(OUT_DIR)
	rm -f css-icecap.bin
