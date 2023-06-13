# Data generator sdk/examples/number-stream-accumulation
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

STREAM_ROUND = 10
TARGET_PREFIX = number-stream
TARGET_DAT = $(TARGET_PREFIX)-init.dat $(TARGET_PREFIX)
TARGET_DIR = ../../datasets
TARGET_DIR_DAT = $(addprefix $(TARGET_DIR)/,$(TARGET_DAT))
SEED = 0
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean fmt fmt-check

all: $(TARGET_DIR_DAT)

$(TARGET_DIR)/%: % | $(TARGET_DIR)
	cp -r $< $@

$(TARGET_DIR):
	mkdir -p $@

$(TARGET_DAT):
	$(RUN_COMMAND) --file_prefix $(TARGET_PREFIX) --size $(STREAM_ROUND) --seed $(SEED);

clean:
	cargo clean
	rm -f *.dat
	rm -rf $(TARGET_DIR_DAT)

quick-clean: clean

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
