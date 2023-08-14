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

VEC_SIZE = 10
TARGET_DAT = postcard.dat
TARGET_DIR = ../../datasets
TARGET_DIR_DAT = $(addprefix $(TARGET_DIR)/,$(TARGET_DAT))
SEED = 0
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean fmt fmt-check

all: $(TARGET_DIR_DAT)

$(TARGET_DIR)/%.dat: %.dat | $(TARGET_DIR)
	cp -r $< $@

$(TARGET_DIR):
	mkdir -p $@

$(TARGET_DAT):
	$(RUN_COMMAND) --file $(TARGET_DAT) --size $(VEC_SIZE) --seed $(SEED);

clean:
	cargo clean
	rm -f *.dat
	rm -rf $(TARGET_DIR_DAT)

quick-clean: clean

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
