# Data generator for sdk/examples/linear-regression
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the file `LICENSE.md` in the Veracruz root directory for licensing
# and copyright information.

ROW = 10000
TARGET_DAT = linear-regression.dat
TARGET_DIR = ../../datasets
TARGET_DIR_DAT = $(addprefix $(TARGET_DIR)/,$(TARGET_DAT))
SEED = 0
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean fmt fmt-check

all: $(TARGET_DIR_DAT)

$(TARGET_DIR)/%.dat: %.dat | $(TARGET_DIR)
	cp $< $@

$(TARGET_DIR):
	mkdir -p $@

$(TARGET_DAT):
	$(RUN_COMMAND) --file_name $(basename $@) --size $(ROW) --seed $(SEED)

clean:
	cargo clean
	rm -f *.dat
	rm -f *.txt
	rm -f $(TARGET_DIR_DAT)

quick-clean: clean

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
