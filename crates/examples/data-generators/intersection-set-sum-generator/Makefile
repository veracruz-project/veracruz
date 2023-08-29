# Data generator sdk/examples/intersection-set-sum
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

FILE_PREFIX = intersection
SIZE = 100
DIFF = 25
TARGET_DATS = $(addprefix $(FILE_PREFIX)-,advertisement-viewer.dat customer.dat)
SEED = 0
TARGET_DIR = ../../datasets
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR)/,$(TARGET_DATS))
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean fmt fmt-check

all: $(TARGET_DIR_DATS)

$(TARGET_DIR)/%.dat: %.dat | $(TARGET_DIR)
	cp $< $@

$(TARGET_DIR):
	mkdir -p $@

$(TARGET_DATS) &: $(SOURCE_FILES)
	$(RUN_COMMAND) --file_prefix $(FILE_PREFIX) --size $(SIZE) --num_of_diff $(DIFF) --seed $(SEED)

clean:
	cargo clean
	rm -f *.dat
	rm -f $(TARGET_DIR_DATS)

quick-clean: clean

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
