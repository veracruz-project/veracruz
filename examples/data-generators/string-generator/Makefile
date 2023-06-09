# Data generator for string-edit-distance
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

TARGET_DATS = hello-world-1.dat hello-world-2.dat

TARGET_DIR = ../../datasets
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR)/,$(TARGET_DATS))
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean fmt fmt-check

all: $(TARGET_DIR_DATS)

$(TARGET_DIR)/%.dat: %.dat | $(TARGET_DIR)
	cp $< $@

$(TARGET_DIR):
	mkdir -p $@

%.dat: %.txt
	$(RUN_COMMAND) --input_file $<

clean:
	cargo clean
	rm -f *.dat
	rm -f $(TARGET_DIR_DATS)

quick-clean: clean

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
