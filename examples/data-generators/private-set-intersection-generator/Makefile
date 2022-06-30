# Data generator sdk/examples/private-set-intersection 
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

TARGET_DATS = private-set-1.dat private-set-2.dat

TARGET_DIR = ../../datasets/
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR),$(TARGET_DATS))
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean fmt fmt-check

all: $(TARGET_DIR_DATS)

.SECONDEXPANSION:
$(TARGET_DIR_DATS): %.dat : $$(notdir $$@) $(TARGET_DIR)
	cp $< $@ 

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

$(TARGET_DATS) : %.dat : %.csv
	$(RUN_COMMAND) --input_file $<

clean:
	cargo clean
	rm -f *.dat
	rm -f $(TARGET_DIR_DATS)

quick-clean:
	cargo clean
	rm -f *.dat
	rm -f $(TARGET_DIR_DATS)

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
