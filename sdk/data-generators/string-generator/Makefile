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

TARGET_DIR = ../../datasets/
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR),$(TARGET_DATS))

.PHONY: all clean quick-clean fmt

all: $(TARGET_DIR_DATS)

.SECONDEXPANSION:
$(TARGET_DIR_DATS): %.dat : $$(notdir $$@) $(TARGET_DIR)
	cp $< $@ 

$(TARGET_DIR):
	mkdir $(TARGET_DIR)

$(TARGET_DATS) : %.dat : %.txt
	cargo run -- --input_file $<

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
