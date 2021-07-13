# Data generator for sdk/examples/linear-regression
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
# and copyright information.

ROW = 10000
TARGET_DAT = linear-regression.dat
TARGET_DIR = ../../datasets/
TARGET_DIR_DAT = $(addprefix $(TARGET_DIR),$(TARGET_DAT))
SEED = 0

.PHONY: all clean fmt

all: $(TARGET_DIR_DAT)

.SECONDEXPANSION:
$(TARGET_DIR_DAT): %.dat : $$(notdir $$@) $(TARGET_DIR)
	cp $< $@ 

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

$(TARGET_DAT):
	cargo run -- --file_name $(basename $@) --size $(ROW) --seed $(SEED)

clean:
	cargo clean
	rm -f *.dat
	rm -f *.txt
	rm -f $(TARGET_DIR_DAT)

fmt:
	cargo fmt
