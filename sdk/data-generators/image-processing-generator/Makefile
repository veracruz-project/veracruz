# Data generator sdk/examples/number-stream-accumulation
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.


WIDTH = 1024
HEIGHT = 1024
TARGET_PREFIX = image-processing
TARGET_DAT = $(addprefix $(TARGET_PREFIX), .dat)
TARGET_DIR = ../../datasets/
TARGET_DIR_DAT = $(addprefix $(TARGET_DIR),$(TARGET_DAT))

.PHONY: all clean fmt

all: $(TARGET_DIR_DAT)

.SECONDEXPANSION:
$(TARGET_DIR_DAT): %.dat : $$(notdir $$@) $(TARGET_DIR)
	cp $< $@ 

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

$(TARGET_DAT): 
	cargo run -- --file_prefix $(TARGET_PREFIX) --width $(WIDTH) --height $(HEIGHT) --seed $(SEED); 

clean:
	cargo clean
	rm -f *.dat
	rm -f $(TARGET_DIR_DAT)

fmt:
	cargo fmt
