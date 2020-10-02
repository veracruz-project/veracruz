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


STREAM_ROUND = 10
TARGET_PREFIX = number-stream
TARGET_DAT = $(addprefix $(TARGET_PREFIX), -init.dat -1.dat -2.dat)
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
	cargo run -- --file_prefix $(TARGET_PREFIX) --size $(STREAM_ROUND) --seed $(SEED); 

clean:
	cargo clean
	rm -f *.dat
	rm -f $(TARGET_DIR_DAT)

fmt:
	cargo fmt
