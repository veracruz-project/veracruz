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


# "Puerto de Veracruz" by Eduardo Pavon is licensed under CC BY-SA 2.0
IMAGE_PATH = "./veracruz.jpg"

WIDTH = 1024
HEIGHT = 1024
TARGET_PREFIX = image-processing
TARGET_DAT = $(addprefix $(TARGET_PREFIX), .png)
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
	cargo run -- --file_prefix $(TARGET_PREFIX) --image_path $(IMAGE_PATH) --width $(WIDTH) --height $(HEIGHT); 

clean:
	cargo clean
	rm -f *.png
	rm -f $(TARGET_DIR_DAT)

fmt:
	cargo fmt
