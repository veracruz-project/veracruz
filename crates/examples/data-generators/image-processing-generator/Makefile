# Data generator sdk/examples/number-stream-accumulation
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.md` file in the Veracruz root directory for licensing
# and copyright information.

IMAGE_PATH = "./veracruz.jpg"
WIDTH = 1024
HEIGHT = 1024
TARGET_PREFIX = image-processing
TARGET_DAT = $(addprefix $(TARGET_PREFIX), .png)
TARGET_DIR = ../../datasets
TARGET_DIR_DAT = $(addprefix $(TARGET_DIR)/,$(TARGET_DAT))
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean fmt fmt-check

all: $(TARGET_DIR_DAT)

$(TARGET_DIR)/%.png: %.png | $(TARGET_DIR)
	cp $< $@

$(TARGET_DIR):
	mkdir -p $@

$(TARGET_DAT):
	$(RUN_COMMAND) --file_prefix $(TARGET_PREFIX) --image_path $(IMAGE_PATH) --width $(WIDTH) --height $(HEIGHT);

clean:
	cargo clean
	rm -f *.png
	rm -f $(TARGET_DIR_DAT)

quick-clean: clean

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
