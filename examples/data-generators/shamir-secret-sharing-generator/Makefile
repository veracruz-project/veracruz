# Data generator for Shamir's secret sharing
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

TARGET_DATS = share-1.dat share-2.dat share-3.dat

TARGET_DIR = ../../datasets/
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR),$(TARGET_DATS))
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean fmt fmt-check

all: $(TARGET_DIR_DATS)

.SECONDEXPANSION:
$(TARGET_DIR_DATS): %.dat : $$(notdir $$@) $(TARGET_DIR)
	cp $< $@ 

$(TARGET_DIR):
	mkdir $(TARGET_DIR)

$(TARGET_DATS):
	$(strip \
		$(RUN_COMMAND) "Hello World!" -n 3 \
		| split -l1 -a1 --numeric-suffixes=1 --additional-suffix=.dat - share- )

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
