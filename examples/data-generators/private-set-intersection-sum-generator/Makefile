# Data generator sdk/examples/string-edit-distance
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

BASENAME = data
SAMPLE_NUMBER = 5
# The comment is the full run
#RANGE = $(shell seq 2000 2000 10000) $(shell seq 20000 20000 100000) 5000 50000
RANGE ?= $(shell seq 2000 2000 2000)
RANGE_SUFFIX = $(foreach index,$(shell seq 0 1 $(shell expr $(SAMPLE_NUMBER) - 1)),$(addsuffix -$(index),$(RANGE)))
INDICE_SUFFIX = $(addprefix -,$(RANGE_SUFFIX))
TARGET_DATS = $(foreach base_name,$(BASENAME),$(addprefix $(base_name),$(INDICE_SUFFIX)))
TARGET_DIR = ../../datasets/private-set-inter-sum
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR)/,$(TARGET_DATS))
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean fmt fmt-check

all: $(TARGET_DIR_DATS)

$(TARGET_DIR):
	mkdir -p $@

$(TARGET_DIR_DATS) &: | $(TARGET_DIR)
	echo $@
	for number in $(RANGE) ; do \
		$(RUN_COMMAND) --directory $(TARGET_DIR) --size $$number --num_of_sample $(SAMPLE_NUMBER) --seed 0 ; \
	done

clean:
	cargo clean
	rm -f *.dat
	rm -rf $(TARGET_DIR)

quick-clean: clean

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
