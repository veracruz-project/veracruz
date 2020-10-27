# Data generator sdk/examples/string-edit-distance
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.

BASENAME = data
SAMPLE_NUMBER = 5
RANGE = $(shell seq 2000 2000 10000) $(shell seq 20000 20000 100000) 5000 50000
RANGE_SUFFIX = $(foreach index,$(shell seq 0 1 $(shell expr $(SAMPLE_NUMBER) - 1)),$(addsuffix -$(index),$(RANGE)))
INDICE_SUFFIX = $(addprefix -,$(addsuffix .dat,$(RANGE_SUFFIX)))
TARGET_DATS = $(foreach base_name,$(BASENAME),$(addprefix $(base_name),$(INDICE_SUFFIX)))
TARGET_DIR = ../../datasets/private-set-inter-sum/
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR),$(TARGET_DATS))

.PHONY: all clean fmt

all: $(TARGET_DIR_DATS)

$(TARGET_DIR): 
	mkdir -p $(TARGET_DIR)

$(TARGET_DIR_DATS) : %.dat : $(TARGET_DIR)
	for number in $(RANGE) ; do \
    	cargo run -- --directory $(TARGET_DIR) --size $$number --num_of_sample $(SAMPLE_NUMBER) --seed 0 ; \
	done

clean:
	cargo clean
	rm -f *.dat
	rm -rf $(TARGET_DIR)

fmt:
	cargo fmt
