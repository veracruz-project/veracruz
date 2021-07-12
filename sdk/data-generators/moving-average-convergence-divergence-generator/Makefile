# Data generator sdk/examples/moving-average-convergence-divergence
# External data, apple_prices.csv
# can be found on https://github.com/woonhulktin/HETSA/tree/master/GeneralToolbox/FinancialApplications/macd-Plaintext/data
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.


SOURCE_FILES = apple_prices.csv
RANGE = $(shell seq 40 20 1000)
INDICE_SUFFIX = $(addprefix -,$(addsuffix .dat,$(RANGE)))
TARGET_DATS = $(foreach base_name,$(basename $(SOURCE_FILES)),$(addprefix $(base_name),$(INDICE_SUFFIX)) ) 
TARGET_DIR = ../../datasets/macd/
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR),$(TARGET_DATS))
GENERATED_DATA_FILE_PREFIX = generate
GENERATED_DATA_TARGET_DATS = $(addprefix $(GENERATED_DATA_FILE_PREFIX),$(INDICE_SUFFIX))
GENERATED_DATA_TARGET_DIR_DATS = $(addprefix $(TARGET_DIR),$(GENERATED_DATA_TARGET_DATS))
SEED = 0

.PHONY: all clean external fmt

all: $(GENERATED_DATA_TARGET_DIR_DATS)

.SECONDEXPANSION:
$(GENERATED_DATA_TARGET_DIR_DATS): %.dat : $$(notdir $$@) $(TARGET_DIR)
	cp $< $@ 

$(GENERATED_DATA_TARGET_DATS) : %.dat :
	for number in $(RANGE) ; do \
    	cargo run -- generate --file_prefix $(GENERATED_DATA_FILE_PREFIX) --size $$number --seed $(SEED); \
	done

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

external: $(TARGET_DIR_DATS)

.SECONDEXPANSION:
$(TARGET_DIR_DATS): %.dat : $$(notdir $$@) $(TARGET_DIR)
	cp $< $@ 

$(TARGET_DATS) : %.dat : $(SOURCE_FILES) 
	for number in $(RANGE) ; do \
    	cargo run -- external --input_file $< --size $$number ; \
	done

clean:
	cargo clean
	rm -f *.dat
	rm -rf $(TARGET_DIR)

fmt:
	cargo fmt
