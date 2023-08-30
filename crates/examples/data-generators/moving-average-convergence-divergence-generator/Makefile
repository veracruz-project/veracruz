# Data generator sdk/examples/moving-average-convergence-divergence
# External data, apple_prices.csv, can be found at
# https://raw.githubusercontent.com/ht-weng/HETSA/master/FinancialApplications/data/apple_prices.csv
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.md` file in the Veracruz root directory for licensing
# and copyright information.

SOURCE_FILES = apple_prices.csv
# The range of data
RANGE ?= $(shell seq 1000 20 1000)
INDICE_SUFFIX = $(addprefix -,$(addsuffix .dat,$(RANGE)))
TARGET_DATS = $(foreach base_name,$(basename $(SOURCE_FILES)),$(addprefix $(base_name),$(INDICE_SUFFIX)) )
TARGET_DIR = ../../datasets/macd
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR)/,$(TARGET_DATS))
GENERATED_DATA_FILE_PREFIX = generate
GENERATED_DATA_TARGET_DATS = $(addprefix $(GENERATED_DATA_FILE_PREFIX),$(INDICE_SUFFIX))
GENERATED_DATA_TARGET_DIR_DATS = $(addprefix $(TARGET_DIR)/,$(GENERATED_DATA_TARGET_DATS))
SEED = 0
RUN_COMMAND ?= cargo run --

.PHONY: all clean external quick-clean fmt fmt-check

all: $(GENERATED_DATA_TARGET_DIR_DATS)

$(TARGET_DIR)/%.dat: %.dat | $(TARGET_DIR)
	cp $< $@

$(GENERATED_DATA_TARGET_DATS) &:
	for number in $(RANGE) ; do \
		$(RUN_COMMAND) generate --file_prefix $(GENERATED_DATA_FILE_PREFIX) --size $$number --seed $(SEED); \
	done

$(TARGET_DIR):
	mkdir -p $@

external: $(TARGET_DIR_DATS)

$(TARGET_DATS) &: $(SOURCE_FILES)
	for number in $(RANGE) ; do \
		$(RUN_COMMAND) external --input_file $< --size $$number ; \
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
