# Data generator for sdk/examples/idash2017-logistic-regression
# External data (SOURCE_FILES) can be found in
# https://github.com/kimandrik/IDASH2017/tree/master/IDASH2017/data
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

SOURCE_FILES = edin.txt idash.txt lbw.txt nhanes3.txt pcs.txt uis.txt
FOLD = 5
NUM_ITER = 7
SIGMOID = 5
GAMMA_UP = 1
GAMMA_DOWN = -1
INDICE_SUFFIX = $(addprefix -data-,$(addsuffix .dat,$(shell seq 0 $(shell expr $(FOLD) - 1))))
TARGET_DATS = $(foreach base_name,$(basename $(SOURCE_FILES)),$(addprefix $(base_name),$(INDICE_SUFFIX)) )
TARGET_DIR = ../../datasets/idash2017
TARGET_DIR_DATS = $(addprefix $(TARGET_DIR)/,$(TARGET_DATS))
GENERATED_DATA_FILE_PREFIX = generate
GENERATED_DATA_ROW ?= 200
GENERATED_DATA_COL ?= 20
GENERATED_DATA_TARGET_DATS = $(addprefix $(GENERATED_DATA_FILE_PREFIX),$(INDICE_SUFFIX))
GENERATED_DATA_TARGET_DIR_DATS = $(addprefix $(TARGET_DIR)/,$(GENERATED_DATA_TARGET_DATS))
SEED = 0
COMMON_CONFIG =  --fold=$(FOLD) --num_of_iter=$(NUM_ITER) --sigmoid=$(SIGMOID) --gamma_up=$(GAMMA_UP) --gamma_down=$(GAMMA_DOWN) --seed=$(SEED)
RUN_COMMAND ?= cargo run --

.PHONY: all clean quick-clean external fmt fmt-check

all: $(GENERATED_DATA_TARGET_DIR_DATS)

$(TARGET_DIR)/%.dat: %.dat | $(TARGET_DIR)
	cp $< $@

$(GENERATED_DATA_TARGET_DATS) &:
	$(RUN_COMMAND) $(COMMON_CONFIG) generate --file_prefix=$(GENERATED_DATA_FILE_PREFIX) \
				--row=$(GENERATED_DATA_ROW) --column=$(GENERATED_DATA_COL)

$(TARGET_DIR):
	mkdir -p $@

# Target for generating data from external resources,
# edin.txt idash.txt lbw.txt nhanes3.txt pcs.txt and uis.txt,
# which can be found in https://github.com/kimandrik/IDASH2017/tree/master/IDASH2017/data
external: $(TARGET_DIR_DATS)

$(TARGET_DATS) &: $(SOURCE_FILES)
	$(RUN_COMMAND) $(COMMON_CONFIG) external --input_file=edin.txt    --is_label_first=false
	$(RUN_COMMAND) $(COMMON_CONFIG) external --input_file=idash.txt   --is_label_first=true
	$(RUN_COMMAND) $(COMMON_CONFIG) external --input_file=lbw.txt     --is_label_first=false
	$(RUN_COMMAND) $(COMMON_CONFIG) external --input_file=nhanes3.txt --is_label_first=false
	$(RUN_COMMAND) $(COMMON_CONFIG) external --input_file=pcs.txt     --is_label_first=false
	$(RUN_COMMAND) $(COMMON_CONFIG) external --input_file=uis.txt     --is_label_first=false

clean:
	cargo clean
	rm -f *.dat
	rm -f *.csv
	rm -rf $(TARGET_DIR)

quick-clean: clean

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
