# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

.PHONY: all doc clean fmt datasets clean-datasets

WORKSPACE_DIR = $(abspath ..)
include $(WORKSPACE_DIR)/common.mk

all: crates/sdk/wasm-checker/bin/wasm-checker
	cargo build $(PROFILE_FLAG)

DATA_GENERATORS = idash2017-logistic-regression-generator \
                      intersection-set-sum-generator \
                      moving-average-convergence-divergence-generator \
                      private-set-intersection-generator \
                      private-set-intersection-sum-generator \
                      string-generator \
                      linear-regression-generator \
                      number-stream-generator \
                      image-processing-generator \
                      shamir-secret-sharing

DATASETS = $(patsubst %, dataset-%, $(DATA_GENERATORS))

datasets: all $(DATASETS)

.PHONY:
dataset-%:
	$(MAKE) -C crates/sdk/data-generators/$* RUN_COMMAND=$(abspath target/$(PROFILE_PATH)/$*)

clean-datasets: $(patsubst %, clean-dataset-%, $(DATA_GENERATORS))

clean-dataset-%:
	$(MAKE) -C crates/sdk/data-generators/$* clean

crates/sdk/wasm-checker/bin/wasm-checker:
	$(MAKE) -C crates/sdk/wasm-checker

doc:
	cargo doc

fmt:
	cargo fmt

clean: clean-datasets
	cargo clean
	rm -f Cargo.lock
