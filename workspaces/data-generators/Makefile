# Applications Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

.PHONY: all clean clean-cargo-lock doc fmt

WORKSPACE_DIR = $(abspath ..)
include $(WORKSPACE_DIR)/common.mk

DATA_GENERATORS = idash2017-logistic-regression-generator \
                      intersection-set-sum-generator \
                      moving-average-convergence-divergence-generator \
                      postcard-generator \
                      private-set-intersection-generator \
                      private-set-intersection-sum-generator \
                      string-generator \
                      linear-regression-generator \
                      number-stream-generator \
                      image-processing-generator \
                      shamir-secret-sharing-generator

DATASETS = $(patsubst %, dataset-%, $(DATA_GENERATORS))

all: cargo-build $(DATASETS)

cargo-build:
	cargo build $(PROFILE_FLAG) $(V_FLAG)

.PHONY:
dataset-%:
	$(MAKE) -C crates/examples/data-generators/$* RUN_COMMAND=$(abspath target/$(PROFILE_PATH)/$*)

.PHONY:
clean-datasets: $(patsubst %, clean-dataset-%, $(DATA_GENERATORS))

clean-dataset-%:
	$(MAKE) -C crates/examples/data-generators/$* clean

doc:
	cargo doc

fmt:
	cargo fmt

clean: clean-datasets 
	cargo clean

clean-cargo-lock:
	rm -f Cargo.lock
