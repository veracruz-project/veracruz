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

all: crates/sdk/wasm-checker/bin/wasm-checker
	cargo build --release

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

dataset-%:
	$(MAKE) -C crates/sdk/data-generators/$* RUN_COMMAND=$(abspath target/release/$*)

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
