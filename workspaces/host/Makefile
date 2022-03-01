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

.PHONY: all install clean clean-cargo-lock clean-datasets datasets doc fmt

WORKSPACE_DIR = $(abspath ..)
BIN_DIR ?= /usr/local/cargo/bin
include $(WORKSPACE_DIR)/common.mk


all: crates/sdk/wasm-checker/bin/wasm-checker
	cargo build $(PROFILE_FLAG) $(V_FLAG)

install: all
	# create full names
	cp -f target/$(PROFILE_PATH)/freestanding-execution-engine $(BIN_DIR)
	cp -f target/$(PROFILE_PATH)/generate-policy $(BIN_DIR)
	cp -f crates/sdk/wasm-checker/bin/wasm-checker $(BIN_DIR)
	# create short names
	ln -sf $(BIN_DIR)/freestanding-execution-engine $(BIN_DIR)/vc-fee
	ln -sf $(BIN_DIR)/generate-policy $(BIN_DIR)/vc-pgen
	ln -sf $(BIN_DIR)/wasm-checker $(BIN_DIR)/vc-wc

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

clean-cargo-lock:
	rm -f Cargo.lock
