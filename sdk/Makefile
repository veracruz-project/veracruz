# Top-level build-all Makefile for the SDK
#
# Builds:
#   - freestanding-chihuahua
#   - Rust libveracruz
#   - Rust veracruz-rt
#   - Rust getrandom and rand libraries in lib/
#   - all of the Rust examples in the examples/ directory
#   - all of the datasets in data-generators/ directory
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.

# All Rust example programs
RUST_EXAMPLES = idash2017-logistic-regression \
	   	   linear-regression \
		   moving-average-convergence-divergence \
		   private-set-intersection \
		   random-source \
		   intersection-set-sum \
		   logistic-regression \
		   nop \
		   private-set-intersection-sum \
		   string-edit-distance
RUST_EXAMPLE_DIR = rust-language-support/examples/
# The actual example WASM programs
RELATIVE_RUST_EXAMPLES = $(foreach EXAMPLE,$(RUST_EXAMPLES),$(addsuffix /target/wasm32-arm-veracruz/release/$(EXAMPLE).wasm,$(addprefix $(RUST_EXAMPLE_DIR), $(EXAMPLE))))
# All dataset filenames
DATA = hello-world-1.dat \
 	   hello-world-2.dat \
	   intersection-advertisement-viewer.dat \
	   intersection-customer.dat \
	   linear-regression.dat \
	   private-set-1.dat \
	   private-set-2.dat \
	   idash2017/ \
	   macd/ \
	   private-set-inter-sum/
DATASET_PATH = datasets/
RELATIVE_DATA = $(addprefix $(DATASET_PATH), $(DATA))
# All data generators for `fmt` and `clean` targets.
DATA_GENERATORS = idash2017-logistic-regression-generator \
	              intersection-set-sum-generator \
	              moving-average-convergence-divergence-generator \
	              private-set-intersection-generator \
	              private-set-intersection-sum-generator \
	              string-generator \
	              linear-regression-generator
DATA_GENERATORS_PATH = data-generators
RELATIVE_DATA_GEN = $(addprefix $(DATA_GENERATORS_PATH)/, $(DATA_GENERATORS))

.PHONY: all clean fmt freestanding-chihuahua rust-libveracruz rust-veracruz-rt tlaxcala env

all: tlaxcala $(RELATIVE_DATA) $(RELATIVE_RUST_EXAMPLES) freestanding-chihuahua rust-libveracruz rust-veracruz-rt rust-getrandom rust-rand

tlaxcala:
	$(MAKE) -C tlaxcala

.SECONDEXPANSION:
$(RELATIVE_RUST_EXAMPLES): %.wasm : $$(addsuffix /src/main.rs,$$(addprefix $(RUST_EXAMPLE_DIR),$$(basename $$(notdir $$@)))) env tlaxcala
	$(MAKE) -C $(addprefix $(RUST_EXAMPLE_DIR),$(basename $(notdir $@)))
	./tlaxcala/bin/tlaxcala -c ./tlaxcala/tlaxcala_config.json $@

freestanding-chihuahua: env
	$(MAKE) -C freestanding-chihuahua/

rust-libveracruz: env
	$(MAKE) -C rust-language-support/libveracruz/
 
rust-veracruz-rt: env
	$(MAKE) -C rust-language-support/veracruz-rt/

rust-getrandom: env
	$(MAKE) -C rust-language-support/lib/getrandom/

rust-rand: env
	$(MAKE) -C rust-language-support/lib/rand/

# Specify the dependency for all datasets
$(addprefix $(DATASET_PATH),hello-world-1.dat hello-world-2.dat): %.dat : $$(addprefix $(DATA_GENERATORS_PATH)/string-generator/,Makefile src/main.rs $$(notdir %.txt))
$(addprefix $(DATASET_PATH),intersection-advertisement-viewer.dat intersection-advertisement-customer.dat): %.dat : $$(addprefix $(DATA_GENERATORS_PATH)/intersection-set-sum-generator/,Makefile src/main.rs)
$(DATASET_PATH)linear-regression.dat: $$(addprefix $(DATA_GENERATORS_PATH)/linear-regression-generator/,Makefile src/main.rs)
$(addprefix $(DATASET_PATH),private-set-1.dat private-set-2.dat): %.dat : $$(addprefix $(DATA_GENERATORS_PATH)/private-set-intersection-generator/,Makefile src/main.rs $$(notdir %.csv))
$(DATASET_PATH)idash2017/: $$(addprefix $(DATA_GENERATORS_PATH)/idash2017-logistic-regression-generator/,Makefile src/main.rs)
$(DATASET_PATH)macd/: $$(addprefix $(DATA_GENERATORS_PATH)/moving-average-convergence-divergence-generator/,Makefile src/main.rs)
$(DATASET_PATH)private-set-inter-sum/: $$(addprefix $(DATA_GENERATORS_PATH)/private-set-intersection-sum-generator/,Makefile src/main.rs)

# Call makefiles to generate datasets
$(RELATIVE_DATA):
	$(MAKE) -C $(dir $<)

env:
	rustup component add rust-src rust-std

fmt:
	for data in $(RELATIVE_DATA_GEN); do \
		$(MAKE) -C $$data fmt; \
	done
	for example in $(addprefix $(RUST_EXAMPLE_DIR),$(basename $(notdir $(RELATIVE_RUST_EXAMPLES)))); do \
        	$(MAKE) -C $$example fmt; \
    	done
	$(MAKE) -C freestanding-chihuahua/ fmt
	$(MAKE) -C rust-language-support/libveracruz/ fmt
	$(MAKE) -C rust-language-support/veracruz-rt/ fmt

clean:
	for data in $(RELATIVE_DATA_GEN); do \
		$(MAKE) -C $$data clean; \
	done
	rm -rf datasets
	for example in $(addprefix $(RUST_EXAMPLE_DIR),$(basename $(notdir $(RELATIVE_RUST_EXAMPLES)))); do \
		$(MAKE) -C $$example clean; \
	done
	$(MAKE) -C freestanding-chihuahua/ clean
	$(MAKE) -C rust-language-support/libveracruz/ clean
	$(MAKE) -C rust-language-support/veracruz-rt/ clean
	$(MAKE) -C rust-language-support/lib/getrandom/ clean
	$(MAKE) -C rust-language-support/lib/rand/ clean
	$(MAKE) -C tlaxcala/ clean
