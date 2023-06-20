# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root director for licensing
# and copyright information.

.PHONY: all clean clean-cargo-lock doc fmt clippy linux linux-runtime-manager

default: all

WORKSPACE_DIR = $(abspath ..)

include $(WORKSPACE_DIR)/common.mk

unresolved_crates_path := $(shell pwd)/crates

all: linux

linux: linux-runtime-manager

linux-runtime-manager:
	RUSTFLAGS="--remap-path-prefix $(unresolved_crates_path)=$(shell readlink -f $(unresolved_crates_path))" \
	cargo build $(PROFILE_FLAG) $(V_FLAG)

doc:
	cargo doc

clippy:
	cargo clippy $(PROFILE_FLAG) $(V_FLAG) \
		-p linux-runtime-manager -p execution-engine \
		-p session-manager -p policy-utils -p platform-services
		-- --no-deps

fmt:
	cargo fmt

clean:
	@cargo clean

clean-cargo-lock:
	rm -f Cargo.lock
