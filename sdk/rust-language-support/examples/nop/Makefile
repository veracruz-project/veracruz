# Example Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

PLATFORM = $(shell uname)
RUSTUP_HOME ?= ~/.rustup

ifeq ($(PLATFORM), Darwin)
	RUST_STDLIB_SRC_DIR ?= ~/.rustup/toolchains/nightly-2020-05-07-x86_64-apple-darwin/lib/rustlib/src/rust/src
endif

ifeq ($(PLATFORM), Linux)
	RUST_STDLIB_SRC_DIR ?= $(RUSTUP_HOME)/toolchains/nightly-2020-05-07-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/src
endif

VERACRUZ_TARGET_PATH = $(shell cd ../../../ && pwd)

.PHONY: all doc clean fmt

all:
	XARGO_RUST_SRC=$(RUST_STDLIB_SRC_DIR) RUST_TARGET_PATH=$(VERACRUZ_TARGET_PATH) xargo build --target wasm32-arm-veracruz --release

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
	xargo clean
	rm -f Cargo.lock

