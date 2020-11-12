# Makefile for the Veracruz runtime library
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSE.markdown` file in the Veracruz root directory for
# licensing and copyright information.

PLATFORM = $(shell uname)

ifeq ($(PLATFORM), Darwin)
	RUST_STDLIB_SRC_DIR ?= ~/.rustup/toolchains/nightly-2020-05-07-x86_64-apple-darwin/lib/rustlib/src/rust/src
endif

ifeq ($(PLATFORM), Linux)
	RUST_STDLIB_SRC_DIR ?= ~/.rustup/toolchains/nightly-2020-05-07-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/src
endif

.PHONY: all clean doc fmt

VERACRUZ_TARGET_PATH = $(shell cd ../ && pwd)

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

