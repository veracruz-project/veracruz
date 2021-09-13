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
 
.PHONY: all doc clean fmt

all:
	rustup target add wasm32-wasi
	cargo build --target wasm32-wasi --release

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean
