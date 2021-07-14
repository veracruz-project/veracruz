# Makefile for the end-to-end demo
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSE_MIT.markdown` file in the Veracruz repository root
# directory for copyright and licensing information.

.PHONY: clean

.DEFAULT: all

all:
	cd oblivious-routing && cargo build --release --target wasm32-wasi
	cd ../sgx-root-enclave-bind && cargo build --release
	cd ../runtime-manager-bind && cargo build --release
	cargo build --release --features std
	./populate-test-database.sh
	

clean:
	$(CD) oblivious-routing && cargo clean
	cargo clean
