# Top-level Makefile for workspaces
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

default:

include common.mk

.PHONY: all clean icecap icecap-clippy icecap-clean linux linux-install linux-clippy \
	linux-clean nitro nitro-clippy nitro-clean shared shared-install shared-clean

all: shared linux nitro icecap

clean: shared-clean linux-clean nitro-clean icecap-clean

linux: shared
	$(MAKE) -C linux-runtime
	$(MAKE) -C linux-host

linux-tests:
	$(MAKE) -C linux-host tests

nitro: shared
	$(MAKE) -C nitro-host
	$(MAKE) -C nitro-runtime

icecap-cca: shared
	$(MAKE) -C icecap-host build-cca

icecap: shared
	$(MAKE) -C icecap-runtime build
	$(MAKE) -C icecap-host

icecap-tests:
	$(MAKE) -C icecap-host tests

shared:
	$(MAKE) -C applications
	$(MAKE) -C host
	$(MAKE) -C data-generators

linux-install: shared-install
	$(MAKE) -C linux-host install

shared-install:
	$(MAKE) -C host install

linux-clippy:
	make -C linux-runtime clippy
	make -C linux-host clippy

nitro-clippy:
	make -C nitro-runtime clippy
	make -C nitro-host clippy

icecap-clippy:
	make -C icecap-host clippy

linux-clean:
	$(MAKE) -C linux-host clean
	$(MAKE) -C linux-runtime clean

nitro-clean:
	$(MAKE) -C nitro-host clean
	$(MAKE) -C nitro-runtime clean

icecap-clean:
	$(MAKE) -C icecap-host clean
	$(MAKE) -C icecap-runtime clean

shared-clean:
	$(MAKE) -C applications clean
	$(MAKE) -C host clean
	$(MAKE) -C data-generators clean
	rm -f host/crates/test-collateral/*.pem

clean-cargo-lock:
	rm -f */Cargo.lock
