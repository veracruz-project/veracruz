default:

include common.mk

all: shared linux nitro

shared:
	$(MAKE) -C applications
	$(MAKE) -C host

linux: shared
	$(MAKE) -C linux-host
	$(MAKE) -C linux-runtime

nitro: shared
	$(MAKE) -C nitro-host
	$(MAKE) -C nitro-runtime

icecap: # shared
	# shared is disabled because icecap uses its own
	# environment to build applications and host
	$(MAKE) -C icecap-runtime runtime-manager
	$(MAKE) -C icecap-host test-system

shared-clean:
	$(MAKE) -C applications clean
	$(MAKE) -C host clean

linux-clean:
	$(MAKE) -C linux-host clean
	$(MAKE) -C linux-runtime clean

nitro-clean:
	$(MAKE) -C nitro-host clean
	$(MAKE) -C nitro-runtime clean

icecap-clean:
	$(MAKE) -C icecap-host clean
	$(MAKE) -C icecap-runtime clean

clean: shared-clean linux-clean nitro-clean
