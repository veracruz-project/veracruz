shared:
	$(MAKE) -C applications
	$(MAKE) -C host

all: shared linux nitro

linux:
	$(MAKE) -C linux-host
	$(MAKE) -C linux-runtime

nitro:
	$(MAKE) -C nitro-host
	$(MAKE) -C nitro-runtime

clean:
	$(MAKE) -C applications clean
	$(MAKE) -C host clean

linux-clean:
	$(MAKE) -C linux-host clean
	$(MAKE) -C linux-runtime clean

nitro-clean:
	$(MAKE) -C nitro-host clean
	$(MAKE) -C nitro-runtime clean

icecap:
	$(MAKE) -C icecap-runtime runtime-manager
	$(MAKE) -C icecap-host test-system

icecap-clean:
	$(MAKE) -C icecap-host clean
	$(MAKE) -C icecap-runtime clean

clean-all: clean linux-clean nitro-clean
