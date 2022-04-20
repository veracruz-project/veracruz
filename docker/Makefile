VERSION = v22.05
IMAGE ?= veracruz
CONTAINER ?= veracruz
VERACRUZ_ROOT ?= ..
USER ?= $(shell id -un)
UID ?= $(shell id -u)
OS_NAME := $(shell uname -s | tr A-Z a-z)
AWS_NITRO_CLI_REVISION = v1.1.0
NE_GID := $(shell getent group ne | awk -F: '{printf $$3}')

ifeq ($(OS_NAME),darwin)
LOCALIP = $(shell "(ifconfig en0 ; ifconfig en1) | grep "inet " | grep -Fv 127.0.0.1 | awk '{print $2}'")
DOCKER_GROUP_ID=$(shell stat -f "%g" $(shell realpath /var/run/docker.sock))
else
LOCALIP = $(shell ip -4 address show eth0 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*')
DOCKER_GROUP_ID=$(shell stat --format "%g" $(shell realpath /var/run/docker.sock))
endif

BUILD_ARGS = --build-arg ARCH=$(shell uname -m) \
	--build-arg VERSION=$(VERSION)

DOCKER_RUN_PARAMS = \
		-v $(abspath $(VERACRUZ_ROOT)):/work/veracruz \
		--mount type=bind,src=$(abspath $(VERACRUZ_ROOT)),dst=/local

default:

#####################################################################
# Shared targets

.PHONY: base
base: base/Dockerfile
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARGS) -t $(IMAGE)/base:$(VERSION) -f $< .

.PHONY: %-build
%-build: Dockerfile %-base
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARGS) \
		--build-arg USER=$(USER) --build-arg UID=$(UID) --build-arg TEE=$* \
		--build-arg DOCKER_GROUP_ID=$(DOCKER_GROUP_ID) \
		-t $(IMAGE)/$*/$(USER):$(VERSION) -f $< .

.PHONY: all-base
all-base: base linux-base nitro-base icecap-base
	echo 'All base docker images re-built from scratch'

#####################################################################
# CI-related targets
#
.PHONY: ci-base ci-run ci-exec ci-image ci-image-tag \
	localci-run localci-exec localci-base

ci-base: ci/Dockerfile.base nitro-base
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARGS) -t $(IMAGE)/ci-base:$(VERSION) -f $< .

ci-run: ci-image
	# Make sure the cargo registry directory exists to avoid permission issues
	mkdir -p $(HOME)/.cargo/registry
	docker run --init --privileged --rm -d \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(abspath $(VERACRUZ_ROOT)):/work/veracruz \
		--name $(CONTAINER)-ci-$(USER)-$(VERSION) \
		$(IMAGE)/ci:$(VERSION) sleep inf

ci-exec:
	docker exec -u root -i -t $(CONTAINER)-ci-$(USER)-$(VERSION) /bin/bash || true

ci-image: ci/Dockerfile.cache ci-base
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARGS) -t $(IMAGE)/ci:$(VERSION) -f $< .

ci-image-tag:
	docker tag $(IMAGE)/ci:$(VERSION) ghcr.io/veracruz-project/veracruz/ci:$(VERSION)

# "localci" is similar to "ci" but does not run as root to avoid problems
# with file permissions.
localci-run: localci-build
	# Make sure the cargo registry directory exists to avoid permission issues
	mkdir -p $(HOME)/.cargo/registry
	docker run --init --privileged --rm -d $(DOCKER_RUN_PARAMS) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		--name $(CONTAINER)-localci-$(USER)-$(VERSION) \
		$(IMAGE)/localci/$(USER):$(VERSION) sleep inf

localci-exec:
	docker exec -i -t $(CONTAINER)-localci-$(USER)-$(VERSION) /bin/bash || true

localci-base: ci/Dockerfile.local ci-base
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARGS) -t $(IMAGE)/localci:$(VERSION) -f $< .

.PHONY: all-ci
all-ci: ci-image localci-base
	echo 'All CI docker images re-built from scratch'

#####################################################################
# IceCap-related targets

.PHONY:
icecap-run: icecap-build
	# Make sure the cargo registry directory exists to avoid permission issues
	mkdir -p $(HOME)/.cargo/registry
	docker run --init --privileged --rm -d $(DOCKER_RUN_PARAMS) \
		--name $(CONTAINER)-icecap-$(USER)-$(VERSION) \
		$(IMAGE)/icecap/$(USER):$(VERSION) sleep inf

.PHONY:
icecap-exec:
	docker exec -i -t $(CONTAINER)-icecap-$(USER)-$(VERSION) /bin/bash || true

.PHONY: icecap-base
icecap-base: icecap/Dockerfile base
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARGS) -t $(IMAGE)/icecap:$(VERSION) -f $< .

#####################################################################
# Linux-related targets

.PHONY:
linux-run: linux-build
	# Make sure the cargo registry directory exists to avoid permission issues
	mkdir -p $(HOME)/.cargo/registry
	docker run --init --privileged --rm -d $(DOCKER_RUN_PARAMS) \
		--name $(CONTAINER)-linux-$(USER)-$(VERSION) \
		$(IMAGE)_linux:$(USER) sleep inf

.PHONY:
linux-exec:
	docker exec -i -t $(CONTAINER)-linux-$(USER)-$(VERSION) /bin/bash || true

.PHONY:
linux-base: linux/Dockerfile base
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARGS) -t $(IMAGE)/linux:$(VERSION) -f $< .

#####################################################################
# Nitro-related targets

.PHONY: nitro-run nitro-run-build nitro-exec nitro-base

# "nitro-run" should be run on a AWS Nitro Enclave instance, "nitro-run-build"
# allows to build Veracruz with Nitro support on other machines.
nitro-run: nitro-build
	# Make sure the cargo registry directory exists to avoid permission issues
	mkdir -p $(HOME)/.cargo/registry
	# This container must be started on a "Nitro Enclave"-capable AWS instance
	docker run --init --privileged --rm -d $(DOCKER_RUN_PARAMS) \
		-v /usr/bin:/host/bin \
		-v /usr/share/nitro_enclaves:/usr/share/nitro_enclaves \
		-v /run/nitro_enclaves:/run/nitro_enclaves \
		-v /etc/nitro_enclaves:/etc/nitro_enclaves \
		--device=/dev/vsock:/dev/vsock \
		--device=/dev/nitro_enclaves:/dev/nitro_enclaves \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-p $(LOCALIP):3010:3010/tcp \
		--name $(CONTAINER)-nitro-$(USER)-$(VERSION) \
		$(IMAGE)/nitro/$(USER):$(VERSION) sleep inf

nitro-run-build: nitro-build
	# Make sure the cargo registry directory exists to avoid permission issues
	mkdir -p $(HOME)/.cargo/registry
	# This container does not need to be run in AWS, it can build but not start enclaves
	docker run --init --privileged --rm -d $(DOCKER_RUN_PARAMS) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-p $(LOCALIP):3010:3010/tcp \
		--name $(CONTAINER)-nitro-$(USER)-$(VERSION) \
		$(IMAGE)/nitro/$(USER):$(VERSION) sleep inf

nitro-exec:
	docker exec -i -t $(CONTAINER)-nitro-$(USER)-$(VERSION) /bin/bash || true

nitro-base: nitro/Dockerfile base
ifeq (,$(wildcard aws-nitro-enclaves-cli))
	git clone https://github.com/aws/aws-nitro-enclaves-cli.git
endif
	cd "aws-nitro-enclaves-cli" && git checkout $(AWS_NITRO_CLI_REVISION) || \
		(git fetch ; git checkout $(AWS_NITRO_CLI_REVISION))
	perl -i -pe 's/readlink -f/realpath/' aws-nitro-enclaves-cli/Makefile # Work-around to build on Mac
	make -C aws-nitro-enclaves-cli nitro-cli
	DOCKER_BUILDKIT=1 docker build $(BUILD_ARGS) \
		--build-arg NE_GID=$(NE_GID) -t $(IMAGE)/nitro:$(VERSION) -f $< .
