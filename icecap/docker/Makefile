# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

nix_root := hacking/nix-root
veracruz_root := ../..
icecap_root := ../../../icecap

label := veracruz-icecap
local_repository := veracruz-icecap
container_name_base := veracruz-icecap

stateful_hacking_dockerfile := hacking/Dockerfile.stateful
stateful_hacking_image_tag := $(local_repository):hacking
stateful_hacking_container_name := $(container_name_base)-hacking

stateless_hacking_dockerfile := hacking/Dockerfile.stateless
stateless_hacking_image_tag := $(local_repository):hacking-stateless
stateless_hacking_container_name := $(container_name_base)-hacking-stateless

uid := $(shell id -u)
gid := $(shell id -g)

.PHONY: all
all:

### stateful ###

.PHONY: build
build:
	docker build -f $(stateful_hacking_dockerfile) \
		--build-arg UID=$(uid) --build-arg GID=$(gid) \
		--label $(label) -t $(stateful_hacking_image_tag) .

.PHONY: run
run: build
	docker run --privileged -d --name $(stateful_hacking_container_name) --label $(label) \
		--mount type=bind,src=$(abspath $(veracruz_root)),dst=/work/veracruz \
		$(stateful_hacking_image_tag) sleep inf

.PHONY: exec
exec:
	docker exec -it $(stateful_hacking_container_name) bash

.PHONY: rm-container
rm-container:
	for id in $$(docker ps -aq -f "name=$(stateful_hacking_container_name)"); do \
		docker rm -f $$id; \
	done

### stateless ###

.PHONY: build-stateless
build-stateless:
	docker build -f $(stateless_hacking_dockerfile) \
		--build-arg UID=$(uid) --build-arg GID=$(gid) \
		--label $(label) -t $(stateless_hacking_image_tag) .

$(nix_root):
	mkdir -p -m 0755 $@

$(nix_root)/.installed: build-stateless $(nix_root)
	docker run --privileged --rm --label $(label) -w /home/x \
		--mount type=bind,src=$(abspath $(nix_root)),dst=/nix \
		$(stateless_hacking_image_tag) flock /nix/.installed.lock bash /setup.sh

.PHONY: run-stateless
run-stateless: build-stateless $(nix_root)/.installed
	docker run --privileged -d --name $(stateless_hacking_container_name) --label $(label) \
		--mount type=bind,src=$(abspath $(nix_root)),dst=/nix \
		--mount type=bind,src=$(abspath $(veracruz_root)),dst=/work/veracruz \
		$(stateless_hacking_image_tag) sleep inf

.PHONY: exec-stateless
exec-stateless:
	docker exec -it $(stateless_hacking_container_name) bash

.PHONY: rm-stateless-container
rm-stateless-container:
	for id in $$(docker ps -aq -f "name=$(stateless_hacking_container_name)"); do \
		docker rm -f $$id; \
	done

.PHONY: rm-nix-root
rm-nix-root:
	if [ -d $(nix_root) ]; then \
		chmod -R u+w $(nix_root); \
		rm -rf $(nix_root); \
	fi

### CI ###

icecap_rev := $(shell GIT_DIR=../icecap/.git git rev-parse HEAD)
icecap_rev_short := $(shell GIT_DIR=../icecap/.git git rev-parse --short=10 HEAD)

ci_image_tag_name := ci-$(icecap_rev_short)
ci_image_tag := $(local_repository):$(ci_image_tag_name)
ci_container_name := $(container_name_base)-ci

# TODO investigate the benefits of the use of --squash
.PHONY: ci-build
ci-build:
	docker build -f ci/Dockerfile \
		--build-arg ICECAP_REV=$(icecap_rev) \
		--label $(label) -t $(ci_image_tag)  .

.PHONY: ci-run
ci-run:
	docker run -d --name $(ci_container_name) --label $(label) \
		--mount type=bind,src=$(abspath $(veracruz_root)),dst=/work/veracruz \
		$(ci_image_tag) sleep inf

.PHONY: ci-exec
ci-exec:
	docker exec -it $(ci_container_name) bash

.PHONY: ci-test-populate
ci-test-populate:
	ICECAP_REV=$(icecap_rev) bash ci/populate/run.sh

.PHONY: ci-rm-container
ci-rm-container:
	for id in $$(docker ps -aq -f "name=$(ci_container_name)"); do \
		docker rm -f $$id; \
	done

### CI + remote registry ###

remote_repository := ghcr.io/veracruz-project/veracruz/veracruz-icecap
remote_ci_image_tag := $(remote_repository):$(ci_image_tag_name)

# NOTE use caution
.PHONY: ci-push
ci-push:
	docker tag $(ci_image_tag) $(remote_ci_image_tag)
	docker push $(remote_ci_image_tag)
