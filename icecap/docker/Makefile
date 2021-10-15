# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

ICECAP_LOCAL ?= 0

nix_root := hacking/nix-root
veracruz_root := ../..
icecap_root := ../../../icecap

ifeq ($(ICECAP_LOCAL), 1)
       icecap_mount := --mount type=bind,src=$(abspath $(icecap_root)),dst=/work/icecap
endif

label := veracruz-icecap
local_repository := veracruz-icecap
container_name_base := veracruz-icecap

hacking_image_tag := $(local_repository):hacking
hacking_container_name := $(container_name_base)-hacking

uid := $(shell id -u)
gid := $(shell id -g)

.PHONY: all
all: run

.PHONY: build
build:
	docker build -f hacking/Dockerfile \
		--build-arg UID=$(uid) --build-arg GID=$(gid) \
		--label $(label) -t $(hacking_image_tag) .

$(nix_root):
	mkdir -p -m 0755 $@

$(nix_root)/.installed: build $(nix_root)
	docker run --privileged --rm --label $(label) -w /home/x \
		--mount type=bind,src=$(abspath $(nix_root)),dst=/nix \
		$(hacking_image_tag) flock /nix/.installed.lock bash /setup.sh

.PHONY: run
run: build $(nix_root)/.installed
	docker run --privileged -d --name $(hacking_container_name) --label $(label) \
		--mount type=bind,src=$(abspath $(nix_root)),dst=/nix \
		--mount type=bind,src=$(abspath $(veracruz_root)),dst=/work/veracruz \
		$(icecap_mount) \
		$(hacking_image_tag) sleep inf

.PHONY: exec
exec:
	docker exec -it $(hacking_container_name) bash

.PHONY: logs
logs:
	for id in $$(docker ps -aq -f "label=$(label)"); do \
		docker logs $$id; \
	done

.PHONY: clean
clean:
	for id in $$(docker ps -aq -f "label=$(label)"); do \
		docker rm -f $$id; \
	done

.PHONY: deep-clean
deep-clean: clean
	if [ -d $(nix_root) ]; then \
		chmod -R u+w $(nix_root); \
		rm -rf $(nix_root); \
	fi


### CI ###

icecap_rev := 720872483ddb7270c58fffd517437f1e4e00c027

icecap_rev_short := $(shell echo $(icecap_rev) | head -c 10)
ci_image_tag_name := ci-$(icecap_rev_short)
ci_image_tag := $(local_repository):$(ci_image_tag_name)
ci_container_name := $(container_name_base)-ci

# TODO investigate the benefits of the use of --squash
.PHONY: build-ci
build-ci:
	docker build -f ci/Dockerfile \
		--build-arg ICECAP_REV=$(icecap_rev) \
		--label $(label) -t $(ci_image_tag)  .

.PHONY: run-ci
run-ci:
	docker run -d --name $(ci_container_name) --label $(label) \
		--mount type=bind,src=$(abspath $(veracruz_root)),dst=/work/veracruz \
		$(icecap_mount) \
		$(ci_image_tag) sleep inf

.PHONY: exec-ci
exec-ci:
	docker exec -it $(ci_container_name) bash

.PHONY: clean-ci
clean-ci:
	for id in $$(docker ps -aq -f "name=$(ci_container_name)"); do \
		docker rm -f $$id; \
	done

.PHONY: test-ci
test-ci:
	docker run -it --name $(ci_container_name) --label $(label) \
		--mount type=bind,src=$(abspath $(veracruz_root)),dst=/work/veracruz \
		$(icecap_mount) \
		$(ci_image_tag) bash /work/veracruz/icecap/ci/run.sh

.PHONY: test-ci-populate
test-ci-populate:
	ICECAP_REV=$(icecap_rev) bash populate/run.sh


### CI + remote registry ###

remote_repository := ghcr.io/veracruz-project/veracruz/veracruz-icecap
remote_ci_image_tag := $(remote_repository):$(ci_image_tag_name)

.PHONY: test-ci-remote
test-ci-remote:
	docker run --rm --label $(label) \
		--mount type=bind,src=$(abspath $(veracruz_root)),dst=/work/veracruz \
		$(icecap_mount) \
		$(remote_ci_image_tag) bash /work/veracruz/icecap/ci/run.sh

.PHONY: pull-ci
pull-ci:
	docker rmi $(remote_ci_image_tag)
	docker pull $(remote_ci_image_tag)

# NOTE use caution
.PHONY: push-ci
push-ci:
	docker tag $(ci_image_tag) $(remote_ci_image_tag)
	docker push $(remote_ci_image_tag)
