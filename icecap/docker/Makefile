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
		$(hacking_image_tag) sleep inf

.PHONY: exec
exec:
	docker exec -it $(hacking_container_name) bash

.PHONY: rm-container
rm-container:
	for id in $$(docker ps -aq -f "name=$(hacking_container_name)"); do \
		docker rm -f $$id; \
	done

.PHONY: rm-nix-state
rm-nix-state:
	if [ -d $(nix_root) ]; then \
		chmod -R u+w $(nix_root); \
		rm -rf $(nix_root); \
	fi


### CI ###

icecap_rev := e27e7bf9b4160a718cf59d5e2a97674a8456bdc1

icecap_rev_short := $(shell echo $(icecap_rev) | head -c 10)
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
