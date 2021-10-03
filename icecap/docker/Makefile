# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

ICECAP_LOCAL ?= 0

nix_root := ./nix-root
veracruz_root := ../..
icecap_root := ../../../icecap

ifeq ($(ICECAP_LOCAL), 1)
       icecap_mount := --mount type=bind,src=$(abspath $(icecap_root)),dst=/work/icecap
endif

label := veracruz-icecap
image_tag := veracruz-icecap
container_name := veracruz-icecap

uid := $(shell id -u)
gid := $(shell id -g)

.PHONY: all
all: run

.PHONY: build
build:
	docker build --build-arg UID=$(uid) --build-arg GID=$(gid) --label $(label) -t $(image_tag) .

$(nix_root):
	mkdir -p -m 0755 $@

$(nix_root)/.installed: build $(nix_root)
	docker run --privileged --rm --label $(label) -w /home/x \
		--mount type=bind,src=$(abspath $(nix_root)),dst=/nix \
		$(image_tag) flock /nix/.installed.lock bash /setup.sh

.PHONY: run
run: build $(nix_root)/.installed
	docker run --privileged -d --name $(container_name) --label $(label) \
		--mount type=bind,src=$(abspath $(nix_root)),dst=/nix \
		--mount type=bind,src=$(abspath $(veracruz_root)),dst=/work/veracruz \
		$(icecap_mount) \
		$(image_tag) sleep inf

.PHONY: exec
exec:
	docker exec -it $(container_name) bash

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
