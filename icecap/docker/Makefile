local_root := ../..

user := $(shell id -un)
uid := $(shell id -u)
gid := $(shell id -g)

label := icecap-ubuntu
image_tag := icecap-ubuntu:$(user)
container_name := icecap-ubuntu-$(user)

.PHONY: all
all:

.PHONY: build
build:
	docker build \
		--build-arg USER=$(user) --build-arg UID=$(uid) --build-arg GID=$(gid) \
		--label $(label) -t $(image_tag) .

.PHONY: try
try: build
	docker run -it --rm --label $(label) \
		--mount type=bind,src=$(abspath $(local_root)),dst=/local \
		$(image_tag) bash

.PHONY: run
run: build
	docker run -d --name $(container_name) --label $(label) \
		--mount type=bind,src=$(abspath $(local_root)),dst=/local \
		$(image_tag) sleep inf

.PHONY: exec
exec:
	docker exec -it $(container_name) bash

.PHONY: clean
clean:
	for id in $$(docker ps -aq -f "name=$(container_name)"); do \
		docker rm -f $$id; \
	done
