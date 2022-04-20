# docker image for developing and testing Veracruz.
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.
#
# NOTE: We try to follow the guide in https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
#       Each RUN contains a bundle of steps, which reduces the cache.

ARG TEE
ARG VERSION="latest"

FROM veracruz/${TEE}:${VERSION}
ARG USER=root
ARG UID=0
ARG DOCKER_GROUP_ID=0
ENV DEBIAN_FRONTEND noninteractive

ENV SCCACHE_DIR="/local/build/cache/sccache" \
    SCCACHE_CACHE_SIZE="10G" \
    RUSTUP_HOME="/local/build/cache/rustup" \
    CARGO_HOME="/local/build/cache/cargo" \
    STACK_ROOT="/local/build/cache/stack" \
    PATH="/local/build/cache/rustup/bin:$PATH"

# ENV RUSTC_WRAPPER=sccache

# Use bash as the default
SHELL ["/bin/bash", "-c"]

# add a user
RUN \
    mkdir -p /work; \
    mkdir -p /local; \
    if [ "$USER" != "root" ] ; then \
        useradd -l -u $UID -m -p `openssl rand -base64 32` -s /bin/bash $USER ; \
        if [ "$DOCKER_GROUP_ID" != "0" ] ; then \
            groupadd -g ${DOCKER_GROUP_ID} docker ; \
            usermod -a -G docker $USER ; \
        fi ; \
        if getent group ne &>/dev/null ; then \
            usermod -a -G ne $USER ; \
        fi ; \
        echo "$USER ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USER && chmod 0440 /etc/sudoers.d/$USER ; \
    fi

USER $USER
WORKDIR /work
