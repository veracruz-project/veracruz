# docker image for developing and testing Veracruz on AMD SEV-SNP enclaves
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

ARG VERSION="latest"

FROM veracruz/base:${VERSION}
ENV DEBIAN_FRONTEND noninteractive

ARG ARCH=x86_64

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        apt-transport-https \
        ca-certificates \
        lsb-release \
        lxc \
	    llvm \
        musl-tools \
	    guestfs-tools && \
    apt-get autoremove -y && apt-get clean && \
    rm -rf /tmp/* /var/tmp/* /var/lib/apt/lists/*

WORKDIR /work
RUN wget https://musl.cc/${ARCH}-linux-musl-native.tgz && \
    tar zxvf ${ARCH}-linux-musl-native.tgz && \
    ln -sf /work/${ARCH}-linux-musl-native/bin/${ARCH}-linux-musl-gcc /usr/bin/${ARCH}-linux-musl-gcc && \
    ln -sf /work/${ARCH}-linux-musl-native/bin/${ARCH}-linux-musl-g++ /usr/bin/${ARCH}-linux-musl-g++ && \
    rm ${ARCH}-linux-musl-native.tgz
