# docker image for developing and testing Veracruz on AWS Nitro Enclaves
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.md` file in the Veracruz root directory for licensing
# and copyright information.
#
# NOTE: We try to follow the guide in https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
#       Each RUN contains a bundle of steps, which reduces the cache.

ARG VERSION="latest"

FROM veracruz/base:${VERSION}
ENV DEBIAN_FRONTEND noninteractive

ARG ARCH=x86_64
ARG NE_GID=""

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        apt-transport-https \
        ca-certificates \
        lsb-release \
        lxc \
        musl-tools && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    arch=$(dpkg --print-architecture) && \
    dist=$(lsb_release -cs) && \
    echo "deb [arch=$arch signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu impish stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && apt-get install --no-install-recommends -y docker-ce-cli && \
    apt-get autoremove -y && apt-get clean && \
    rm -rf /tmp/* /var/tmp/* /var/lib/apt/lists/*

COPY aws-nitro-enclaves-cli/build/nitro_cli/${ARCH}-unknown-linux-musl/release/nitro-cli /usr/bin/

WORKDIR /work
RUN wget https://musl.cc/${ARCH}-linux-musl-native.tgz && \
    tar zxvf ${ARCH}-linux-musl-native.tgz && \
    ln -sf /work/${ARCH}-linux-musl-native/bin/${ARCH}-linux-musl-gcc /usr/bin/${ARCH}-linux-musl-gcc && \
    ln -sf /work/${ARCH}-linux-musl-native/bin/${ARCH}-linux-musl-g++ /usr/bin/${ARCH}-linux-musl-g++ && \
    rm ${ARCH}-linux-musl-native.tgz

RUN mkdir -p /var/log/nitro_enclaves ; \
    touch /var/log/nitro_enclaves/nitro_enclaves.log ; \
    chmod -R a+rw /var/log/nitro_enclaves ; \
    chmod a+x /var/log/nitro_enclaves ; \
    mkdir -p /usr/share/nitro_enclaves/blobs/
COPY aws-nitro-enclaves-cli/blobs/${ARCH}/* /usr/share/nitro_enclaves/blobs

RUN NE_GID=${NE_GID} ; \
    if [ -z "$NE_GID" ] ; then \
        echo "No ne group found. Non-root users will be able to build, but not run nitro tests" ; \
    else \
        groupadd -g ${NE_GID} ne ; \
    fi

RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o "awscliv2.zip" \
	&& unzip awscliv2.zip \
	&& ./aws/install \
    && rm -rf awscliv2.zip aws

