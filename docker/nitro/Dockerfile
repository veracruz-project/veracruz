# docker image for developing and testing Veracruz on AWS Nitro Enclaves
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

RUN pip install --no-cache-dir awscli

RUN wget https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.1.tar.gz && \
    tar zxvf openssl-3.0.1.tar.gz &&\
    cd openssl-openssl-3.0.1 && \
    CC="musl-gcc -fPIE -pie -static -idirafter /usr/include/ -idirafter /usr/include/${ARCH}-linux-gnu/" \
        ./Configure no-shared no-async -DOPENSSL_NO_SECURE_MEMORY \
        --prefix=/work/veracruz-nitro-root-enclave/musl \
        --openssldir=/work/veracruz/nitro-root-enclave/musl/ssl linux-${ARCH} && \
    make -j $(nproc) && \
    make install_sw install_ssldirs && \
    cd .. && \
    rm -rf openssl-openssl-3.0.1 openssl-3.0.1.tar.gz

ENV \
    AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/work/veracruz-nitro-root-enclave/musl/lib64 \
    X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=/work/veracruz-nitro-root-enclave/musl/lib64 \
    AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR=/work/veracruz-nitro-root-enclave/musl/include \
    X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR=/work/veracruz-nitro-root-enclave/musl/include

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

