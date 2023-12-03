# base docker image for developing and testing Veracruz
#
# This builds a common Ubuntu base image with the right pre-installed tools
# to build custom versions of tools, install rust, and build veracruz itself
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

from ${DOCKER_ARCH}golang:1.19 AS go_builder

RUN set -eux; \
    echo "iteration 0"; \
    git clone https://github.com/veracruz-project/proxy_attestation_server.git --branch main --tags ; \
    cd proxy_attestation_server; \
    git checkout v0.2.1; \
    go build -o ./vts/vts -ldflags "-X 'github.com/veraison/services/config.SchemeLoader=builtin'" github.com/veraison/services/vts/cmd/vts-service; \
    go build -o ./provisioning/provisioning -ldflags "-X 'github.com/veraison/services/config.SchemeLoader=builtin'" github.com/veraison/services/provisioning/cmd/provisioning-service; \
    go build .; \
    ls

from ${DOCKER_ARCH}golang:1.19 AS corim_builder

RUN set -eux; \
    go install github.com/veraison/corim/cocli@latest

COPY MyComidPsaIak.json /go/
COPY AWSNitroComid.json /go/
COPY corimMini.json /go/
RUN cocli comid create --template MyComidPsaIak.json
RUN cocli comid create --template AWSNitroComid.json
RUN cocli corim create -m MyComidPsaIak.cbor -t corimMini.json -o psa_corim.cbor
RUN cocli corim create -m AWSNitroComid.cbor -t corimMini.json -o nitro_corim.cbor

FROM ${DOCKER_ARCH}ubuntu:22.04

ARG ARCH=x86_64
ENV DEBIAN_FRONTEND noninteractive

# Use bash as the default
SHELL ["/bin/bash", "-c"]

# SUPPLY_CHAIN_NOTE: apt-get update means we always get latest, but also doesn't fix versions

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
        bash-completion \
        bc \
        bison \
        ca-certificates \
        cabal-install \
        ccache \
        clang \
        cmake \
        coreutils \
        cpio \
        curl \
        device-tree-compiler \
        doxygen \
        file \
        flex \
        g++ \
        gcc \
        gcc-aarch64-linux-gnu \
        g++-aarch64-linux-gnu \
        gdb \
        ghc \
        git \
        gnupg \
        jq \
        less \
        libc6-dev-arm64-cross \
        libnuma1 \
        libnuma-dev \
        libsqlite3-dev \
        libssl-dev \
        libxml2-utils \
        make \
        netbase \
        ninja-build \
        openssh-client \
        pkg-config \
        protobuf-compiler \
        procps \
        psmisc \
        python3-dev \
        python3-pip \
        python3-protobuf \
        python3-setuptools \
        qemu-system-arm \
        sqlite3 \
        strace \
        sudo \
        telnet \
        u-boot-tools \
        unzip \
        uuid-dev \
        vim \
        wabt \
        wget \
        xxd \
        xz-utils \
        zlib1g-dev \
        && \
    apt-get autoremove -y && apt-get clean && \
    rm -rf /tmp/* /var/tmp/* /var/lib/apt/lists/* && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 1

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.70.0

RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='0b2f6c8f85a3d02fde2efc0ced4657869d73fccfce59defb4e8d29233116e6db' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='673e336c81c65e6b16dcdede33f4cc9ed0f08bde1dbe7a935f113605292dc800' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/1.26.0/${rustArch}/rustup-init"; \
    wget "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION --default-host ${rustArch}; \
    rm rustup-init; \
    rm -rf /usr/local/cargo/registry/*/github.com-*

RUN mkdir /opt/veraison/; \
    mkdir /opt/veraison/vts; \
    mkdir /opt/veraison/vts/plugins; \
    mkdir /opt/veraison/provisioning; \
    mkdir /opt/veraison/provisioning/plugins
COPY --from=go_builder /go/proxy_attestation_server/vts /opt/veraison/vts/
COPY --from=go_builder /go/proxy_attestation_server/provisioning /opt/veraison/provisioning/
COPY --from=go_builder /go/proxy_attestation_server/proxy_attestation_server /opt/veraison/
COPY --from=corim_builder /go/psa_corim.cbor /opt/veraison/
COPY --from=corim_builder /go/nitro_corim.cbor /opt/veraison/

COPY vts_config.yaml /opt/veraison/vts/config.yaml
COPY --from=go_builder /go/proxy_attestation_server/vts/skey.jwk /opt/veraison/vts/
COPY provisioning_config.yaml /opt/veraison/provisioning/config.yaml
