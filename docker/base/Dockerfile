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
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.
#
# NOTE: We try to follow the guide in https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
#       Each RUN contains a bundle of steps, which reduces the cache.

FROM ubuntu:22.04

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
        gdb \
        ghc \
        git \
        gnupg \
        haskell-stack \
        jq \
        less \
        libc6-dev-arm64-cross \
        libsqlite3-dev \
        libssl-dev \
        libxml2-utils \
        netbase \
        ninja-build \
        openssh-client \
        pkg-config \
        protobuf-compiler \
        procps \
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
        zlib1g-dev \
        && \
    apt-get autoremove -y && apt-get clean && \
    rm -rf /tmp/* /var/tmp/* /var/lib/apt/lists/* && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 1

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.56.1

RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='3dc5ef50861ee18657f9db2eeb7392f9c2a6c95c90ab41e45ab4ca71476b4338' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='32a1532f7cef072a667bac53f1a5542c99666c4071af0c9549795bbdb2069ec1' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/1.24.3/${rustArch}/rustup-init"; \
    wget "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION --default-host ${rustArch}; \
    rm rustup-init; \
    cargo install diesel_cli --no-default-features --features sqlite ; \
    rm -rf /usr/local/cargo/registry/*/github.com-*
