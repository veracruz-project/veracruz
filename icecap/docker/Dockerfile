# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

FROM ubuntu:18.04

ARG UID
ARG GID

# from ../base/Dockerfile, +rsync
RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    bc \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    git \
    libaio-dev \
    libbluetooth-dev \
    libcap-dev \
    libclang-dev \
    libcurl4-openssl-dev \
    libfdt-dev \
    libglib2.0-dev \
    libpixman-1-dev \
    libsqlite3-dev \
    libssl-dev \
    libtool \
    llvm-dev \
    make \
    pkg-config \
    python \
    python \
    python-crypto \
    python-pip \
    sqlite3 \
    unzip \
    uuid-dev \
    wget \
    xxd \
    zlib1g-dev \
    rsync \
    && rm -rf /var/lib/apt/lists/*

RUN pip install pycryptodome


RUN groupadd -f -g $GID x && useradd -u $UID -g $GID -m -p x x
USER x


### rust ###

ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH "${CARGO_HOME}/bin:${PATH}"

USER root
RUN mkdir $RUSTUP_HOME $CARGO_HOME && chown x $RUSTUP_HOME $CARGO_HOME
USER x

ARG rustup_tmp=/tmp/rustup-init
ARG rust_version=1.48.0
RUN curl -L -o ${rustup_tmp} "https://static.rust-lang.org/rustup/archive/1.22.1/x86_64-unknown-linux-gnu/rustup-init" && \
    echo "49c96f3f74be82f4752b8bffcf81961dea5e6e94ce1ccba94435f12e871c3bdb ${rustup_tmp}" | sha256sum -c - && \
    chmod +x ${rustup_tmp} && \
    ${rustup_tmp} -y --no-modify-path --profile minimal --default-toolchain ${rust_version} --default-host x86_64-unknown-linux-gnu && \
    rm ${rustup_tmp}

RUN cargo install diesel_cli --no-default-features --features sqlite


### nix ###

ENV PATH="/nix/env/bin:${PATH}"
ENV MANPATH="/nix/env/share/man:${MANPATH}"
ENV NIX_SSL_CERT_FILE=/nix/env/etc/ssl/certs/ca-bundle.crt

# HACK for persistent git cache.
ENV XDG_CACHE_HOME=/nix/cache

ENV NIX_BUILD_SHELL bash

COPY nix.conf /etc/nix/
COPY setup.sh /

WORKDIR /work
