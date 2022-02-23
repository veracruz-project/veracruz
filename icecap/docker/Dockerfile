FROM ubuntu:22.04
ARG USER=root
ARG UID=0
ARG GID=0
ENV DEBIAN_FRONTEND noninteractive

# Use bash as the default
SHELL ["/bin/bash", "-c"]

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        bash-completion \
        bc \
        bison \
        ccache \
        ca-certificates \
        cmake \
        coreutils \
        cpio \
        curl \
        device-tree-compiler \
        doxygen \
        file \
        flex \
        gcc-aarch64-linux-gnu \
        gdb \
        git \
        gnupg \
        haskell-stack \
        less \
        libxml2-utils \
        netbase \
        ninja-build \
        openssh-client \
        protobuf-compiler \
        python3-dev \
        python3-pip \
        python3-protobuf \
        python3-setuptools \
        qemu-system-arm \
        strace \
        sudo \
        u-boot-tools \
        unzip \
        vim \
        wget \
        && \
    apt-get upgrade -y && \
    apt-get autoremove -y && apt-get clean && \
    rm -rf /tmp/* /var/tmp/* /var/lib/apt/lists/*

# Install repo
RUN \
    export REPO=$(mktemp /tmp/repo.XXXXXXXXX) ; \
    curl -o ${REPO} https://storage.googleapis.com/git-repo-downloads/repo && \
    gpg --recv-key 8BB9AD793E8E6153AF0F9A4416530D5E920F5C65 && \
    curl -s https://storage.googleapis.com/git-repo-downloads/repo.asc | gpg --verify - ${REPO} && \
    install -m 755 ${REPO} /usr/bin/repo && \
    rm ${REPO}

# Install sel4-deps python packages
RUN \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 1 && \
    python3 -m pip install --no-cache-dir \
        aenum \
        concurrencytest \
        hypothesis \
        orderedset \
        pyelftools \
        nose \
        sel4-deps \
        six \
        sortedcontainers

# Optional packages for sel4 documentation
# RUN \
#     apt-get update && \
#     apt-get install --no-install-recommends -y \
#         gcc-arm-linux-gnueabi g++-arm-linux-gnueabi \
#         gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
#         texlive texlive-latex-extra texlive-fonts-extra \
#         && \
#     apt-get autoremove -y && apt-get clean && \
#     rm -rf /tmp/* /var/tmp/* /var/lib/apt/lists/*

ENV \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=nightly-2021-08-25

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
    mkdir -p /local; \
    if [ "$USER" != "root" ] ; then \
        groupadd -f -g $GID $USER ; \
        useradd -u $UID -g $GID -m -p `openssl rand -base64 32` -s /bin/bash $USER ; \
        chown $USER:$GID /local ; \
        chown -R $USER:$GID /usr/local/rustup /usr/local/cargo ; \
        echo "$USER ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USER && chmod 0440 /etc/sudoers.d/$USER ; \
    fi

ENV RUSTUP_HOME="/local/build/cache/rustup"
ENV CARGO_HOME="/local/build/cache/cargo"
ENV STACK_ROOT="/local/build/cache/stack"

USER $USER
WORKDIR /local
