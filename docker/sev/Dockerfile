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

FROM veracruz/nitro:${VERSION}
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
	    guestfs-tools \
	    autoconf \
	    automake \
        bash-completion \
        bc \
        bison \
	    build-essential \
        ca-certificates \
        cabal-install \
        ccache \
        clang \
	    cloud-image-utils \
	    cloud-init \
        cmake \
        coreutils \
        cpio \
        curl \
        device-tree-compiler \
        doxygen \
	    dpkg-dev \
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
        haskell-stack \
	    iasl \
        jq \
        less \
        libc6-dev-arm64-cross \
	    libelf-dev \
	    libffi-dev \
	    libglib2.0-dev \
	    libfdt-dev \
	    libpixman-1-dev \
        libsqlite3-dev \
        libssl-dev \
        libxml2-utils \
	    nasm \
        netbase \
        openssh-client \
        pkg-config \
        protobuf-compiler \
        procps \
        psmisc \
        python3-dev \
        python3-pip \
        python3-protobuf \
        python3-setuptools \
	    qemu-efi \
        qemu-system-arm \
	    rsync \
        sqlite3 \
        strace \
        sudo \
        telnet \
        u-boot-tools \
        unzip \
        uuid-dev \
        vim \
	    virt-manager \
        wabt \
        wget \
        xxd \
        zlib1g-dev \
	    zstd \
	    meson \
	    debhelper \
        && \
    apt-get autoremove -y && apt-get clean && \
    rm -rf /tmp/* /var/tmp/* /var/lib/apt/lists/*

WORKDIR /work
RUN wget https://musl.cc/${ARCH}-linux-musl-native.tgz && \
    tar zxvf ${ARCH}-linux-musl-native.tgz && \
    ln -sf /work/${ARCH}-linux-musl-native/bin/${ARCH}-linux-musl-gcc /usr/bin/${ARCH}-linux-musl-gcc && \
    ln -sf /work/${ARCH}-linux-musl-native/bin/${ARCH}-linux-musl-g++ /usr/bin/${ARCH}-linux-musl-g++ && \
    rm ${ARCH}-linux-musl-native.tgz
RUN rustup target add x86_64-unknown-linux-musl

RUN wget https://github.com/openssl/openssl/archive/OpenSSL_1_1_1f.tar.gz
RUN tar -zxvf OpenSSL_1_1_1f.tar.gz; \
         cd openssl-OpenSSL_1_1_1f/; \
         CC="musl-gcc -fPIE -pie" ./Configure no-shared no-async --prefix=/musl --openssldir=/musl/ssl linux-x86_64; \
         make depend; \
         make -j$(nproc); \
         make install;

WORKDIR /
RUN git clone --branch snp-latest https://github.com/AMDESE/AMDSEV.git
WORKDIR /AMDSEV
#RUN git checkout d80b494f712317493d464a55652698c4d1b7bb0f
#RUN git checkout b04cde73313687cbd6c21c444cfd6f7ee8d28062
WORKDIR /
COPY common.patch AMDSEV/common.patch
COPY build.patch AMDSEV/build.patch
#COPY stable-commits.patch AMDSEV/stable-commits.patch
COPY boot_config AMDSEV/.config
COPY get-report.patch AMDSEV/get-report.patch
WORKDIR AMDSEV
RUN git apply common.patch
RUN git apply build.patch
#RUN git apply stable-commits.patch
RUN ./build.sh --package qemu
RUN ./build.sh --package kernel guest
RUN ./build.sh --package ovmf

WORKDIR /
#RUN git clone https://github.com/virtee/sev-snp-measure.git
RUN git clone https://github.com/larrydewey/sev-snp-measure.git
WORKDIR /sev-snp-measure
RUN git checkout debugswap
#cd sev-snp-measure
#./sev-snp-measure.py --help

