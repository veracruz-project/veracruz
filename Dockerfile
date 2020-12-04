FROM ubuntu:18.04

ARG TARGET
ARG USER
ARG UID

ENV DEBIAN_FRONTEND noninteractive

# Need different version of cmake from kitware
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gnupg \
        software-properties-common \
        wget && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | apt-key add - && \
    apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main' && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake=3.18.4-0kitware1 \
        cmake-data=3.18.4-0kitware1

# Zephyr dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ccache \
        device-tree-compiler \
        dfu-util \
        file \
        g++-multilib \
        gcc \
        gcc-multilib \
        git \
        gperf \
        libsdl2-dev \
        make \
        ninja-build \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-tk \
        python3-wheel \
        wget \
        xz-utils

# Install Zephyr
WORKDIR /zephyr-workspace
RUN pip3 install west && \
    west init --mr v2.4.0 && \
    west update && \
    pip3 install -r zephyr/scripts/requirements.txt

# Get the Zephyr SDK
#
# TODO we don't need all the compilers in this package... can we reduce
# this to just arm-none-eabi-gcc?
RUN wget https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.11.4/zephyr-sdk-0.11.4-setup.run -O /tmp/zephyr-sdk-0.11.4-setup.run 2>/dev/null && \
    chmod +x /tmp/zephyr-sdk-0.11.4-setup.run && \
    /tmp/zephyr-sdk-0.11.4-setup.run -- -d /opt/zephyr-sdk-0.11.4

# Extra config needed for Zephyr's tools
ENV PYTHONIOENCODING "UTF-8"

WORKDIR /zephyr-workspace/$TARGET
