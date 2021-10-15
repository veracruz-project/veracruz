# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    curl git man make rsync \
    procps \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -m 0755 /nix

RUN groupadd -r nixbld && useradd -rMN -g nixbld -G nixbld -d /var/empty -s /bin/false nixbld

COPY install-nix.sh .
RUN bash install-nix.sh && rm install-nix.sh

ENV PATH="/nix/env/bin:${PATH}"
ENV MANPATH="/nix/env/share/man:${MANPATH}"
ENV NIX_SSL_CERT_FILE=/nix/env/etc/ssl/certs/ca-bundle.crt
ENV NIX_BUILD_SHELL bash

COPY ci/nix.conf /etc/nix/
COPY ci/populate populate/

ARG ICECAP_REV
RUN ICECAP_REV=${ICECAP_REV} bash populate/run.sh && rm -r populate && rm -rf /root/.cache/nix

WORKDIR /work
