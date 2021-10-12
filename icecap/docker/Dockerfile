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

RUN apt-get update && apt-get install -y \
    curl git man make rsync \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -f -g $GID x && useradd -u $UID -g $GID -m -p x x
USER x

ENV PATH="/nix/env/bin:${PATH}"
ENV MANPATH="/nix/env/share/man:${MANPATH}"
ENV NIX_SSL_CERT_FILE=/nix/env/etc/ssl/certs/ca-bundle.crt

# HACK for persistent git cache.
ENV XDG_CACHE_HOME=/nix/cache

ENV NIX_BUILD_SHELL bash

COPY nix.conf /etc/nix/
COPY install-nix.sh /
COPY setup.sh /

WORKDIR /work
