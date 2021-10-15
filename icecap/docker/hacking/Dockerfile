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

ARG UID
ARG GID

RUN groupadd -f -g $GID x && useradd -u $UID -g $GID -m -p x x
USER x

ENV PATH="/nix/env/bin:${PATH}"
ENV MANPATH="/nix/env/share/man:${MANPATH}"
ENV NIX_SSL_CERT_FILE=/nix/env/etc/ssl/certs/ca-bundle.crt
ENV NIX_BUILD_SHELL bash

# HACK for persistent git cache.
ENV XDG_CACHE_HOME=/nix/cache

COPY install-nix.sh /
COPY hacking/setup.sh /
COPY hacking/nix.conf /etc/nix/

WORKDIR /work
