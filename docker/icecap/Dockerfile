# docker image for developing and testing Veracruz on IceCap
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

FROM veracruz/base:${VERSION} as final

ARG ARCH=x86_64
ARG USER=root
ARG UID=0

# Install repo
RUN \
    export REPO=$(mktemp /tmp/repo.XXXXXXXXX) ; \
    curl -o ${REPO} https://storage.googleapis.com/git-repo-downloads/repo && \
    gpg --recv-key 8BB9AD793E8E6153AF0F9A4416530D5E920F5C65 && \
    curl -s https://storage.googleapis.com/git-repo-downloads/repo.asc | gpg --verify - ${REPO} && \
    install -m 755 ${REPO} /usr/bin/repo && \
    rm ${REPO}

# Install sel4-deps & other IceCap python package dependencies
RUN \
    python3 -m pip install --no-cache-dir \
        aenum \
        concurrencytest \
        hypothesis \
        nose \
        orderedset \
        pyelftools \
        sel4-deps \
        six \
        sortedcontainers

RUN \
    git clone https://gitlab.com/tseenshe/stack2cabal.git &&  \
    cd stack2cabal && \
    cabal v2-update && \
    cabal v2-build -j --disable-optimization --ghc-options "-O0" all && \
    cp $(cabal v2-exec --disable-optimization -v0 which -- stack2cabal) /usr/local/bin && \
    cd .. && \
    rm -rf stack2cabal && \
    git clone https://gitlab.com/arm-research/security/icecap/capdl.git && \
    cd capdl/capDL-tool && \
    /usr/local/bin/stack2cabal && \
    perl -i -pe 's/with-compiler: ghc-.*/with-compiler: ghc-8.8.4/' cabal.project && \
    cabal v2-build -j --disable-optimization --ghc-options "-O0" all && \
    cp $(cabal v2-exec --disable-optimization -v0 which -- parse-capDL) /usr/local/bin && \
    cd ../.. && \
    rm -rf capdl && \
    cabal v2-clean && \
    rm -rf $HOME/.cabal
