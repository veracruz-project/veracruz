#!/bin/bash
#
# Development script to update IceCap/seL4 git submodules.
#
## Authors
#
# The Veracruz Development Team.
#
## Licensing and copyright notice
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
# information on licensing and copyright.

set -e

cd $(dirname $(dirname $(realpath $0)))

git submodule update --init --recursive

(cd icecap/icecap ; git stash ; git fetch ; git checkout realmos ; git branch -M backup-$(date +%Y-%m-%d-%H%M%S) ; git checkout -B realmos origin/realmos)
(cd workspaces/icecap-runtime/deps/seL4 ; git stash ; git fetch ; git checkout realmos ; git branch -M backup-$(date +%Y-%m-%d-%H%M%S) ; git checkout -B realmos origin/realmos)
(cd workspaces/icecap-runtime/deps/seL4_tools ; git stash ; git fetch ; git checkout realmos ; git branch -M backup-$(date +%Y-%m-%d-%H%M%S) ; git checkout -B realmos origin/realmos)
