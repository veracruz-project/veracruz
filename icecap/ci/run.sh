#!/bin/bash
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory
# for licensing and copyright information.

set -e

cd /work/veracruz/icecap

make run-tests VERACRUZ_REMOTE_CI=true
