#!/bin/bash
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.
#

# Runs the example in GETTING_STARTED_CLI.markdown as a bash script, with any
# failing commands results in an error
#

set -euo pipefail

# start from scratch
rm -f GETTING_STARTED_CLI.markdown.sh

# make it so any error results in script failure
echo 'set -euxo pipefail' >> GETTING_STARTED_CLI.markdown.sh

# grab every bash code block, remove line continuation, and only keep lines
# that start with '$' (of course removing that '$' in the process)
#
# GETTING_STARTED_CLI.markdown currently uses sgx, replace with requested TEE
#
sed -n '/``` bash/,/```/{/```/d; p}' GETTING_STARTED_CLI.markdown \
    | sed ':a; /\\$/{N; s/\\\n//; ta}' \
    | sed -n '/^\$/{s/^\$ \?//; p}' \
    | sed "s/sgx/${1:-sgx}/g" \
    >> GETTING_STARTED_CLI.markdown.sh

# run script
bash GETTING_STARTED_CLI.markdown.sh
