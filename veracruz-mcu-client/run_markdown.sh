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

# Runs the given markdown file as a bash script, with any failing commands
# resulting in an error
#

set -euo pipefail

DOC="$1"
TERM="${2:-bash}"

# start from scratch
rm -f $DOC.sh

# make it so any error results in script failure
echo 'set -euxo pipefail' >> $DOC.sh

# grab every bash code block, remove line continuation, and only keep lines
# that start with '$' (of course removing that '$' in the process)
#
sed -n '/``` '"$TERM"'/,/```/{/```/d; p}' $DOC \
    | sed ':a; /\\$/{N; s/\\\n//; ta}' \
    | sed -n '/^\$/{s/^\$ \?//; p}' \
    >> $DOC.sh

# run script
bash $DOC.sh
