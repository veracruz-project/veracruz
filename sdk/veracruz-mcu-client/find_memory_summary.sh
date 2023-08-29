#!/bin/bash
#
# Print a summary of total memory usage
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.


set -euo pipefail

if [[ $# -ne 3 ]]
then
    echo "usage: $0 <rom_report> <static_ram_report> <dyn_ram_report>"
    exit 1
fi

# extract summary from each report
printf "%7s %7s %7s %7s\n" code static heap stack
awk 'END{printf "%7d ",$1}' "$1"
awk 'END{printf "%7d ",$1}' "$2"
awk '\
    BEGIN{heap=0} \
    /^[ 0-9,]*$/{gsub(/,/,"",$3); if ($3 > heap) heap=$3} \
    END{printf "%7d ",heap}' "$3"
awk '\
    BEGIN{stack=0} \
    /^[ 0-9,]*$/{gsub(/,/,"",$6); if ($6 > stack) stack=$6} \
    END{printf "%7d ",stack}' "$3"
echo
