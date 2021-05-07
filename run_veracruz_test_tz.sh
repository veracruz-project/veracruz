#!/bin/bash
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.

# Run test individual phases:
./run_tz_test.sh "veracruz_test veracruz_phase1"  100
./run_tz_test.sh "veracruz_test veracruz_phase2"  200
./run_tz_test.sh "veracruz_test veracruz_phase3"  100
./run_tz_test.sh "veracruz_test veracruz_phase4"  200
