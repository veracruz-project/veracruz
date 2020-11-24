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
./run_tz_test.sh "sinaloa_test test_phase1"  20
./run_tz_test.sh "sinaloa_test test_phase2"  20
./run_tz_test.sh "sinaloa_test test_phase3"  20
./run_tz_test.sh "sinaloa_test test_phase4"  40
