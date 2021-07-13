#!/bin/bash
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

# Run test individual phases:
./run_tz_test.sh "veracruz_server_test test_phase1"  30
./run_tz_test.sh "veracruz_server_test test_phase2"  30
./run_tz_test.sh "veracruz_server_test test_phase3"  30
./run_tz_test.sh "veracruz_server_test test_phase4"  50
