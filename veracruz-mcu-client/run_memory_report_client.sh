#!/bin/bash
#
# Run and accumulate memory reports on the execution of the Veracruz MCU Client demo
#
# Note that this requires that run_mcu_demo_server.sh to have been run in order
# to set up the necessary servers
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

set -euxo pipefail

# make sure our path is pointing to the root of veracruz-mcu-client
cd $(dirname $0)

# run Shamir's Secret Sharing to test all of the program/data/result
# Veracruz interactions
make clean run-with-memory-report \
    VC_POLICY_PATH=example/policy.json \
    VC_IDENTITY_PATH=example/mcu0-cert.pem \
    VC_KEY_PATH=example/mcu0-key.pem
