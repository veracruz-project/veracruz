#!/bin/bash
#
# Run the client-side commands needed test the Veracruz MCU Client
#
# Note that this requires that run_mcu_test_server.sh to have been run in order
# to set up the necessary servers
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSE.md` file in the Veracruz root directory for
# licensing and copyright information.

set -euxo pipefail

# make sure our path is pointing to the root of veracruz-mcu-client
cd $(dirname $0)

# run Shamir's Secret Sharing to test all of the program/data/result
# Veracruz interactions
make clean build-test run \
    VC_POLICY_PATH=test-data/test-policy.json \
    VC_IDENTITY_PATH=test-data/test-cert.pem \
    VC_KEY_PATH=test-data/test-key.pem \
    SHAMIR_SECRET_SHARING_BINARY_PATH=test-data/test-binary.wasm
