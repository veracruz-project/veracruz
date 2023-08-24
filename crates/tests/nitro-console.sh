#!/bin/bash

# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.md` file in the Veracruz root directory for licensing
# and copyright information.

# Attaches to the console for any currently running Nitro enclave. Will throw
# an error if there are no currently enclaves

ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
echo $ENCLAVE_ID
nitro-cli console --enclave-id $ENCLAVE_ID
