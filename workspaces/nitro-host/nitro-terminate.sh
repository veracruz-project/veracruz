#!/bin/bash

# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

# Terminates any currently running AWS nitro enclaves running on the current
# instance.

INFO=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
echo $INFO

nitro-cli terminate-enclave --enclave-id $INFO && echo "None found"
(exit 0)
