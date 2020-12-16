INFO=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
echo $INFO
#jENCLAVE_ID=$(jq -r '[0].EnclaveID')
#jecho $ENCLAVE_ID
nitro-cli terminate-enclave --enclave-id $INFO
