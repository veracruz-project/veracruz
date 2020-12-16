ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
echo $ENCLAVE_ID
nitro-cli console --enclave-id $ENCLAVE_ID
