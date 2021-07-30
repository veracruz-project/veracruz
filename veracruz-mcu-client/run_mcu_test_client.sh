
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
