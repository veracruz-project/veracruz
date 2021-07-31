
set -euxo pipefail

# make sure our path is pointing to the root of veracruz-mcu-client
cd $(dirname $0)

# run Shamir's Secret Sharing to test all of the program/data/result
# Veracruz interactions

make clean run_with_memory_report \
    VC_POLICY_PATH=example/policy.json \
    VC_IDENTITY_PATH=example/mcu0-cert.pem \
    VC_KEY_PATH=example/mcu0-key.pem
