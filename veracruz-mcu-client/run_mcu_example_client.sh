
set -euxo pipefail

# make sure our path is pointing to the root of veracruz-mcu-client
cd $(dirname $0)

# run each client in the example
make clean build run \
    VC_POLICY_PATH=example/policy.json \
    VC_IDENTITY_PATH=example/mcu0-cert.pem \
    VC_KEY_PATH=example/mcu0-key.pem

make clean build run \
    VC_POLICY_PATH=example/policy.json \
    VC_IDENTITY_PATH=example/mcu1-cert.pem \
    VC_KEY_PATH=example/mcu1-key.pem \
    AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER=1

make clean build run \
    VC_POLICY_PATH=example/policy.json \
    VC_IDENTITY_PATH=example/mcu2-cert.pem \
    VC_KEY_PATH=example/mcu2-key.pem \
    AUDIO_EVENT_TRIANGULATION_CLAP_NUMBER=2

