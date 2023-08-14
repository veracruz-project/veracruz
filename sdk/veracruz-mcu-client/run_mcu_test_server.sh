#!/bin/bash
#
# Run the server-side commands needed test the Veracruz MCU Client
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

# make sure our path is pointing to the root of Veracruz
cd $(dirname $0)/..

# kill existing servers
pkill vc-server || true
pkill vc-pas || true

# build dependencies
make sgx-cli-install sdk

make -C examples/rust-examples/shamir-secret-sharing
mkdir -p veracruz-mcu-client/test-data
cp examples/rust-examples/shamir-secret-sharing/target/wasm32-wasi/release/shamir-secret-sharing.wasm veracruz-mcu-client/test-data/test-binary.wasm
./sdk/wasm-checker/wabt/bin/wasm-strip veracruz-mcu-client/test-data/test-binary.wasm

# setup identities
openssl ecparam -name prime256v1 -genkey \
    -out veracruz-mcu-client/test-data/test-key.pem
openssl req -x509 -sha256 -days 3650 \
    -key veracruz-mcu-client/test-data/test-key.pem \
    -out veracruz-mcu-client/test-data/test-cert.pem \
    -config test-collateral/cert.conf

openssl ecparam -name prime256v1 -genkey \
    -out veracruz-mcu-client/test-data/test-ca-key.pem
openssl req -x509 -sha256 -days 1825 \
    -subj "/C=Mx/ST=Veracruz/L=Veracruz/O=Veracruz/OU=Proxy/CN=VeracruzProxyServer" \
    -key veracruz-mcu-client/test-data/test-ca-key.pem \
    -out veracruz-mcu-client/test-data/test-ca-cert.pem \
    -config test-collateral/ca-cert.conf

# generate the policy
vc-pgen \
    --proxy-attestation-server-ip 172.17.0.2:3010 \
    --proxy-attestation-server-cert veracruz-mcu-client/test-data/test-ca-cert.pem \
    --veracruz-server-ip 172.17.0.2:3017 \
    --certificate-expiry "$(date --rfc-2822 -d 'now + 100 days')"\
    --css-file runtime-manager/css-sgx.bin \
    --certificate veracruz-mcu-client/test-data/test-cert.pem \
    --capability "test-binary.wasm:w,input-0:w,input-1:w,input-2:w,output:r" \
    --program-binary test-binary.wasm=veracruz-mcu-client/test-data/test-binary.wasm \
    --capability "input-0:r,input-1:r,input-2:r,output:w" \
    --output-policy-file veracruz-mcu-client/test-data/test-policy.json

# launch vc-pas
RUST_LOG=debug vc-pas veracruz-mcu-client/test-data/test-policy.json \
    --ca-cert=veracruz-mcu-client/test-data/test-ca-cert.pem \
    --ca-key=veracruz-mcu-client/test-data/test-ca-key.pem &
sleep 10

# launch vc-server
RUST_LOG=debug,actix_http=off vc-server veracruz-mcu-client/test-data/test-policy.json &
sleep 10


