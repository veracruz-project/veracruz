#!/bin/bash
#
# Run the server-side commands needed to run the Veracruz MCU Client demo
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

# build dependencies
make sdk sgx-cli-install

mkdir -p veracruz-mcu-client/example
make -C sdk/rust-examples/audio-event-triangulation
cp sdk/rust-examples/audio-event-triangulation/target/wasm32-wasi/release/audio-event-triangulation.wasm veracruz-mcu-client/example/audio-event-triangulation.wasm

# setup identities
openssl genrsa -out veracruz-mcu-client/example/controller-key.pem 2048
openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key veracruz-mcu-client/example/controller-key.pem \
    -out veracruz-mcu-client/example/controller-cert.pem \
    -config test-collateral/cert.conf

openssl genrsa -out veracruz-mcu-client/example/mcu0-key.pem 2048
openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key veracruz-mcu-client/example/mcu0-key.pem \
    -out veracruz-mcu-client/example/mcu0-cert.pem \
    -config test-collateral/cert.conf

openssl genrsa -out veracruz-mcu-client/example/mcu1-key.pem 2048
openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key veracruz-mcu-client/example/mcu1-key.pem \
    -out veracruz-mcu-client/example/mcu1-cert.pem \
    -config test-collateral/cert.conf

openssl genrsa -out veracruz-mcu-client/example/mcu2-key.pem 2048
openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key veracruz-mcu-client/example/mcu2-key.pem \
    -out veracruz-mcu-client/example/mcu2-cert.pem \
    -config test-collateral/cert.conf

openssl ecparam -name prime256v1 -genkey -noout \
    -out veracruz-mcu-client/example/ca-key.pem
openssl req -new -x509 -sha256 -nodes -days 1825 \
    -subj "/C=Mx/ST=Veracruz/L=Veracruz/O=Veracruz/OU=Proxy/CN=VeracruzProxyServer" \
    -key veracruz-mcu-client/example/ca-key.pem \
    -out veracruz-mcu-client/example/ca-cert.pem \
    -config test-collateral/ca-cert.conf

# generate the policy
vc-pgen \
    --proxy-attestation-server-ip 172.17.0.2:3010 \
    --proxy-attestation-server-cert veracruz-mcu-client/example/ca-cert.pem \
    --veracruz-server-ip 172.17.0.2:3017 \
    --certificate-expiry "$(date --rfc-2822 -d 'now + 100 days')" \
    --css-file runtime-manager/css-sgx.bin \
    --certificate veracruz-mcu-client/example/controller-cert.pem \
    --capability "audio-event-triangulation.wasm:w,output:r" \
    --certificate veracruz-mcu-client/example/mcu0-cert.pem \
    --capability "input-0:w" \
    --certificate veracruz-mcu-client/example/mcu1-cert.pem \
    --capability "input-1:w" \
    --certificate veracruz-mcu-client/example/mcu2-cert.pem \
    --capability "input-2:w" \
    --binary audio-event-triangulation.wasm=veracruz-mcu-client/example/audio-event-triangulation.wasm \
    --capability "input-0:r,input-1:r,input-2:r,output:w" \
    --output-policy-file veracruz-mcu-client/example/policy.json

# create the pas database
./test-collateral/populate-test-database.sh veracruz-mcu-client/example/pas.db

# launch vc-pas
pkill vc-pas || true
RUST_LOG=debug \
    vc-pas veracruz-mcu-client/example/policy.json \
        --database-url=veracruz-mcu-client/example/pas.db \
        --ca-cert=veracruz-mcu-client/example/ca-cert.pem \
        --ca-key=veracruz-mcu-client/example/ca-key.pem &
sleep 10

# launch vc-server
pkill vc-server || true
RUST_LOG=debug,actix_http=off \
    vc-server veracruz-mcu-client/example/policy.json &
sleep 10

# run the controller
PYTHONIOENCODING=utf-8 \
    ./sdk/rust-examples/audio-event-triangulation/scripts/poll_for_result.py \
        veracruz-mcu-client/example/policy.json \
        --identity veracruz-mcu-client/example/controller-cert.pem \
        --key veracruz-mcu-client/example/controller-key.pem \
        --program veracruz-mcu-client/example/audio-event-triangulation.wasm

