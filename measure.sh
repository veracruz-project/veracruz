#!/bin/bash

if [ -z "${1+x}"] ; then
    echo Give number of bytes as argument, for example $0 100000000
    exit
fi

set -euxo pipefail

size=$1
perl -e 'if ($ARGV[0] !~ /^[1-9][0-9]*$/) {
  die "Argument must be decimal\n"; }' "$size"

head -c $size /dev/zero > example/input.dat
perl -i -pe 's/ len = \d+/ len = '$size'/;' \
  examples/rust-examples/file-transfer/src/main.rs

make -C workspaces linux PROFILE=release
sudo make -C workspaces linux-install PROFILE=release

cargo build --manifest-path=workspaces/applications/Cargo.toml \
  --target wasm32-wasi --release --package file-transfer
mkdir -p example
cp workspaces/applications/target/wasm32-wasi/release/file-transfer.wasm \
  example/example-binary.wasm

openssl ecparam -name prime256v1 -genkey > example/example-program-key.pem
openssl req -x509 -days 3650 \
    -key example/example-program-key.pem \
    -out example/example-program-cert.pem \
    -config workspaces/cert.conf

openssl ecparam -name prime256v1 -genkey > example/example-data0-key.pem
openssl req -x509 -days 3650 \
    -key example/example-data0-key.pem \
    -out example/example-data0-cert.pem \
    -config workspaces/cert.conf

openssl ecparam -name prime256v1 -genkey > example/example-result-key.pem
openssl req -x509 -days 3650 \
    -key example/example-result-key.pem \
    -out example/example-result-cert.pem \
    -config workspaces/cert.conf

vc-pgen \
    --proxy-attestation-server-ip 127.0.0.1:3010 \
    --proxy-attestation-server-cert example/CACert.pem \
    --veracruz-server-ip 127.0.0.1:3017 \
    --certificate-expiry "$(date --rfc-2822 -d 'now + 100 days')" \
    --css-file workspaces/linux-runtime/target/release/runtime_manager_enclave \
    --certificate example/example-program-cert.pem \
    --capability "/program/:w" \
    --certificate example/example-data0-cert.pem \
    --capability "/input/:w" \
    --certificate example/example-result-cert.pem \
    --capability "/program/:x,/output/:r" \
    --binary /program/example-binary.wasm=example/example-binary.wasm \
    --capability "/input/:r,/output/:w" \
    --output-policy-file example/example-policy.json \
    --max-memory-mib 256

( cd /opt/veraison/vts && /opt/veraison/vts/vts ) &
( cd /opt/veraison/provisioning && /opt/veraison/provisioning/provisioning ) &
( cd example && /opt/veraison/proxy_attestation_server -l 127.0.0.1:3010 ) &
sleep 5

curl -X POST -H 'Content-Type: application/corim-unsigned+cbor; profile=http://arm.com/psa/iot/1' --data-binary "@/opt/veraison/psa_corim.cbor" localhost:8888/endorsement-provisioning/v1/submit
curl -X POST -H 'Content-Type: application/corim-unsigned+cbor; profile=http://aws.com/nitro' --data-binary "@/opt/veraison/nitro_corim.cbor" localhost:8888/endorsement-provisioning/v1/submit
time vc-server example/example-policy.json &
sleep 10

vc-client example/example-policy.json \
  --identity example/example-program-cert.pem \
  --key example/example-program-key.pem \
  --program program/example-binary.wasm=example/example-binary.wasm

T0=$(date +%s.%N)
time vc-client example/example-policy.json \
  --identity example/example-data0-cert.pem \
  --key example/example-data0-key.pem \
  --data input/file.dat=example/input.dat

T1=$(date +%s.%N)
time vc-client example/example-policy.json \
  --identity example/example-result-cert.pem \
  --key example/example-result-key.pem \
  --compute program/example-binary.wasm \
  --result output/file.dat=example/output.dat

T2=$(date +%s.%N)

pkill provisioning || true
pkill proxy_attestati || true
pkill vc-server || true
pkill vts || true

perl -i -pe 's/ len = \d+/ len = 1/;' \
  examples/rust-examples/file-transfer/src/main.rs

sleep 3
perl -e '@x = @ARGV; $size = $x[3];
  $in = $size / ($x[1] - $x[0]); $in_mb = int($in / 1e6 + 0.5);
  $out = $size / ($x[2] - $x[1]); $out_mb = int($out / 1e6 + 0.5);
  print "\nBytes: $size\n";
  print "In: $in B/s ($in_mb MB/s)\n";
  print "Out: $out B/s ($out_mb MB/s)\n\n";' \
  "$T0" "$T1" "$T2" "$size"
