#!/bin/bash
set -xe

#rm -rf /tmp/vc_test/
mkdir -p /tmp/vc_test/

mkdir -p /tmp/vc_test/shared/

mkdir -p /tmp/vc_test/shared/test/

cp ./target/aarch64-unknown-linux-gnu/debug/*.ta /tmp/vc_test/shared/test
find target/aarch64-unknown-linux-gnu/debug/deps -regextype sed -regex ".*/veracruz_test-[a-f0-9]\{16\}" \
       -exec cp \{\} /tmp/vc_test/shared/test/veracruz_test \;
cp -r ../test-collateral/ /tmp/vc_test/shared/
cp /usr/lib/aarch64-linux-gnu/libsqlite3.so.0 /tmp/vc_test/shared/
cp proxy-attestation-server.db /tmp/vc_test/shared/test

cat >/tmp/vc_test/shared/test/env.sh <<EOF
cp *.ta /lib/optee_armtz/
cp ../lib* /usr/lib
rm -f *.d
cat veracruz_test* > /dev/random
export DATABASE_URL=./proxy-attestation-server.db
EOF
chmod u+x /tmp/vc_test/shared/test/env.sh
