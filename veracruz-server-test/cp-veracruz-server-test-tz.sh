#!/bin/bash
set -xe

#rm -rf /tmp/vc_test/
mkdir -p /tmp/vc_test/

mkdir -p /tmp/vc_test/shared/

mkdir -p /tmp/vc_test/shared/test/

cp ../runtime-manager/e71bf7f6*.ta /tmp/vc_test/shared/test/
cp ../trustzone-root-enclave/75bb9a28*.ta /tmp/vc_test/shared/test/
find target/aarch64-unknown-linux-gnu/debug/deps -regextype sed -regex ".*/veracruz_server_test-[a-f0-9]\{16\}" \
       -exec cp \{\} /tmp/vc_test/shared/test/veracruz_server_test \;
cp -r ../test-collateral/ /tmp/vc_test/shared/
cp /usr/lib/aarch64-linux-gnu/libsqlite3.so.0 /tmp/vc_test/shared/
cp proxy-attestation-server.db /tmp/vc_test/shared/test

cat >/tmp/vc_test/shared/test/env.sh <<EOF
cp *.ta /lib/optee_armtz/
cp ../lib* /usr/lib
rm -f *.d
cat veracruz_server_test* > /dev/random
export DATABASE_URL=./proxy-attestation-server.db
EOF
chmod u+x /tmp/vc_test/shared/test/env.sh
