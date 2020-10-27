#!/bin/bash
set -xe

#rm -rf /tmp/vc_test/
mkdir -p /tmp/vc_test/

mkdir -p /tmp/vc_test/shared/

mkdir -p /tmp/vc_test/shared/test/

cp ./target/aarch64-unknown-linux-gnu/debug/*.ta /tmp/vc_test/shared/test/
find ./target/aarch64-unknown-linux-gnu/debug/deps -executable -type f \
       -exec cp \{\} /tmp/vc_test/shared/test/sinaloa_test \;
cp -r ../test-collateral/ /tmp/vc_test/shared/
cp /usr/lib/aarch64-linux-gnu/libsqlite3.so.0 /tmp/vc_test/shared/
cp tabasco.db /tmp/vc_test/shared/test

cat >/tmp/vc_test/shared/test/env.sh <<EOF
cp *.ta /lib/optee_armtz/
cp ../lib* /usr/lib
rm -f *.d
cat sinaloa_test* > /dev/random
export DATABASE_URL=./tabasco.db
EOF
chmod u+x /tmp/vc_test/shared/test/env.sh
