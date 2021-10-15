set -e

set -x
nproc
free -h
set +x

cd /work/veracruz/icecap

make run-tests
