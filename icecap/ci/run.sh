set -e

error_df()
{
    echo
    echo df -H
    df -H
}
trap error_df EXIT

cd /work/veracruz/icecap

make run-tests
