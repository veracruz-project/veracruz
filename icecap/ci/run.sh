set -e

error_df()
{
    set +e
    echo
    echo df -H
    df -H
    echo
    echo du -sh
    du -sh /nix /root /work
    echo
    echo du -k
    du -k /work | sort -rn | head -n 30
}
trap error_df EXIT

cd /work/veracruz/icecap

make run-tests
