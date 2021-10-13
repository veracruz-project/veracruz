set -e

nix_binary_cache_url="http://52.214.93.220:5000"
nix_binary_cache_public_key="icecap:j+jQQU4VWcGmre43aPtCt1GNfLmtO2IMKoZ1MsHOmVY="

nix-build populate.nix \
    --option extra-substituters "$nix_binary_cache_url" \
    --option extra-trusted-public-keys "$nix_binary_cache_public_key" \
    --no-out-link
