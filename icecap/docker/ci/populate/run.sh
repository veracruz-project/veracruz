set -e

here="$(dirname "$0")"

nix_binary_cache_url="http://52.214.93.220:5000"
nix_binary_cache_public_key="icecap:j+jQQU4VWcGmre43aPtCt1GNfLmtO2IMKoZ1MsHOmVY="
nix_binary_cache_options=" \
    --option extra-substituters $nix_binary_cache_url \
    --option extra-trusted-public-keys $nix_binary_cache_public_key \
"

SALT=$RANDOM nix-build $nix_binary_cache_options $here --no-out-link
