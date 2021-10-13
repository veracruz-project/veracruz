set -e

nix_binary_cache_url="http://52.214.93.220:5000"
nix_binary_cache_public_key="icecap:j+jQQU4VWcGmre43aPtCt1GNfLmtO2IMKoZ1MsHOmVY="
nix_binary_cache_options=" \
    --option extra-substituters $nix_binary_cache_url \
    --option extra-trusted-public-keys $nix_binary_cache_public_key \
"

drv=$(nix-instantiate populate.nix $nix_binary_cache_options --add-root cache-roots)

nix-store --realise $nix_binary_cache_options $(nix-store -qR $drv)

# NOTE
# Counterintuitively counterproductive. We don't benefit from hard-links.
# nix-store --optimise
