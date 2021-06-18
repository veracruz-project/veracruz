set -e

here="$(dirname "$0")"
host="$1"

nix-copy-closure --include-outputs --to "$host" $(nix-instantiate "$here/populate.nix")
