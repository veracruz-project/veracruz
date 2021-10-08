# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

set -eu

if [ ! -f /nix/.installed ]; then
    echo "Installing Nix..."
    bash /install-nix.sh
    touch /nix/.installed
    echo "Done"
fi
