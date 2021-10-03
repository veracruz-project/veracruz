# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

set -e

if [ ! -f /nix/.installed ]; then
    echo "Installing Nix..."
    curl -L https://github.com/nspin/minimally-invasive-nix-installer/raw/dist-11p9fcf3ca/dist/install.sh -o install-nix.sh
    echo "8bf39c7fc93534ee98fdbf2c3ae970def38ce0eb2f2146a66b067bc3975f0cda install-nix.sh" | sha256sum -c -
    bash install-nix.sh
    rm install-nix.sh
    touch /nix/.installed
    echo "Done"
fi
