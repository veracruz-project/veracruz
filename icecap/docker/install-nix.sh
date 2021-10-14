# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

# update by copying from https://github.com/nspin/minimally-invasive-nix-installer/blob/master/dist/install-min-nix.fragment.sh

set -e

script_name="install-min-nix.sh"
script_url="https://github.com/nspin/minimally-invasive-nix-installer/raw/dist-y64jgzkzg5/dist/install-min-nix.sh"
script_sha256="f6772ec8ed9b4cb2253167b3d5e6091e9ddc365f170c3c043a39c8f3350ea291"

curl -fL "$script_url" -o "$script_name"
echo "$script_sha256 $script_name" | sha256sum -c -
bash "$script_name"
rm "$script_name"
