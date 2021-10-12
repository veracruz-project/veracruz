# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

# from https://github.com/nspin/minimally-invasive-nix-installer/blob/master/dist/install-min-nix.fragment.sh

set -e

script_name="install-min-nix.sh"
script_url="https://github.com/nspin/minimally-invasive-nix-installer/raw/dist-62j2x1q9zy/dist/install-min-nix.sh"
script_sha256="6882ea0e9b9a12750028d589a17e9e7c184dc0058eb87be3a4064a5c53bfc73e"

curl -fL "$script_url" -o "$script_name"
echo "$script_sha256 $script_name" | sha256sum -c -
bash "$script_name"
rm "$script_name"
