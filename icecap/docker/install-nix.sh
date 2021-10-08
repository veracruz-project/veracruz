# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

set -eu

arch="$(uname -m)"
version=hwv38gkcw4
script_name="install-${arch}-linux.sh"
url="https://github.com/nspin/minimally-invasive-nix-installer/raw/dist-${version}/dist/${script_name}"

case "$arch" in
    x86_64)
        sha256=828cb187045e69327b9164fae0374ec2ec64b8d5316b555dc1fa9a443111f94f
        ;;
    aarch64)
        sha256=b1e81a2cc8986cafd69baadd7d1999fa529dc30691eb253a6561f660957bfcb3
        ;;
    *)
        echo >&2 "unsupported architecture: '$arch'"
        exit 1
        ;;
esac

curl -L "$url" -o "$script_name"
echo "$sha256 $script_name" | sha256sum -c -
bash "$script_name"
rm "$script_name"
