# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

{ lib, mkShell
, crateUtils
, rustup, git, cacert
, cmake, python3, perl
, file, bc, xxd
, sqlite, diesel-cli
}:

mkShell rec {

  # By default, Nix injects hardening options into C compilation.
  # For now, to reduce build complexity, disable that.
  hardeningDisable = [ "all" ];

  nativeBuildInputs = [
    rustup git cacert
    cmake python3 perl
    file bc xxd
    sqlite diesel-cli
  ];

}
