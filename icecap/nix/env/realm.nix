# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

{ lib, stdenv, buildPackages, mkShell
, rustup, git, cacert, rustfmt
, protobuf, perl, python3
, libsel4, libs
, libc-supplement
}:

mkShell rec {

  # By default, Nix injects hardening options into C compilation.
  # For now, to reduce build complexity, disable that.
  hardeningDisable = [ "all" ];

  depsBuildBuild = [
    buildPackages.stdenv.cc
  ];

  nativeBuildInputs = [
    rustup git cacert rustfmt
    protobuf perl python3
  ];

  buildInputs = [
    libsel4
    libs.icecap-runtime
    libs.icecap-utils
    libs.icecap-pure
    libc-supplement
  ];

  # For bindgen
  LIBCLANG_PATH = "${lib.getLib buildPackages.llvmPackages.libclang}/lib";

}
