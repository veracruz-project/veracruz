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
, libsel4, userC
, libc-supplement
, cmake, stdenvToken
}:

mkShell.override { stdenv = stdenvToken; } rec {

  # By default, Nix injects hardening options into C compilation.
  # For now, to reduce build complexity, disable that.
  hardeningDisable = [ "all" ];

  depsBuildBuild = [
    buildPackages.stdenv.cc
  ];

  nativeBuildInputs = [
    rustup git cacert rustfmt
    protobuf perl python3
    cmake
  ];

  buildInputs = [
    libsel4
    userC.nonRootLibs.icecap-runtime
    userC.nonRootLibs.icecap-utils
    userC.nonRootLibs.compiler-some-libc
    userC.nonRootLibs.icecap-some-libc
    libc-supplement
  ];

  # Sets __STDC_HOSTED__=0
  NIX_CFLAGS_COMPILE = [ "-ffreestanding" ];

  # For bindgen
  LIBCLANG_PATH = "${lib.getLib buildPackages.llvmPackages.libclang}/lib";

}
