# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

{ lib, stdenv, buildPackages, mkShell
, rustc, cargo, git, cacert, rustfmt
, crateUtils, nixToToml, rustTargetName
, protobuf, perl, python3
, libsel4, libs, sysroot-rs
, libc-supplement
}:

let

  name = "runtime-manager";

  manifestPath = toString (../../.. + "/${name}/Cargo.toml");

  debug = false;

  cargoConfig = nixToToml (crateUtils.clobber [
    crateUtils.baseCargoConfig
    {
      target.${rustTargetName}.rustflags = [
        "--sysroot=${sysroot-rs}"
        "-l" "static=icecap_pure"
        "-L" "${libs.icecap-pure}/lib"
        "-l" "static=c_supplement"
        "-L" "${libc-supplement}/lib"
      ];
    }
  ]);

in

mkShell (crateUtils.baseEnv // {

  depsBuildBuild = [
    buildPackages.stdenv.cc
  ];

  nativeBuildInputs = [
    rustc cargo git cacert rustfmt
    protobuf perl python3
  ];

  buildInputs = [
    libsel4
    libs.icecap-autoconf
    libs.icecap-runtime
    libs.icecap-utils
    libs.icecap-pure
    libc-supplement
  ];

  # For bindgen
  LIBCLANG_PATH = "${lib.getLib buildPackages.llvmPackages.libclang}/lib";

  shellHook = ''
    # NOTE
    # If this ever ceases to suffice, see $BINDGEN_EXTRA_CLANG_ARGS for the host binaries. 
    export BINDGEN_EXTRA_CLANG_ARGS="$NIX_CFLAGS_COMPILE"

    build_dir=build/${name}
    build_dir_inverse=../..
    target_dir=build/target

    build() {
      setup && \
      (cd $build_dir && cargo build \
         -Z unstable-options \
        --manifest-path ${manifestPath} \
        --target ${rustTargetName} --features icecap \
        ${lib.optionalString (!debug) "--release"} \
        --target-dir $build_dir_inverse/$target_dir \
        --out-dir ./out \
        -j$NIX_BUILD_CORES \
        "$@"
      )
    }

    setup() {
      mkdir -p $build_dir/.cargo
      ln -sf ${cargoConfig} $build_dir/.cargo/config
    }
  '';

})
