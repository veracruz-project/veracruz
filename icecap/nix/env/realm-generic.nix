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
, icecapPlat
, kebabToCaml
}:

{ name, path, features ? [], sysroot ? false }:

let

  manifestPath = toString (path + "/Cargo.toml");

  debug = false;

  cargoConfig = nixToToml (crateUtils.clobber [
    crateUtils.baseCargoConfig
    {
      target.${rustTargetName}.rustflags = [
        "--cfg=icecap_plat=\"${icecapPlat}\""
        "-l" "static=icecap-utils"
        "-L" "${libs.icecap-utils}/lib"
        "-l" "static=icecap-pure"
        "-L" "${libs.icecap-pure}/lib"
        "-l" "static=c-supplement"
        "-L" "${libc-supplement}/lib"
      ] ++ lib.optionals sysroot [
        "--sysroot=${sysroot-rs}"
      ];
    }
  ]);

in

mkShell (crateUtils.baseEnv // rec {

  depsBuildBuild = [
    buildPackages.stdenv.cc
  ];

  nativeBuildInputs = [
    rustc cargo git cacert rustfmt
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

  BINDGEN_EXTRA_CLANG_ARGS = map (x: "-I${x}/include") buildInputs;

  "CC_${kebabToCaml rustTargetName}" = "${stdenv.cc.targetPrefix}cc";

  shellHook = ''
    build_dir=build/${name}
    build_dir_inverse=../..
    target_dir=build/target

    build() {
      setup && \
      (cd $build_dir && cargo build \
        -Z unstable-options \
        -Zfeatures=host_dep \
        --manifest-path ${manifestPath} \
        --target ${rustTargetName} \
        --features "${lib.concatStringsSep " " features}" \
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
