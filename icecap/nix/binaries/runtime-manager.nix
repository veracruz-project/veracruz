{ lib, stdenv, hostPlatform, buildPackages, mkShell
, cargo, git, cacert
, protobuf, perl
, crateUtils, nixToToml
, liboutline, sysroot-rs
, icecapCratesAttrs
}:

let

  cargoConfig = crateUtils.clobber [
    crateUtils.baseCargoConfig
    { profile.release.panic = "abort"; }
    {
      target.${hostPlatform.config} = crateUtils.clobber (map (crate:
      if crate.buildScript == null then {} else {
        ${"dummy-link-${crate.name}"} = crate.buildScript;
      }) (lib.attrValues icecapCratesAttrs));
    }
    {
      target.${hostPlatform.config}.rustflags = [ "--sysroot=${sysroot-rs}" ];
    }
  ];

in

mkShell (crateUtils.baseEnv // {

  NIX_HACK_CARGO_CONFIG = nixToToml cargoConfig;

  depsBuildBuild = [
    buildPackages.stdenv.cc
  ];

  nativeBuildInputs = [
    cargo git cacert
    protobuf perl
  ];

  buildInputs = [
    liboutline
  ];

  shellHook = ''
    build() {
      cargo build --target ${hostPlatform.config} --release --features icecap \
        -j $NIX_BUILD_CORES \
        --target-dir build/runtime-manager/target --manifest-path ../runtime-manager/Cargo.toml \
        --out-dir=build/runtime-manager/out -Z unstable-options \
        $@
    }
  '';

})
