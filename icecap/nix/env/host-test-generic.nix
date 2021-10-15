# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

{ lib, stdenv, buildPackages, mkShell
, rustc, cargo, git, cacert
, crateUtils, nixToToml, rustTargetName
, protobuf, perl, python3
, pkgconfig, openssl, sqlite
}:

{ name }:

let

  manifestPath = toString (../../.. + "/${name}/Cargo.toml");

  debug = false;

  cargoConfig = nixToToml (crateUtils.clobber [
    crateUtils.baseCargoConfig
  ]);

in

mkShell (crateUtils.baseEnv // rec {

  # By default, Nix injects hardening options into C compilation.
  # For now, to reduce build complexity, disable that.
  hardeningDisable = [ "all" ];

  depsBuildBuild = [
    buildPackages.stdenv.cc
  ];

  nativeBuildInputs = [
    rustc cargo git cacert
    protobuf perl python3
    pkgconfig
  ];

  buildInputs = [
    openssl sqlite
  ];

  PKG_CONFIG_ALLOW_CROSS = 1;

  # For bindgen
  LIBCLANG_PATH = "${lib.getLib buildPackages.llvmPackages.libclang}/lib";

  shellHook = ''
    # NOTE
    #
    # This is one spot where we have to do a bit of Nix gymnastics.
    # Having to do this kind of thing isn't ideal, but it's the price we pay.
    #
    # Copied from: https://github.com/NixOS/nixpkgs/blob/1fab95f5190d087e66a3502481e34e15d62090aa/pkgs/applications/networking/browsers/firefox/common.nix#L247-L253
    # Set C flags for bindgen. Bindgen does not invoke $CC directly. Instead it
    # uses LLVM's libclang. To make sure all necessary flags are included, we
    # need to look in a few places.
    export BINDGEN_EXTRA_CLANG_ARGS=" \
      $(< ${stdenv.cc}/nix-support/libc-crt1-cflags) \
      $(< ${stdenv.cc}/nix-support/libc-cflags) \
      $(< ${stdenv.cc}/nix-support/cc-cflags) \
      $(< ${stdenv.cc}/nix-support/libcxx-cxxflags) \
      -isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc} -isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc}/${stdenv.hostPlatform.config} \
      -isystem ${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.config}/${lib.getVersion stdenv.cc.cc}/include \
      $NIX_CFLAGS_COMPILE \
    "

    build_dir=build/${name}
    build_dir_inverse=../..
    target_dir=build/target

    build() {
      setup && \
      (cd $build_dir && cargo test --no-run \
        --manifest-path ${manifestPath} \
        --target ${rustTargetName} --features icecap \
        ${lib.optionalString (!debug) "--release"} \
        -j$NIX_BUILD_CORES \
        --target-dir $build_dir_inverse/$target_dir \
        "$@"
      ) && \
      distinguish
    }

    setup() {
      mkdir -p $build_dir/.cargo
      ln -sf ${cargoConfig} $build_dir/.cargo/config
    }

    # cargo test --no-run doesn't give the test binary a predictable filename, so we have to find it ourselves
    distinguish() {
      d=$target_dir/${rustTargetName}/${if debug then "debug" else "release"}/deps
      f="$(find $d -executable -type f -name "${crateUtils.kebabToSnake name}-*" -printf "%T@ %p\n" \
        | sort -n \
        | tail -n 1 \
        | cut -d ' ' -f 2 \
      )"
      mkdir -p $build_dir/out
      ln -sf ../"$f" $build_dir/out/${name}
    }
  '';

})
