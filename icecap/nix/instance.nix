{ lib, runCommand
, nukeReferences
, icecapPlat, pkgs_linux
, nixosLite, linuxKernel, uBoot
, mkIceDL, mkDynDLSpec, stripElfSplit
, crateUtils, globalCrates
, mkInstance
}:

let
  host2Stage = false;

  runtimeManagerEnclaveElf = ../build/runtime-manager/out/runtime_manager_enclave.elf;

  testElf = {
    veracruz-server-test = ../build/veracruz-server-test/out/veracruz-server-test;
    veracruz-test = ../build/veracruz-test/out/veracruz-test;
  };

  proxyAttestationServerTestDatabase = ../../veracruz-server-test/proxy-attestation-server.db;

  now = builtins.readFile ../build/NOW;

in
mkInstance (self: with self; {

  inherit proxyAttestationServerTestDatabase testElf;

  payload = uBoot.${icecapPlat}.mkDefaultPayload {
    dtb = composition.host-dtb;
    linuxImage = linuxKernel.host.${icecapPlat}.kernel;
    initramfs = (if host2Stage then nx2Stage else nx1Stage).config.build.initramfs;
    bootargs = [
      "earlycon=icecap_vmm"
      "console=hvc0"
      "loglevel=7"
    ] ++ (if host2Stage then [
      "next_init=${nx2Stage.config.build.nextInit}"
    ] else [
      "spec=${spec}"
      "test_collateral=${testCollateral}"
    ]);
  };

  icecapPlatArgs.rpi4.extraBootPartitionCommands = ''
    ln -s ${spec} $out/spec.bin
    ln -s ${test-collateral} $out/test-collateral
  '';

  nx1Stage = pkgs_linux.nixosLite.mk1Stage {
    modules = [
      (import ./host/1-stage/config.nix {
        inherit icecapPlat now;
        instance = self;
      })
    ];
  };

  nx2Stage = pkgs_linux.nixosLite.mk2Stage {
    modules = [
      (import ./host/2-stage/config.nix {
        inherit icecapPlat now;
        instance = self;
      })
    ];
  };

  spec = mkDynDLSpec {
    cdl = "${ddl}/icecap.cdl";
    root = "${ddl}/links";
  };

  ddl = mkIceDL {
    src = ./realm/ddl;
    config = {
      components = {
        runtime_manager.image = stripElfSplit runtimeManagerEnclaveElf;
      };
    };
  };

  icecapCratesAttrs = crateUtils.flatDepsWithRoots (with globalCrates; [
    icecap-core
    icecap-start-generic
    icecap-std-external
    generated-module-hack
  ]);

  icecapCrates = crateUtils.collectLocal (lib.attrValues icecapCratesAttrs);

  env = {
    runtime-manager = callPackage ./binaries/runtime-manager.nix {};
    veracruz-server-test = pkgs_linux.icecap.callPackage ./binaries/test.nix {} {
      name = "veracruz-server-test";
    };
    veracruz-test = pkgs_linux.icecap.callPackage ./binaries/test.nix {} {
      name = "veracruz-test";
    };
  };

  testCollateral = runCommand "test-collateral" {
    nativeBuildInputs = [ nukeReferences ];
  } ''
    cp -r --no-preserve=mode,ownership ${testCollateralRaw} $out
    find $out -type d -empty -delete
    nuke-refs $out
  '';

  testCollateralRaw = lib.cleanSourceWith {
    src = lib.cleanSource ../../test-collateral;
    filter = name: type: type == "directory" || lib.any (pattern: builtins.match pattern name != null) [
      ".*\\.json"
      ".*\\.pem"
      ".*\\.wasm"
      ".*\\.dat"
    ];
  };

  test2Stage = lib.mapAttrs (k: v: pkgs_linux.writeScript "${k}.sh" ''
    #!${pkgs_linux.runtimeShell}
    cd /x
    ln -sf ${testCollateral} /test-collateral
    RUST_LOG=debug \
    DATABASE_URL=proxy-attestation-server.db \
    VERACRUZ_RESOURCE_SERVER_ENDPOINT=file:/dev/rb_resource_server \
    VERACRUZ_REALM_ID=0 \
    VERACRUZ_REALM_SPEC=${spec} \
    VERACRUZ_REALM_ENDPOINT=/dev/rb_realm \
      ${v} --test-threads=1 "$@"
  '') testElf;

})
