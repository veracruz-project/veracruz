{ lib, pkgs, configured }:

let

  inherit (pkgs.dev) runCommand nukeReferences;
  inherit (pkgs.none.icecap) icecapSrc crateUtils elfUtils platUtils;
  inherit (pkgs.linux.icecap) linuxKernel nixosLite;

  inherit (configured)
    icecapFirmware icecapPlat selectIceCapPlatOr
    mkIceDL mkDynDLSpec
    globalCrates;

  now = builtins.readFile ../build/NOW;

  runtimeManagerElf = ../build/runtime-manager/out/runtime_manager_enclave.elf;

  testElf = {
    veracruz-server-test = ../build/veracruz-server-test/out/veracruz-server-test;
    veracruz-test = ../build/veracruz-test/out/veracruz-test;
  };

  proxyAttestationServerTestDatabase = ../../test-collateral/proxy-attestation-server.db;

in lib.fix (self: with self; {

  inherit configured;

  inherit proxyAttestationServerTestDatabase testElf;

  run = platUtils.${icecapPlat}.bundle {
    firmware = icecapFirmware.image;
    payload = icecapFirmware.mkDefaultPayload {
      linuxImage = pkgs.linux.icecap.linuxKernel.host.${icecapPlat}.kernel;
      initramfs = hostUser.config.build.initramfs;
      bootargs = [
        "earlycon=icecap_vmm"
        "console=hvc0"
        "loglevel=7"
      ] ++ lib.optionals (icecapPlat == "virt") [
        "spec=${spec}"
        "test_collateral=${testCollateral}"
      ];
    };
    platArgs = selectIceCapPlatOr {} {
      rpi4 = {
        extraBootPartitionCommands = ''
          ln -s ${spec} $out/spec.bin
          ln -s ${testCollateral} $out/test-collateral
        '';
      };
    };
  };

  hostUser = nixosLite.eval {
    modules = [
      (import ./host/config.nix {
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
        runtime_manager.image = elfUtils.split runtimeManagerElf;
      };
    };
  };

  icecapCrates = lib.attrValues (crateUtils.closure' (with globalCrates; [
    icecap-core
    icecap-start-generic
    icecap-std-external
    icecap-event-server-types
    biterate
  ]));

  icecapCratesEnv = crateUtils.collectEnv icecapCrates;

  env = {
    runtime-manager = configured.callPackage ./realm/runtime-manager.nix {
      inherit icecapCrates fakeLibc;
    };
    veracruz-server-test = pkgs.linux.icecap.callPackage ./host/test.nix {} {
      name = "veracruz-server-test";
    };
    veracruz-test = pkgs.linux.icecap.callPackage ./host/test.nix {} {
      name = "veracruz-test";
    };
  };

  fakeLibc = configured.libs.mk {
    name = "fake-libc";
    root = icecapSrc.absoluteSplit ./realm/fake-libc;
    propagatedBuildInputs = [
      configured.libs.icecap-pure
      configured.libs.icecap-utils
    ];
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

})
