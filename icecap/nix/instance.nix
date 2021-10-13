# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

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

  sshPort = "6666";
  readyPort = "6667";

in lib.fix (self: with self; {

  inherit configured;

  inherit proxyAttestationServerTestDatabase testElf;

  runTests = pkgs.dev.writeScript "run-test.sh" ''
    #!${pkgs.dev.runtimeShell}
    set -e

    trap "exit" INT TERM
    trap "kill 0" EXIT

    ${runAuto}/run < /dev/null &

    ${pkgs.dev.netcat}/bin/nc -l ${readyPort} < /dev/null
    echo "dev: ready"

    ${pkgs.dev.openssh}/bin/ssh \
      -o UserKnownHostsFile=/dev/null \
      -o StrictHostKeyChecking=no \
      -o Preferredauthentications=publickey \
      -i ${toString ./keys/dev.priv} root@localhost -p ${sshPort} \
      /run-tests
  '';

  run = { automate ? false }:
    platUtils.${icecapPlat}.bundle {
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
        ] ++ lib.optionals automate [
          "automate=1"
        ];
      };
      platArgs = selectIceCapPlatOr {} {
        virt = {
          extraNetDevArgs = "hostfwd=tcp::${sshPort}-:22";
        };
        rpi4 = {
          extraBootPartitionCommands = ''
            ln -s ${spec} $out/spec.bin
            ln -s ${testCollateral} $out/test-collateral
          '';
        };
      };
    };

  runAuto = run { automate = true; };
  runManual = run { automate = false; };

  hostUser = nixosLite.eval {
    modules = [
      (import ./host/config.nix {
        inherit icecapPlat now readyPort;
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
        runtime_manager.heap_size = 64 * 1048576; # 64M (HACK overstimate)
      };
    };
  };

  icecapWrapperCrate = configured.callPackage ./realm/icecap-wrapper/cargo.nix {};

  icecapCrates = lib.attrValues (crateUtils.closure icecapWrapperCrate);

  icecapCratesEnv = crateUtils.collectEnv icecapCrates;

  env = {
    runtime-manager = configured.callPackage ./realm/runtime-manager.nix {
      inherit icecapCrates libc-supplement;
    };
    veracruz-server-test = pkgs.linux.icecap.callPackage ./host/test.nix {} {
      name = "veracruz-server-test";
    };
    veracruz-test = pkgs.linux.icecap.callPackage ./host/test.nix {} {
      name = "veracruz-test";
    };
    test-resources = pkgs.dev.icecap.callPackage ./host/test-resources.nix {};
  };

  libc-supplement = configured.libs.mk {
    name = "c-supplement";
    root = icecapSrc.absoluteSplit ./realm/libc-supplement;
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
    filter = name: type:
      type == "directory" || (
        lib.any (pattern: builtins.match pattern name != null) [
          ".*\\.json"
          ".*\\.pem"
          ".*\\.wasm"
          ".*\\.dat"
        ] &&
        lib.all (pattern: builtins.match pattern name == null) ([
          "^\\..*"
          ".*/\\..*"
        ] ++ lib.optionals (icecapPlat == "rpi4") [
          # HACK ':' not allowed in FAT file names
          ".*:.*"
        ])
      );
  };

})
