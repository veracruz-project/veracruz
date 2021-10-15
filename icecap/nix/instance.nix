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

  sshPort = "6666"; # on emulated machine
  readyPort = "6667"; # on development machine

in lib.fix (self: with self; {

  inherit configured;

  inherit proxyAttestationServerTestDatabase testElf;

  runTests = pkgs.dev.writeScript "run-test.sh" ''
    #!${pkgs.dev.runtimeShell}
    set -e

    cleanup() {
      kill $(jobs -p)
    }

    trap "exit" INT TERM
    trap "cleanup" EXIT

    ${runAuto}/run < /dev/null &

    ${pkgs.dev.netcat}/bin/nc -l ${readyPort} < /dev/null

    ${pkgs.dev.openssh}/bin/ssh \
      -o UserKnownHostsFile=/dev/null \
      -o StrictHostKeyChecking=no \
      -o Preferredauthentications=publickey \
      -i ${toString ./host/token-ssh-keys/client.priv} root@localhost -p ${sshPort} \
      /run-tests
  '';

  run = { automate ? false }:
    assert automate -> icecapPlat == "virt";
    platUtils.${icecapPlat}.bundle {
      firmware = icecapFirmware.image;
      payload = icecapFirmware.mkDefaultPayload {
        linuxImage = linuxKernel.host.${icecapPlat}.kernel;
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

          # NOTE use this to avoid noisy warnings due to poor perf in CI environment
          # "rcupdate.rcu_cpu_stall_suppress=1"
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

  icecapWrapperCrate = configured.callPackage ../src/rust/icecap-wrapper/cargo.nix {};

  icecapCrates = lib.attrValues (crateUtils.closure icecapWrapperCrate);

  icecapCratesEnv = crateUtils.collectEnv icecapCrates;

  env = {
    runtime-manager = configured.callPackage ./env/runtime-manager.nix {
      inherit icecapCrates libc-supplement;
    };
    veracruz-server-test = pkgs.linux.icecap.callPackage ./env/host-test-generic.nix {} {
      name = "veracruz-server-test";
    };
    veracruz-test = pkgs.linux.icecap.callPackage ./env/host-test-generic.nix {} {
      name = "veracruz-test";
    };
    sdk-and-test-collateral = pkgs.dev.icecap.callPackage ./env/sdk-and-test-collateral.nix {};
  };

  libc-supplement = configured.libs.mk {
    name = "c-supplement";
    root = icecapSrc.absoluteSplit ../src/c/libc-supplement;
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
