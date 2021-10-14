let
  icecapRemote = builtins.fetchGit rec {
    url = "https://gitlab.com/arm-research/security/icecap/icecap-refs.git";
    ref = "refs/tags/icecap/keep/${builtins.substring 0 32 rev}";
    rev = builtins.getEnv "ICECAP_REV";
    submodules = true;
  };

  icecapLocal = ../../../icecap;

  icecapSource = icecapRemote;

  # NOTE to develop using a local checkout of IceCap, replace the above with:
  # icecapSource = icecapLocal;

  icecap = import icecapSource;

in with icecap;
let

  configured = pkgs.none.icecap.configured.virt;

  inherit (configured) icecapFirmware icecapPlat mkDynDLSpec mkIceDL;
  inherit (pkgs.dev) writeText linkFarm;
  inherit (pkgs.none.icecap) platUtils;
  inherit (pkgs.linux.icecap) linuxKernel nixosLite;

  run = platUtils.${icecapPlat}.bundle {
    firmware = icecapFirmware.image;
    payload = icecapFirmware.mkDefaultPayload {
      linuxImage = linuxKernel.host.${icecapPlat}.kernel;
      initramfs = hostUser.config.build.initramfs;
      bootargs = [];
    };
  };

  hostUser = nixosLite.eval {
    modules = [];
  };

  spec = mkDynDLSpec {
    cdl = "${ddl}/icecap.cdl";
    root = "${ddl}/links";
  };

  ddl = mkIceDL {
    src = ./cdl;
    config = {
      components = {
      };
    };
  };

  roots = [
    run
    spec
    pkgs.dev.icecap.rustc
    pkgs.dev.icecap.cargo
    pkgs.musl.icecap.icecap-host
    pkgs.linux.dropbear
    configured.sysroot-rs
    configured.icecap-sel4-sys-gen
    configured.liboutline
  ];

in
writeText "cache-roots" (toString roots)
