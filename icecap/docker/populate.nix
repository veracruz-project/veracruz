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

  inherit (pkgs.dev) runCommand nukeReferences;
  inherit (pkgs.none.icecap) platUtils;
  inherit (pkgs.linux.icecap) linuxKernel nixosLite;
  inherit (pkgs.musl.icecap) icecap-host;
  inherit (configured) icecapFirmware icecapPlat;

  hostUser = nixosLite.eval {
    modules = [];
  };

  run = platUtils.${icecapPlat}.bundle {
    firmware = icecapFirmware.image;
    payload = icecapFirmware.mkDefaultPayload {
      linuxImage = linuxKernel.host.${icecapPlat}.kernel;
      initramfs = hostUser.config.build.initramfs;
      bootargs = [];
    };
  };

  roots = [
    run
    icecap-host
    pkgs.dev.icecap.rustc
    pkgs.dev.icecap.cargo

    # extra
    pkgs.linux.dropbear
  ];

in
pkgs.dev.writeText "cache-roots" (toString roots)
