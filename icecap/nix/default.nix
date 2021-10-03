let
  icecapRemote = builtins.fetchGit rec {
    url = "https://gitlab.com/arm-research/security/icecap/icecap.git";
    ref = "veracruz";
    rev = "2fdddf0f082f7cd8e132455ae9277ff836ea14cf";
    submodules = true;
  };

  icecapLocal = ../../../icecap;

  icecapSource = icecapRemote;
  # icecapSource = icecapLocal;

  icecap = import icecapSource;

  instances = with icecap; lib.flip lib.mapAttrs pkgs.none.icecap.configured (_: configured:
    import ./instance.nix {
      inherit lib pkgs configured;
    }
  );

in icecap // instances
