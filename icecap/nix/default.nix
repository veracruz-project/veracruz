# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

let
  icecapRemote = builtins.fetchGit rec {
    url = "https://gitlab.com/arm-research/security/icecap/icecap.git";
    ref = "veracruz";
    rev = "aa47154739c5d90cdbd2d6a64ba3bb30d545c535";
    submodules = true;
  };

  icecapLocal = ../../../icecap;

  icecapSource = icecapRemote;

  # NOTE to develop using a local checkout of IceCap, replace the above with:
  # icecapSource = icecapLocal;

  icecap = import icecapSource;

  veracruz = with icecap; lib.flip lib.mapAttrs pkgs.none.icecap.configured (_: configured:
    import ./instance.nix {
      inherit lib pkgs configured;
    }
  );

in icecap // {
  inherit veracruz;
}
