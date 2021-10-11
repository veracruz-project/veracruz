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
    url = "https://gitlab.com/arm-research/security/icecap/icecap-refs.git";
    ref = "refs/tags/icecap/keep/${builtins.substring 0 32 rev}";
    rev = "e3c8980f6d301b9f340ad859caef511696c18ba3";
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
