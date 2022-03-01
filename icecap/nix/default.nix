# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

# FIXME: This file is duplicated at workspaces/icecap-host/nix/default.nix

let
  icecap = import ../icecap;

  veracruz = with icecap; lib.flip lib.mapAttrs pkgs.none.icecap.configured (_: configured:
    import ./instance.nix {
      inherit lib pkgs configured;
    }
  );

in icecap // {
  inherit veracruz;
}
