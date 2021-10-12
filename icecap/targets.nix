# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

let
  topLevel = import ./nix;
  inherit (topLevel) lib veracruz;

in lib.flip lib.mapAttrs veracruz (_plat: attrs: {
  crates = attrs.icecapCratesEnv;
  runtime-manager = attrs.env.runtime-manager;
  veracruz-server-test = attrs.env.veracruz-server-test;
  veracruz-test = attrs.env.veracruz-test;
  test-resources = attrs.env.test-resources;
  test-system = attrs.runManual;
})
