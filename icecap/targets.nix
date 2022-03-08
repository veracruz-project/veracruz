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
  inherit (topLevel.framework) lib;
  inherit (topLevel) veracruz;

in lib.flip lib.mapAttrs veracruz (_plat: attrs: {
  test-system = attrs.runManual;
  run-tests = attrs.runTests;
  inherit (attrs) env;
})
