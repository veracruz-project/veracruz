# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

{ crateUtils, globalCrates, icecapSrc }:

crateUtils.mkCrate {
  nix.name = "icecap-wrapper";
  nix.src = icecapSrc.absoluteSplit ./src;
  nix.localDependencies = with globalCrates; [
    icecap-core
    icecap-start-generic
    icecap-std-external
    icecap-event-server-types
  ];
}
