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
  runtime-manager-supervisor = attrs.env.runtime-manager-supervisor;
  veracruz-server-test = attrs.env.veracruz-server-test;
  veracruz-test = attrs.env.veracruz-test;
  sdk = attrs.env.sdk-and-test-collateral;
  test-collateral = attrs.env.sdk-and-test-collateral;
  test-system = attrs.runManual;
  run-tests = attrs.runTests;
  veracruz-server = attrs.env.veracruz-server;
  proxy-attestation-server = attrs.env.proxy-attestation-server;
  veracruz-client = attrs.env.veracruz-client;
  run-server = attrs.runServer;
  run-bench = attrs.runBench;
})
