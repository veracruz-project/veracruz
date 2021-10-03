let
  topLevel = import ./nix;
  inherit (topLevel) lib veracruz;

in lib.flip lib.mapAttrs veracruz (_plat: attrs: {
  crates = attrs.icecapCratesEnv;
  runtime-manager = attrs.env.runtime-manager;
  veracruz-server-test = attrs.env.veracruz-server-test;
  veracruz-test = attrs.env.veracruz-test;
  test-system = attrs.run;
})
