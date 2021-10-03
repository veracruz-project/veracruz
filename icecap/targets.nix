with import ./nix;

{
  crates = virt.icecapCratesEnv;
  runtime-manager = virt.env.runtime-manager;
  veracruz-server-test = virt.env.veracruz-server-test;
  veracruz-test = virt.env.veracruz-test;
  test-system = virt.run;
}
