with import ../nix;

let
  roots = [
    # HACK
    icecap.instances.virt.demos.realm-vm.run
    icecap.instances.virt.demos.realm-vm.cscope.sysroot-rs
  ];

in
icecap.dev.writeText "root" (toString roots)
