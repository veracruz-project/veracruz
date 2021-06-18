{ icecapPlat, instance, now }:

{ config, pkgs, lib, ... }:

let
  executableInContext = name: file: pkgs.runCommand "veracruz-server-test" {} ''
    mkdir -p $out/bin
    cp ${file} $out/bin/${name}
  '';

in {
  config = {

    net.interfaces = lib.optionalAttrs (icecapPlat == "virt") {
      eth1 = {};
      lo = { static = "127.0.0.1"; };
    };

    initramfs.extraInitCommands = ''
      mkdir -p /etc /bin /mnt/nix/store
      ln -s $(which sh) /bin/sh
      mount -t debugfs none /sys/kernel/debug/

    '' + lib.optionalString (icecapPlat == "virt") ''
      mount -t 9p -o trans=virtio,version=9p2000.L,ro store /mnt/nix/store/
      spec="$(sed -rn 's,.*spec=([^ ]*).*,\1,p' /proc/cmdline)"
      echo "cp -L /mnt/$spec /spec.bin..."
      cp -L "/mnt/$spec" /spec.bin
      echo "...done"

    '' + lib.optionalString (icecapPlat == "rpi4") ''
      (
        cd /sys/devices/system/cpu/cpu0/cpufreq/
        echo userspace > scaling_governor
        echo 1500000 > scaling_setspeed
      )

      mount -o ro /dev/mmcblk0p1 mnt/
      ln -s /mnt/spec.bin /spec.bin
    '' + ''

      mkdir /x
      cp ${instance.proxyAttestationServerTestDatabase} /x/proxy-attestation-server.db

      test_collateral="$(sed -rn 's,.*test_collateral=([^ ]*).*,\1,p' /proc/cmdline)"
      ln -s "/mnt/$test_collateral" /test-collateral

      date -s '@${now}' # HACK
    '';

    initramfs.extraUtilsCommands = ''
      ${lib.concatStrings (lib.mapAttrsToList (k: v: ''
        copy_bin_and_libs ${executableInContext k v}/bin/${k}
      '') instance.testElf)}

      cp -pdv ${pkgs.sqlite.out}/lib/libsqlite3.so* $out/lib # HACK

      copy_bin_and_libs ${pkgs.icecap.icecap-host}/bin/icecap-host

      # debugging tools
      copy_bin_and_libs ${pkgs.strace}/bin/strace
      copy_bin_and_libs ${pkgs.iproute}/bin/ip
      copy_bin_and_libs ${pkgs.curl.bin}/bin/curl
      cp -pdv ${pkgs.libunwind}/lib/libunwind-aarch64*.so* $out/lib
      cp -pdv ${pkgs.glibc}/lib/libnss_dns*.so* $out/lib
    '';

    initramfs.profile = ''
      run_test() {

        test_cmd=$1
        shift

        cd /x

        RUST_LOG=debug \
        DATABASE_URL=proxy-attestation-server.db \
        VERACRUZ_RESOURCE_SERVER_ENDPOINT=file:/dev/rb_resource_server \
        VERACRUZ_REALM_ID=0 \
        VERACRUZ_REALM_SPEC=/spec.bin \
        VERACRUZ_REALM_ENDPOINT=/dev/rb_realm \
          $test_cmd --test-threads=1 "$@"
      }

      # convenience

      vst() {
        run_test veracruz-server-test
      }

      vt() {
        run_test veracruz-test
      }
    '';

  };
}
