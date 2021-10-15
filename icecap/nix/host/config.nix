# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

{ icecapPlat, now, readyPort, instance }:

{ config, pkgs, lib, ... }:

let
  qemuHostAddr = "10.0.2.2";

  executableInContext = name: file: pkgs.runCommand name {} ''
    mkdir -p $out/bin
    cp ${file} $out/bin/${name}
  '';

  run-test = pkgs.writeScript "run-test.sh" ''
    #!${config.build.extraUtils}/bin/sh
    set -eu

    test_cmd=$1
    shift

    RUST_LOG=info \
    DATABASE_URL=$VERACRUZ_DATABASE_URL \
    VERACRUZ_ICECAP_REALM_ID=0 \
    VERACRUZ_ICECAP_REALM_SPEC=$VERACRUZ_REALM_SPEC \
    VERACRUZ_ICECAP_REALM_ENDPOINT=/dev/icecap_channel_realm_$VERACRUZ_ICECAP_REALM_ID \
    VERACRUZ_POLICY_DIR=$VERACRUZ_TEST_COLLATERAL \
    VERACRUZ_TRUST_DIR=$VERACRUZ_TEST_COLLATERAL \
    VERACRUZ_PROGRAM_DIR=$VERACRUZ_TEST_COLLATERAL \
    VERACRUZ_DATA_DIR=$VERACRUZ_TEST_COLLATERAL \
      $test_cmd --test-threads=1 --nocapture --show-output "$@"
  '';

  run-tests = pkgs.writeScript "run-tests.sh" ''
    #!${config.build.extraUtils}/bin/sh
    set -eu

    . /env.sh

    /run-test veracruz-test
    /run-test veracruz-server-test
  '';

in {
  config = lib.mkMerge [

    {
      initramfs.extraUtilsCommands = ''
        ${lib.concatStrings (lib.mapAttrsToList (k: v: ''
          copy_bin_and_libs ${executableInContext k v}/bin/${k}
        '') instance.testElf)}

        # dependency of veracruz-{server-,}test that isn't picked up by copy_bin_and_libs
        cp -pdv ${pkgs.sqlite.out}/lib/libsqlite3.so* $out/lib

        copy_bin_and_libs ${pkgs.muslPkgs.icecap.icecap-host}/bin/icecap-host
        copy_bin_and_libs ${pkgs.dropbear}/bin/dropbear

        copy_bin_and_libs ${pkgs.strace}/bin/strace
        copy_bin_and_libs ${pkgs.iproute}/bin/ip
        copy_bin_and_libs ${pkgs.curl.bin}/bin/curl
        copy_bin_and_libs ${pkgs.glibc.bin}/bin/locale
        copy_bin_and_libs ${pkgs.glibc.bin}/bin/localedef
        cp -pdv ${pkgs.libunwind}/lib/libunwind-aarch64*.so* $out/lib
        cp -pdv ${pkgs.glibc}/lib/libnss_*.so* $out/lib
      '';

      net.interfaces = {
        lo = { static = "127.0.0.1"; };
      };

      initramfs.extraInitCommands = ''
        mount -t debugfs none /sys/kernel/debug/

        mkdir -p /bin
        ln -s $(which sh) /bin/sh

        echo "root:x:0:0:root:/root:/bin/sh" > /etc/passwd
        mkdir -p /root/.ssh
        ln -s ${./token-ssh-keys}/client.pub /root/.ssh/authorized_keys
        export HOME=/root

        date -s '@${now}'

        ln -s ${run-test} /run-test
        ln -s ${run-tests} /run-tests

        (
          d=/x
          mkdir $d

          cat <<EOF > /env.sh
          export VERACRUZ_REALM_SPEC=$d/spec.bin
          export VERACRUZ_TEST_COLLATERAL=$d/test-collateral
          export VERACRUZ_DATABASE_URL=$d/proxy-attestation-server.db
        # de-dent for heredoc:
        EOF
        )

        . /env.sh
      '';
    }

    (lib.mkIf (icecapPlat == "virt") {
      net.interfaces.eth2 = {};

      initramfs.extraInitCommands = ''
        mkdir -p /mnt/nix/store/
        mount -t 9p -o trans=virtio,version=9p2000.L,ro store /mnt/nix/store/
        spec_src=/mnt/$spec
        test_collateral_src=/mnt/$test_collateral
      '';
    })

    (lib.mkIf (icecapPlat == "rpi4") {
      initramfs.extraInitCommands = ''
        for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
          echo performance > $f
        done

        sleep 2 # HACK wait for sd card
        mkdir /mnt/
        mount -o ro /dev/mmcblk0p1 /mnt/
        spec_src=/mnt/spec.bin
        test_collateral_src=/mnt/test-collateral
      '';
    })

    {
      initramfs.extraInitCommands = ''
        cp -L $spec_src $VERACRUZ_REALM_SPEC
        ln -s $test_collateral_src $VERACRUZ_TEST_COLLATERAL
        cp ${instance.proxyAttestationServerTestDatabase} $VERACRUZ_DATABASE_URL

        if [ "$automate" = "1" ]; then
          dropbear -Es -r ${./token-ssh-keys}/dropbear_ecdsa_server_key -p 0.0.0.0:22
          nc ${qemuHostAddr} ${readyPort} < /dev/null
        fi
      '';

      initramfs.profile = ''
        vt() {
          /run-test veracruz-test
        }

        vst() {
          /run-test veracruz-server-test
        }
      '';
    }

  ];

}
