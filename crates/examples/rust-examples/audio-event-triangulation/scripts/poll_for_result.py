#!/usr/bin/env python3
#
# Poll for audio event triangulation results
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSE.md` file in the Veracruz root directory for
# licensing and copyright information.

import argparse
import json
import re
import struct
import subprocess as sp
import sys
import time

# Convert pair of signed 32-bit latitude+longitude coordinates into
# a human readable representation
def dump_gps(location):
    absy = abs(location[0])
    absx = abs(location[1])
    return '%d°%02d\'%02d.%02d"%c %d°%02d\'%02d.%02d"%c' % (
        absy / (1024*1024),
        (absy / (1024*1024/60)) % 60,
        (absy / (1024*1024/60/60)) % 60,
        (absy / (1024*1024/60/60/100)) % 100,
        'N' if location[0] >= 0 else 'S',
        absx / (1024*1024),
        (absx / (1024*1024/60)) % 60,
        (absx / (1024*1024/60/60)) % 60,
        (absx / (1024*1024/60/60/100)) % 100,
        'E' if location[1] >= 0 else 'W')

def main(args):
    # grab server addresses from policy file
    with open(args.policy) as f:
        policy_json = json.load(f)

    print('\033[0;32mstarting audio event triangulation service\033[m')
    print('veracruz_server: %s' % policy_json['veracruz_server_url'])
    print('proxy_attestation_server: %s' % policy_json['proxy_attestation_server_url'])
    print('waiting for triangulation results...')

    # poll until Veracruz returns a successful computation
    while True:
        try:
            output = sp.check_output([
                'vc-client',
                    args.policy,
                    '--identity', args.identity,
                    '--key', args.key,
                    '--program', 'audio-event-triangulation.wasm=' + args.program,
                    '--output', 'audio-event-triangulation.wasm=-'])
        except sp.CalledProcessError:
            time.sleep(5)
            continue 

        # strip debug info
        output = re.sub(rb'post.*?\n', b'', output)

        # decode found coordinates
        location = struct.unpack('<ii', output)
        print()
        print('\033[1;33maudio event detected!\033[0m')
        print('\033[1;33mlocation:\033[0m %s' % dump_gps(location))
        print('\033[1;33mtimestamp:\033[0m %u' % int(time.time()))
        print()

        break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Poll for audio event triangulation results')
    parser.add_argument('policy',
        help='Veracruz policy file (.json)')
    parser.add_argument('--identity', required=True,
        help='Identity of client (.pem)')
    parser.add_argument('--key', required=True,
        help='Private key of client (.pem)')
    parser.add_argument('--program', required=True,
        help='Path to audio event triangulation binary (.wasm)')
    args = parser.parse_args()
    main(args)
