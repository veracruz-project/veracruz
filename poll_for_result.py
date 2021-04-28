#!/usr/bin/env python3

import subprocess as sp
import re
import struct
import time

def dump_gps(location):
    absy = abs(location[0])
    absx = abs(location[1])
    return '%d°%02d′%02d.%02d″%c %d°%02d′%02d.%02d″%c' % (
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

def main():
    print('\033[0;32mstarting audio event triangulation service\033[m')
    print('veracruz_server: 172.17.0.2:3010')
    print('proxy_attestation_server: 172.17.0.2:3017')
    print('waiting for triangulation results...')

    while True:
        try:
            output = sp.check_output([
                './bin/durango',
                'example/example-policy.json',
                '--target', 'sgx',
                '--key', 'example/example-result-key.pem',
                '--identity', 'example/example-result-cert.pem',
                '--output', 'example-binary.wasm:-'],
                stderr=sp.DEVNULL)
        except sp.CalledProcessError:
            time.sleep(5)
            continue 

        # strip debug info
        #output = re.sub(rb'\[.*?\n', b'', output)
        output = re.sub(rb'post.*?\n', b'', output)

        # decode found coordinates
        location = struct.unpack('<ii', output)
        print()
        print('\033[1;33maudio event detected!\033[0m')
        print('\033[1;33mlocation:\033[0m %s' % dump_gps(location))
        print('\033[1;33mtimestamp:\033[0m %u' % int(time.time()))

        while True:
            time.sleep(5)

        return

if __name__ == "__main__":
    import sys
    main(*sys.argv[1:])
