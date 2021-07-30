#!/usr/bin/env python3
#
# ## Authors
#
# The Veracruz Development Team.
#
# ## Licensing and copyright notice
#
# See the `LICENSE.markdown` file in the Veracruz root directory for
# information on licensing and copyright.
#

import struct
import collections as co
import sys

TIMESTAMP = 1619580492
LOCATIONS = [
    (30.245633363333095, -97.75153437304053),
    (30.222367321649394, -97.84045833888852),
    (30.371553081578483, -97.756234602064),
    (30.293773789031352, -97.74172587073012),
    (30.236512828524855, -97.76291564214209),
    (30.26576811133889,  -97.7496372275359),
    (30.457328895861682, -97.82552717096148),
]

def dump_samples(samples, width=76, height=16):
    max_ = max(samples)
    min_ = min(samples)
    grid = set()

    slice = len(samples) // width
    for i in range(width):
        for j in range(slice):
            y = samples[i*slice+j]
            grid.add((i, (height*(y-min_))//(max_-min_)))

    for y in range(0, height, 2):
        for x in range(width):
            if (x, y) in grid and (x, y+1) in grid:
                sys.stdout.write(':')
            elif (x, y) in grid:
                sys.stdout.write('\'')
            elif (x, y+1) in grid:
                sys.stdout.write('.')
            else:
                sys.stdout.write(' ')
        print()

def avg(xs):
    return sum(xs) // len(xs)

def main(args):
    # parse wave file
    with open(args.claps, 'rb') as f:
        wav = f.read()

    # info from here (very useful)
    # http://soundfile.sapp.org/doc/WaveFormat/
    assert wav[0:4]  == b'RIFF'
    assert wav[8:12] == b'WAVE'

    assert wav[12:16] == b'fmt '
    assert struct.unpack('<I', wav[16:20])[0] == 16 # size of subchunk header
    assert struct.unpack('<H', wav[20:22])[0] == 1  # audio format (PCM)
    channels = struct.unpack('<H', wav[22:24])[0]
    bitrate  = struct.unpack('<I', wav[24:28])[0]
    bitwidth = struct.unpack('<H', wav[34:36])[0]

    print('parsing %s, %d channels, %d-bits @ %d Hz' % (
        args.claps, channels, bitwidth, bitrate))

    assert wav[36:40] == b'data'
    assert channels == 2
    assert bitwidth == 16
    samples = [struct.unpack('<h2x', wav[i:i+4])[0]
        for i in range(44, len(wav), 4)]

    if args.debug:
        print('raw:')
        dump_samples(samples)

    # downsample?
    if args.bitrate:
        slice = bitrate // args.bitrate
#        samples = [samples[i]
#            for i in range(0, len(samples), slice)]
        samples = [avg(samples[i:i+slice])
            for i in range(0, len(samples), slice)]
        old_bitrate, bitrate = bitrate, args.bitrate

        if args.debug:
            print('downsampled %d Hz -> %d Hz:' % (old_bitrate, bitrate))
            dump_samples(samples)

    # find claps
    claps = []
    for j in range(args.clap_count or args.clap+4):
        clap = max((abs(x), i) for i, x in enumerate(samples))[1]
        before = max(clap-args.samples_before, 0)
        after  = min(clap+args.samples_after, len(samples))
        clap_samples = samples[before:after]
        if args.debug:
            print('clap %d @ %d:' % (j, clap))
            dump_samples(clap_samples)

        for i in range(before, after):
            samples[i] = 0

        claps.append(clap_samples)
    
    if args.header:
        print('generating %s' % args.header)
        with open(args.header, 'w') as f:
            _write = f.write
            def write(s='', **args):
                _write(s % args)
            def writeln(s='', **args):
                _write(s % args)
                _write('\n')
            f.write = write
            f.writeln = writeln

            f.writeln('//// AUTOGENERATED ////')
            f.writeln('#ifndef CLAP_H')
            f.writeln('#define CLAP_H')
            f.writeln()
            f.writeln('#include <stdint.h>')
            f.writeln()
            f.writeln('// clap audio sample')
            f.writeln('extern const int16_t _CLAP_SAMPLES[%(len)d];',
                len=len(claps[-1]))
            f.writeln('#define CLAP_SAMPLES _CLAP_SAMPLES')
            f.writeln()
            f.writeln('// other metadata useful for triangulation')
            f.writeln('#define CLAP_TIMESTAMP %(timestamp)d',
                timestamp=TIMESTAMP)
            f.writeln('#define CLAP_LOCATION_Y (%(location_y)d)',
                location_y=1024*1024*LOCATIONS[args.clap][0])
            f.writeln('#define CLAP_LOCATION_X (%(location_x)d)',
                location_x=1024*1024*LOCATIONS[args.clap][1])
            f.writeln()
            f.writeln('// name used by Veracruz')
            f.writeln('#define CLAP_DATA_NAME "input-%(clap)d"',
                clap=args.clap)
            f.writeln()
            f.writeln('// delay used for demos')
            f.writeln('#define DELAY %(delay)d',
                delay=args.delay)
            f.writeln()
            f.writeln('#endif')

    if args.source:
        print('generating %s' % args.source)
        with open(args.source, 'w') as f:
            _write = f.write
            def write(s='', **args):
                _write(s % args)
            def writeln(s='', **args):
                _write(s % args)
                _write('\n')
            f.write = write
            f.writeln = writeln

            f.writeln('//// AUTOGENERATED ////')
            f.writeln()
            f.writeln('#include <stdint.h>')
            f.writeln()
            f.writeln('const int16_t _CLAP_SAMPLES[%(len)d] = {',
                len=len(claps[-1]))
            for i in range(0, len(claps[-1])):
                f.writeln('    %(sample)d,', sample=claps[-1][i])
            f.writeln('};')

if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(
        description='Generate header file containing clap audio samples')
    parser.add_argument('claps',
        help='Wave/PCM file containing claps (.wav)')
    parser.add_argument('-b', '--bitrate', type=int,
        help='Wanted bitrate')
    parser.add_argument('-c', '--clap', type=int, default='0',
        help='Clap index')
    parser.add_argument('-C', '--clap-count', type=int,
        help='Clap count')
    parser.add_argument('-B', '--samples-before', type=int, default='300',
        help='Samples before peaks')
    parser.add_argument('-A', '--samples-after', type=int, default='900',
        help='Samples after peaks')
    parser.add_argument('-d', '--debug', action='store_true',
        help='Show found claps')
    parser.add_argument('--delay', type=int, default='0',
        help='Delay (used for demos)')
    parser.add_argument('--header',
        help='Output header file (.h)')
    parser.add_argument('--source',
        help='Output source file (.c)')
    args = parser.parse_args()
    main(args)