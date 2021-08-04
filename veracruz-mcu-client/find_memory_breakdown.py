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

import re
import itertools as it
import collections as co

# note the order matters here, earlier groups are matched first so
# should be more specific
GROUPS = [
    ('nanopb',  ['Tp', 'nanopb']),
    ('policy',  ['policy.c']),
    ('base64',  ['base64']),
    ('mbedtls', ['mbedtls']),
    ('net',     ['net']),
    ('vc',      ['vc']),
    ('main',    ['samples']),
    ('zephyr',  ['zephyr', 'kernel', 'os', 'drivers', 'arch']),
]


def find_static_groups(report_path):
    with open(report_path, encoding="utf-8") as report:
        # skip lines before ====
        for line in report:
            if re.match('^=+$', line):
                break

        scope = []
        groups = co.defaultdict(lambda: 0)
        total = 0

        # build up paths in ROM report
        for line in report:
            # skip lines after ====
            if re.match('^=+$', line):
                # last line should contain total
                total = int(next(report))
                break

            m = re.match('^([ ├└──│]*)([^ ]+) +([0-9]+)', line)
            if not m:
                continue

            depth = len(m.group(1))
            name = m.group(2)
            size = int(m.group(3))

            # remove prev from scope?
            while len(scope) > 0 and scope[-1][0] >= depth:
                pdepth, pname, psize = scope.pop()
                if psize > 0:
                    pfullname = '/'.join(it.chain(
                        (ppname for _, ppname, _ in scope),
                        [pname]))

                    for group, patterns in GROUPS:
                        if any(pattern in pfullname for pattern in patterns):
                            groups[group] += psize
                            break
                    else:
                        groups['misc'] += psize

                # remove size from parents?
                for i in range(len(scope)):
                    ppdepth, ppname, ppsize = scope[i]
                    scope[i] = (ppdepth, ppname, ppsize - psize)

            # add to scope?
            scope.append((depth, name, size))

    return groups, total


def find_dyn_groups(report_path):
    with open(report_path) as report:
        # first we should find the peak index
        peak = 0
        for line in report:
            m = re.search('([0-9]+) \(peak\)', line)
            if m:
                peak = int(m.group(1))
                break

        # now find the peak
        for line in report:
            m = re.match('^ +([0-9]+) +[0-9,]+ +([0-9,]+) +[0-9,]+ +[0-9,]+ +([0-9,]+)', line)
            if m:
                n = int(m.group(1))
                if n == peak:
                    heap_total = int(m.group(2).replace(',', ''))
                    stack_total = int(m.group(3).replace(',', ''))
                    break

        # following this is more details, parse
        heap_groups = co.defaultdict(lambda: 0)
        size = 0
        nested_lines = []

        for line in report:
            if re.match('->', line):
                # add previous parse
                if size > 0:
                    for group, patterns in GROUPS:
                        if any(pattern in nested_line
                                for pattern in patterns
                                for nested_line in nested_lines):
                            heap_groups[group] += size
                            break
                    else:
                        heap_groups['misc'] += size

                # start next parse
                m = re.search('\(([0-9,]+)B\)', line)
                size = int(m.group(1).replace(',', ''))
                nested_lines = [line]
            elif re.match('[ |]*->', line):
                nested_lines.append(line)

    # we can't find stack this way
    stack_groups = co.defaultdict(lambda: 0)
    stack_groups['misc'] = stack_total

    return (heap_groups, heap_total, stack_groups, stack_total)

def main(args):
    # find groups
    code_groups, code_total = find_static_groups(args.rom_report)
    static_groups, static_total = find_static_groups(args.static_ram_report)
    heap_groups, heap_total, stack_groups, stack_total = find_dyn_groups(args.dyn_ram_report)

    print("%-12s %7s %7s %7s %7s" % ('', 'code', 'static', 'heap', 'stack'))
    for group, _ in it.chain(sorted(GROUPS), [('misc', [])]):
        print("%-12s %7d %7d %7d %7d" % (
            group,
            code_groups[group],
            static_groups[group],
            heap_groups[group],
            stack_groups[group]))
    print("%-12s %7d %7d %7d %7d" % (
        'TOTAL',
        code_total,
        static_total,
        heap_total,
        stack_total))


            

if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(
        description='Summarize breakdown of rom/ram in reports')
    parser.add_argument('rom_report',
        help='ROM report output from Zephyr')
    parser.add_argument('static_ram_report',
        help='Static RAM report output from Zephyr')
    parser.add_argument('dyn_ram_report',
        help='Dynamic RAM report output from Valgrin\'s Massif tool')
    args = parser.parse_args()
    main(args)
