#!/usr/bin/env python3
"""Cross-reference armlint -v findings with a V8 dump's RelocInfo.

Outputs:
  * finding-type x compiler-tier cross-tab -- with armlint -v -d
    output, also the findings per tier that repeat an earlier copy's
    (marked "[repeat]")
  * per finding type: how many findings contain a relocated (patchable)
    instruction, broken down by reloc mode -- those are toolchain-forced
  * top offender functions
  * sample finding blocks per type (with reloc annotation)
"""

import collections
import re
import sys

# The symbol is v8dump2elf.py's sanitized name, which keeps '<' and '>'
# (a regexp's source: RE__<>_) but never a space or a '+'. Matched
# lazily up to the first '>: ', behind an optional '+0x<offset>', it
# cannot run into the detail, which follows that space.
FINDING_RE = re.compile(
    r'^(.+?) at offset: 0x([0-9a-f]+) <([^ +]+?)(?:\+0x([0-9a-f]+))?>: '
    r'(.*) \((\d+) instructions?\)( \[repeat\])?$')
RELOC_RE = re.compile(r'^0x([0-9a-f]+)\s\s+([a-z][a-zA-Z0-9 _-]*)')
RELOC_HDR_RE = re.compile(r'^RelocInfo \(size')


def load_map(path):
    m = {}
    for line in open(path):
        name, addr, size = line.split()
        m[name] = (int(addr, 16), int(size))
    return m


def load_relocs(path):
    relocs = {}
    in_reloc = False
    for line in open(path, errors='replace'):
        if RELOC_HDR_RE.match(line):
            in_reloc = True
            continue
        if in_reloc:
            m = RELOC_RE.match(line)
            if m:
                relocs[int(m.group(1), 16)] = m.group(2).strip()
            elif line.strip():
                in_reloc = False
    return relocs


def main():
    if len(sys.argv) != 5:
        print('usage: v8_analyze_findings.py FINDINGS MAP DUMP OUTPREFIX\n'
              '  FINDINGS: armlint -v output for the ELF built from DUMP\n'
              '  MAP:      the --map sidecar v8dump2elf.py wrote\n'
              '  DUMP:     the V8 code dump itself (for RelocInfo)\n'
              '  OUTPREFIX: sample blocks land in OUTPREFIX-samples.txt',
              file=sys.stderr)
        return 1
    findings_path, map_path, dump_path, prefix = sys.argv[1:5]
    chunk_map = load_map(map_path)
    relocs = load_relocs(dump_path)

    by_type_tier = collections.defaultdict(collections.Counter)
    repeats_by_tier = collections.Counter()
    by_type_reloc = collections.defaultdict(collections.Counter)
    by_func = collections.Counter()
    samples = collections.defaultdict(list)

    cur = None          # (type, absaddr, sym, ninsn, headerline, repeat)
    cur_lines = []

    def flush():
        if cur is None:
            return
        ftype, absaddr, sym, ninsn, header, repeat = cur
        tier = sym.split('_', 1)[0]
        by_type_tier[ftype][tier] += 1
        if repeat:
            repeats_by_tier[tier] += 1
        func = re.sub(r'\.\d+$', '', sym)
        by_func[func] += 1
        modes = set()
        for k in range(ninsn):
            mode = relocs.get(absaddr + 4 * k)
            if mode:
                modes.add(mode)
        if modes:
            for mode in modes:
                by_type_reloc[ftype][mode] += 1
        else:
            by_type_reloc[ftype]['(none)'] += 1
        if len(samples[ftype]) < 8:
            tag = ' [reloc: %s]' % ', '.join(sorted(modes)) if modes else ''
            samples[ftype].append(
                '%s%s\n  @0x%x\n%s' % (header, tag, absaddr,
                                       '\n'.join(cur_lines)))

    unparsed = 0
    for line in open(findings_path, errors='replace'):
        line = line.rstrip('\n')
        m = FINDING_RE.match(line)
        if not m and not line.startswith(' ') and ' at offset: 0x' in line:
            # A finding header this parser cannot read would otherwise
            # vanish from every table below without a trace.
            unparsed += 1
        if m:
            flush()
            ftype = m.group(1)
            sym = m.group(3)
            symoff = int(m.group(4) or '0', 16)
            base = chunk_map.get(sym, (0, 0))[0]
            cur = (ftype, base + symoff, sym, int(m.group(6)), line,
                   m.group(7) is not None)
            cur_lines = []
        elif cur is not None and line.startswith('  '):
            cur_lines.append(line)
        elif cur is not None and not line.strip():
            flush()
            cur = None
            cur_lines = []
    flush()
    if unparsed:
        print('v8_analyze_findings: %d finding headers not parsed and left '
              'out of every table' % unparsed, file=sys.stderr)

    tiers = sorted({t for c in by_type_tier.values() for t in c})
    print('== finding type x tier ==')
    print('%-58s %s' % ('', ' '.join('%8s' % t for t in tiers)))
    for ftype, counter in sorted(by_type_tier.items(),
                                 key=lambda kv: -sum(kv[1].values())):
        print('%-58s %s' % (ftype[:58],
                            ' '.join('%8d' % counter.get(t, 0)
                                     for t in tiers)))
    if repeats_by_tier:
        print('%-58s %s' % ('of which repeat an earlier copy (armlint -d)',
                            ' '.join('%8d' % repeats_by_tier.get(t, 0)
                                     for t in tiers)))

    print('\n== reloc-forced analysis (findings containing a reloc site) ==')
    for ftype, counter in sorted(by_type_reloc.items(),
                                 key=lambda kv: -sum(kv[1].values())):
        total = sum(counter.values())
        forced = total - counter.get('(none)', 0)
        if forced == 0:
            continue
        detail = ', '.join('%s: %d' % (m, c) for m, c in counter.most_common()
                           if m != '(none)')
        print('%-58s %d/%d forced (%s)' % (ftype[:58], forced, total, detail))

    print('\n== top functions ==')
    for func, n in by_func.most_common(20):
        print('%6d  %s' % (n, func))

    with open(prefix + '-samples.txt', 'w') as f:
        for ftype, blocks in sorted(samples.items()):
            f.write('===== %s =====\n' % ftype)
            f.write('\n\n'.join(blocks))
            f.write('\n\n')
    print('\nsamples -> %s-samples.txt' % prefix)


if __name__ == '__main__':
    sys.exit(main())
