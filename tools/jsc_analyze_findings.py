#!/usr/bin/env python3
"""Cross-tabulate armlint -v findings from a JavaScriptCore JIT dump.

Input is armlint -v output for an ELF built by jscdump2elf.py, whose
symbols are named "<LinkBuffer::Profile>_<code block name>".  Outputs:

  * finding-type x JIT tier (Baseline/DFG/FTL/InlineCache/YarrJIT/...)
  * top offender code blocks
  * sample finding blocks per type

Usage: jsc_analyze_findings.py FINDINGS MAP OUTPREFIX
"""

import collections
import re
import sys

# JSC code-block names contain angle brackets ("<global>"), so the symbol
# field is matched greedily and the "+0x<offset>" suffix split off after.
FINDING_RE = re.compile(
    r'^(.+?) at offset: 0x([0-9a-f]+) <(.+)>: (.*) \((\d+) instructions?\)$')
SYMOFF_RE = re.compile(r'^(.*)\+0x([0-9a-f]+)$')


def load_map(path):
    m = {}
    for line in open(path):
        name, addr, size = line.rsplit(None, 2)
        m[name] = (int(addr, 16), int(size))
    return m


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 1
    findings_path, map_path, prefix = sys.argv[1:4]
    chunk_map = load_map(map_path)

    by_type_tier = collections.defaultdict(collections.Counter)
    by_func = collections.Counter()
    samples = collections.defaultdict(list)

    cur = None
    cur_lines = []

    def flush():
        if cur is None:
            return
        ftype, absaddr, sym, header = cur
        tier = sym.split('_', 1)[0]
        by_type_tier[ftype][tier] += 1
        by_func[re.sub(r'\.\d+$', '', sym)] += 1
        if len(samples[ftype]) < 8:
            samples[ftype].append(
                '%s\n  @0x%x\n%s' % (header, absaddr, '\n'.join(cur_lines)))

    for line in open(findings_path, errors='replace'):
        line = line.rstrip('\n')
        m = FINDING_RE.match(line)
        if m:
            flush()
            sym = m.group(3)
            symoff = 0
            mo = SYMOFF_RE.match(sym)
            if mo:
                sym, symoff = mo.group(1), int(mo.group(2), 16)
            base = chunk_map.get(sym, (0, 0))[0]
            cur = (m.group(1), base + symoff, sym, line)
            cur_lines = []
        elif cur is not None and line.startswith('  '):
            cur_lines.append(line)
        elif cur is not None and not line.strip():
            flush()
            cur = None
            cur_lines = []
    flush()

    tiers = sorted({t for c in by_type_tier.values() for t in c},
                   key=lambda t: -sum(c.get(t, 0)
                                      for c in by_type_tier.values()))
    print('== finding type x tier ==')
    print('%-58s %8s %s' % ('', 'total',
                            ' '.join('%12s' % t for t in tiers)))
    for ftype, counter in sorted(by_type_tier.items(),
                                 key=lambda kv: -sum(kv[1].values())):
        print('%-58s %8d %s'
              % (ftype[:58], sum(counter.values()),
                 ' '.join('%12d' % counter.get(t, 0) for t in tiers)))
    print('%-58s %8d %s'
          % ('TOTAL', sum(sum(c.values()) for c in by_type_tier.values()),
             ' '.join('%12d' % sum(c.get(t, 0) for c in by_type_tier.values())
                      for t in tiers)))

    print('\n== top code blocks ==')
    for func, n in by_func.most_common(25):
        print('%6d  %s' % (n, func))

    with open(prefix + '-samples.txt', 'w') as f:
        for ftype, blocks in sorted(samples.items()):
            f.write('===== %s =====\n' % ftype)
            f.write('\n\n'.join(blocks))
            f.write('\n\n')
    print('\nsamples -> %s-samples.txt' % prefix)


if __name__ == '__main__':
    sys.exit(main())
