#!/usr/bin/env python3
"""Audit armlint's flag and register model against LLVM's AArch64 tablegen.

Capstone's implicit-access model has holes -- FJCVTZS, SUBPS and every
SVE compare set NZCV without Capstone 5 saying so -- and armlint fills
them by hand from the encoding. This tool finds the holes it has not
filled yet, using LLVM's instruction definitions as the oracle: every
A64 instruction is a tablegen record with its bit pattern and its
implicit defs and uses (NZCV, LR, ...), and `llvm-tblgen --dump-json`
prints them all.

For each encodable record it builds one word, with the register fields
set to distinct small numbers, and

1. decodes it with tools/tblgen_probe, which prints Capstone's NZCV and
   GPR access lists next to armlint's classify_liveness and
   classify_word_reg_liveness, and reports where Capstone and armlint
   each disagree with the record;

2. assembles the word into three probes per register the record
   touches and runs the armlint binary over them:

     mov xr, #1 ; W ; cbz xr, 1f       a "never taken: xr is 0x1" means
                                       armlint let the value flow
                                       through W's write of xr;
     mov xr, #1 ; W ; mov xr, #2       an "overwritten unread" on the
                                       first MOV means W's read of xr
                                       was missed;
     cmp x9, #0 ; b.ne ; W ; b.ne      a "never taken" decided by the
                                       CMP means W's NZCV write was
                                       transparent.

   The second step is the one that proves a blind spot: armlint
   corrects much of what Capstone omits, so a Capstone disagreement
   alone is not a bug.

3. with --masks, prints for each SVE/SME tablegen class of NZCV writers
   the fixed bits its records share and checks that no other record
   matches them, which is how classify_liveness's SVE table was derived.

Usage:
  tools/tblgen_audit.py --tblgen PATH/llvm-tblgen --llvm PATH/llvm-project
  tools/tblgen_audit.py --json aarch64.json [--masks] [--all]

Needs a built llvm-tblgen (any LLVM build directory has one), clang to
assemble the harness, `make tools/tblgen_probe` and `make armlint`.
Exit status 1 when the harness finds a transparent write; missed reads
are reported but do not fail, since the only known ones are SVE/SME.
"""
import argparse
import collections
import json
import os
import platform
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Register field values: distinct, small, none 31.
REGVAL = {'Rd': 1, 'Rn': 2, 'Rm': 3, 'Rs': 4, 'Rt': 6, 'Rt2': 8, 'Ra': 7,
          'Rt3': 10, 'Xd': 1, 'Xn': 2, 'Xm': 3, 'Xs': 4, 'Xt': 6, 'Wd': 1,
          'Wn': 2, 'Wm': 3, 'Ws': 4, 'Wt': 6, 'Rdn': 1, 'Rv': 5, 'Rdst': 1,
          'Rsrc': 2, 'Zd': 1, 'Zn': 2, 'Zm': 3, 'Zt': 6, 'Pd': 1, 'Pn': 2,
          'Pm': 3, 'Pg': 4}
LIV = {'0': 'UNKNOWN', '1': 'OVERWRITE', '2': 'READ', '3': 'TERM_SAFE',
       '4': 'TERM_UNSAFE'}

MOV_X1 = 0xD2800020      # mov xr, #1
MOV_X2 = 0xD2800040      # mov xr, #2
CBZ_8 = 0xB4000040       # cbz xr, .+8
CMP_X9 = 0xF100013F      # cmp x9, #0
BNE_16 = 0x54000081      # b.ne .+16
BNE_8 = 0x54000041       # b.ne .+8
RET = 0xD65F03C0


def load_records(args):
    if args.json is None:
        if args.tblgen is None or args.llvm is None:
            sys.exit('give --json, or --tblgen and --llvm')
        args.json = os.path.join(tempfile.gettempdir(), 'aarch64-tblgen.json')
        subprocess.run([args.tblgen, '-I', os.path.join(args.llvm, 'llvm/include'),
                        '-I', os.path.join(args.llvm, 'llvm/lib/Target/AArch64'),
                        os.path.join(args.llvm, 'llvm/lib/Target/AArch64/AArch64.td'),
                        '--dump-json', '-o', args.json], check=True)
    with open(args.json) as f:
        d = json.load(f)
    recs = {}
    for name, v in d.items():
        if not (isinstance(v, dict) and isinstance(v.get('Inst'), list)
                and v.get('Namespace') == 'AArch64' and not v.get('isPseudo')
                and len(v['Inst']) == 32):
            continue
        recs[name] = v
    return recs


def defs_of(v, key):
    return [x['def'] for x in (v.get(key) or []) if isinstance(x, dict)]


def encoding(v):
    """(mask of fixed bits, their values) of a record's Inst."""
    mask = bits = 0
    for i, b in enumerate(v['Inst']):
        if b in (0, 1):
            mask |= 1 << i
            bits |= b << i
    return mask, bits


def build_word(v):
    """One word of the record with the register fields set from REGVAL,
    plus a map of variable name to its value."""
    word = 0
    values = {}
    for i, b in enumerate(v['Inst']):
        if b in (0, 1):
            word |= b << i
        elif isinstance(b, dict) and 'var' in b:
            val = REGVAL.get(b['var'], 0)
            values.setdefault(b['var'], val)
            if (val >> b.get('index', 0)) & 1:
                word |= 1 << i
    return word, values


def is_gpr_class(cls):
    return re.search(r'GPR(32|64)|SeqPairs|GPR64x8', cls) is not None


def gpr_access(v, values):
    """(written, read) GPR numbers the record declares."""
    ties = {}
    for m in re.finditer(r'\$(\w+)\s*=\s*\$(\w+)', v.get('Constraints') or ''):
        ties[m.group(1)] = m.group(2)
        ties[m.group(2)] = m.group(1)

    def reg_of(name):
        if name in values:
            return values[name]
        t = ties.get(name)
        return values.get(t)

    def walk(oplist):
        out = set()
        for cls, name in v[oplist]['args']:
            c = cls.get('def') or cls.get('printable', '')
            if not is_gpr_class(c):
                continue
            r = reg_of(name)
            if r is None:
                continue
            out.add(r)
            if 'SeqPairs' in c:
                out.add(r + 1)
        return out

    writes, reads = walk('OutOperandList'), walk('InOperandList')
    for key, acc in (('Defs', writes), ('Uses', reads)):
        for n in defs_of(v, key):
            m = re.match(r'^[WX](\d+)$', n)
            if m:
                acc.add(int(m.group(1)))
            if n == 'LR':
                acc.add(30)
    return writes, reads


def run_probe(probe, words):
    text = ''.join('%08x\n' % w for w in words)
    out = subprocess.run([probe], input=text, capture_output=True, text=True,
                         check=True).stdout
    res = {}
    for line in out.splitlines():
        head, creads, cwrites, tail = line.split('|')
        f = head.split()
        liv, cls = tail.split()
        res[int(f[0], 16)] = {
            'decoded': f[1] == '1', 'mn': f[2],
            'cs_reads_nzcv': f[4] == '1',
            'cs_writes_nzcv': f[5] == '1' or f[6] == '1',
            'cs_reads': {int(x) for x in creads.split(',') if x.strip()},
            'cs_writes': {int(x) for x in cwrites.split(',') if x.strip()},
            'liv': LIV[liv], 'cls': cls,
        }
    return res


def family(mn, preds):
    if any('SVE' in p or 'SME' in p for p in preds):
        return 'SVE/SME'
    return re.sub(r'^(ld|st|cas|swp|cpy|set|rcw)[a-z0-9]*',
                  lambda m: m.group(1) + '*', mn)


def report(title, table, show_all):
    total = sum(len(v) for v in table.values())
    print('== %s: %d' % (title, total))
    for (fam, preds), names in sorted(table.items()):
        if fam == 'SVE/SME' and not show_all:
            continue
        print('  %-14s %-32s %4d  e.g. %s' % (fam, preds[:32], len(names),
                                             ' '.join(names[:3])))
    n = sum(len(v) for (f, p), v in table.items() if f == 'SVE/SME')
    if n and not show_all:
        print('  (SVE/SME: %d, listed with --all)' % n)


def compare(recs, info, show_all):
    """Step 1: Capstone and armlint's classifiers against the records."""
    T = collections.defaultdict(lambda: collections.defaultdict(list))
    undecodable = collections.Counter()
    for name, (v, word, values, writes, reads) in info.items():
        p = v['_probe']
        preds = defs_of(v, 'Predicates')
        nzd, nzu = 'NZCV' in defs_of(v, 'Defs'), 'NZCV' in defs_of(v, 'Uses')
        if not p['decoded']:
            if nzd or nzu or writes or reads:
                undecodable[','.join(preds) or '-'] += 1
            continue
        key = (family(p['mn'], preds), ','.join(preds) or '-')
        if nzd and not p['cs_writes_nzcv']:
            T['NZCV written per LLVM, no Capstone write (armlint %s)'
              % p['liv']][key].append(name)
        if nzu and not p['cs_reads_nzcv']:
            T['NZCV read per LLVM, no Capstone read (armlint %s)'
              % p['liv']][key].append(name)
        if nzu and p['liv'] not in ('READ', 'TERM_UNSAFE', 'TERM_SAFE'):
            T['NZCV read per LLVM, armlint classify_liveness %s'
              % p['liv']][key].append(name)
        for r in writes - p['cs_writes']:
            T['GPR written per LLVM, no Capstone write'][key].append(
                '%s/x%d' % (name, r))
        for r in reads - p['cs_reads']:
            T['GPR read per LLVM, no Capstone read'][key].append(
                '%s/x%d' % (name, r))
        for r in reads:
            if p['cls'][r] in 'OU':
                T['GPR read per LLVM, armlint word classifier %s'
                  % LIV['O' if p['cls'][r] == 'O' else '0']][key].append(
                    '%s/x%d' % (name, r))
    for title in sorted(T):
        report(title, T[title], show_all)
    if undecodable:
        print('== records Capstone cannot decode, by predicate:')
        for preds, n in undecodable.most_common(10):
            print('  %-40s %d' % (preds, n))


def harness(recs, info, armlint, show_all):
    """Step 2: run armlint over probes built from every record."""
    tests = []
    for name, (v, word, values, writes, reads) in info.items():
        if not v['_probe']['decoded']:
            continue
        for r in sorted(writes):
            if r <= 30:
                tests.append(('write', name, r,
                              [MOV_X1 | r, word, CBZ_8 | r, RET, RET]))
        for r in sorted(reads):
            if r <= 30:
                tests.append(('read', name, r,
                              [MOV_X1 | r, word, MOV_X2 | r, RET]))
        if 'NZCV' in defs_of(v, 'Defs'):
            tests.append(('nzcv', name, -1,
                          [CMP_X9, BNE_16, word, BNE_8, RET, RET]))
    with tempfile.TemporaryDirectory() as tmp:
        asm = os.path.join(tmp, 'harness.s')
        obj = os.path.join(tmp, 'harness.o')
        with open(asm, 'w') as f:
            f.write('.text\n')
            for i, (kind, name, r, words) in enumerate(tests):
                f.write('.globl _t%d\n.p2align 2\n_t%d:\n' % (i, i))
                for w in words:
                    f.write('  .long 0x%08x\n' % w)
        target = (['-arch', 'arm64'] if platform.system() == 'Darwin'
                  else ['--target=aarch64-linux-gnu'])
        subprocess.run(['clang'] + target + ['-c', asm, '-o', obj], check=True)
        out = subprocess.run([armlint, '-v', obj], capture_output=True,
                             text=True).stdout
    hits = collections.defaultdict(list)
    for line in out.splitlines():
        m = re.match(r'^(.*?) at offset: 0x[0-9a-f]+ <_t(\d+)(?:\+0x([0-9a-f]+))?>:'
                     r'(.*)$', line)
        if m:
            hits[int(m.group(2))].append((int(m.group(3) or '0', 16),
                                          m.group(1), m.group(4)))
    T = collections.defaultdict(lambda: collections.defaultdict(list))
    fatal = 0
    for i, (kind, name, r, words) in enumerate(tests):
        v = info[name][0]
        key = (family(v['_probe']['mn'], defs_of(v, 'Predicates')),
               ','.join(defs_of(v, 'Predicates')) or '-')
        for off, typ, detail in hits.get(i, []):
            if kind == 'write' and off == 8 and 'never taken' in typ \
                    and re.search(r'\bis 0x1\b', detail):
                T['transparent GPR write'][key].append('%s/x%d' % (name, r))
                fatal += 1
            if kind == 'read' and off == 0 and 'overwritten unread' in typ:
                T['missed GPR read'][key].append('%s/x%d' % (name, r))
            if kind == 'nzcv' and off == 12 and 'never taken' in typ \
                    and 'known 0xc bytes back' in detail:
                T['transparent NZCV write'][key].append(name)
                fatal += 1
    print('== harness: %d probes' % len(tests))
    for title in sorted(T):
        report(title, T[title], show_all)
    if not T:
        print('  no blind spots')
    return fatal


def masks(recs, info):
    """Step 3: fixed bits shared per SVE/SME tablegen class of NZCV
    writers, and whether any other record matches them."""
    nz = {n for n, v in recs.items() if 'NZCV' in defs_of(v, 'Defs')}
    groups = collections.defaultdict(list)
    for n in nz:
        sc = [s for s in recs[n]['!superclasses']
              if s.startswith(('sve', 'sme'))]
        if sc:
            groups[sc[0]].append(n)
    encs = {n: encoding(v) for n, v in recs.items()}
    for g, names in sorted(groups.items()):
        mask = 0xFFFFFFFF
        value = None
        for n in names:
            m, b = encs[n]
            mask &= m
            value = b if value is None else value
        for n in names:
            mask &= ~((encs[n][1] ^ value) & mask)
        value &= mask
        others = [n for n, (m, b) in encs.items()
                  if n not in nz and (m & mask) == mask and (b & mask) == value]
        print('%-36s %3d records  mask %08x value %08x  %s' % (
            g, len(names), mask, value,
            'matches ' + ', '.join(others[:4]) if others else 'exact'))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--json', help='llvm-tblgen --dump-json output to reuse')
    ap.add_argument('--tblgen', help='llvm-tblgen binary')
    ap.add_argument('--llvm', help='llvm-project source tree')
    ap.add_argument('--probe', default=os.path.join(HERE, 'tblgen_probe'))
    ap.add_argument('--armlint', default=os.path.join(ROOT, 'armlint'))
    ap.add_argument('--masks', action='store_true',
                    help='print the per-class masks of NZCV writers')
    ap.add_argument('--all', action='store_true',
                    help='list SVE/SME families instead of counting them')
    args = ap.parse_args()

    recs = load_records(args)
    info = {}
    for name, v in sorted(recs.items()):
        word, values = build_word(v)
        writes, reads = gpr_access(v, values)
        info[name] = (v, word, values, writes, reads)
    probe = run_probe(args.probe, [i[1] for i in info.values()])
    for name, (v, word, *_) in info.items():
        v['_probe'] = probe[word]
    print('%d records, %d decoded by Capstone' % (
        len(info), sum(1 for p in probe.values() if p['decoded'])))
    if args.masks:
        masks(recs, info)
        return 0
    compare(recs, info, args.all)
    return 1 if harness(recs, info, args.armlint, args.all) else 0


if __name__ == '__main__':
    sys.exit(main())
