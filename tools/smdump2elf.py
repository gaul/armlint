#!/usr/bin/env python3
"""Convert SpiderMonkey JS_ARMLINT_DISASM dumps into ELF objects.

The armlint hook in SpiderMonkey's jit::Linker (JS_ARMLINT=1, with
JS_ARMLINT_DISASM=all or a CodeKind name) dumps every linked code blob
as

  ==== DISASM kind=Baseline base=0x1703b71cc010 len=50304 ====
    +0x0000: a9bf7bfd stp x29, x30, [sp, #-0x10]!
    +0x0004: 00000000 .word (undecoded)

This script reassembles the encoding words into ELF ET_REL images for
pairscan / shapescan / armlint, following v8dump2elf.py's layout:

  * one SHF_EXECINSTR section per blob, sh_addr set to the original
    JIT address so findings cross-reference back into the dump;
  * an STT_FUNC symbol per section named <tier>_<base>, tiers being
    ION / BL / RE / TR (Other = trampolines);  JIT addresses are
    reused as code is discarded, so repeated names get .2/.3 suffixes;
  * undecodable words (vixl literal pools, unreachable padding) stay
    in place -- the scanners skip across them on their own.

Benchmark output interleaved between blobs is ignored; a line inside a
blob that is neither a header nor an instruction is skipped without
ending the blob, and offset continuity decides chunk boundaries.

Usage: smdump2elf.py DUMP [-o OUT.elf] [--max-sections N]
Multiple ELFs (OUT.1, OUT.2, ...) are emitted when the blob count
exceeds the ELF uint16 section limit.
"""

import argparse
import re
import struct
import sys

HEADER_RE = re.compile(
    r'^==== DISASM kind=(\S+) base=0x([0-9a-f]+) len=(\d+) ====$')
INSN_RE = re.compile(r'^\s+\+0x([0-9a-f]+): ([0-9a-f]{8}) ')

KIND_PREFIX = {
    'Ion': 'ION',
    'Baseline': 'BL',
    'RegExp': 'RE',
    'Other': 'TR',
}


class Chunk:
    __slots__ = ('name', 'addr', 'data')

    def __init__(self, name, addr):
        self.name = name
        self.addr = addr
        self.data = bytearray()


def parse_dump(fp):
    chunks = []
    kind = ''
    base = 0
    cur = None
    seen = {}

    def display_name(addr):
        prefix = KIND_PREFIX.get(kind, kind[:8] if kind else 'UN')
        full = '%s_%x' % (prefix, addr)
        n = seen.get(full, 0) + 1
        seen[full] = n
        return full if n == 1 else '%s.%d' % (full, n)

    for line in fp:
        m = INSN_RE.match(line)
        if m:
            addr = base + int(m.group(1), 16)
            word = int(m.group(2), 16)
            if cur is None or addr != cur.addr + len(cur.data):
                if cur is not None and cur.data:
                    chunks.append(cur)
                cur = Chunk(display_name(addr), addr)
            cur.data += struct.pack('<I', word)
            continue
        m = HEADER_RE.match(line)
        if m:
            if cur is not None and cur.data:
                chunks.append(cur)
            cur = None
            kind = m.group(1)
            base = int(m.group(2), 16)
            continue
    if cur is not None and cur.data:
        chunks.append(cur)
    return chunks


# === Minimal ELF64 writer (same layout as v8dump2elf.py) ===

SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 0, 1, 2, 3
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4


def align4(n):
    return (n + 3) & ~3


def write_elf(chunks, path):
    ehsize = 64
    shentsize = 64

    payload = bytearray()
    offsets = []
    for c in chunks:
        off = ehsize + len(payload)
        offsets.append(off)
        payload += c.data
        pad = align4(len(payload)) - len(payload)
        payload += b'\0' * pad

    shstrtab = bytearray(b'\0')
    def shname(s):
        off = len(shstrtab)
        shstrtab.extend(s.encode() + b'\0')
        return off
    text_name = shname('.text')
    symtab_name = shname('.symtab')
    strtab_name = shname('.strtab')
    shstrtab_name = shname('.shstrtab')

    strtab = bytearray(b'\0')
    symtab = bytearray(b'\0' * 24)          # index 0: null symbol
    for i, c in enumerate(chunks):
        st_name = len(strtab)
        strtab.extend(c.name.encode() + b'\0')
        st_info = (0 << 4) | 2              # STB_LOCAL, STT_FUNC
        symtab += struct.pack('<IBBHQQ', st_name, st_info, 0,
                              1 + i, 0, len(c.data))

    nsections = 1 + len(chunks) + 3
    symtab_idx = 1 + len(chunks)
    strtab_idx = symtab_idx + 1
    shstrtab_idx = strtab_idx + 1

    symtab_off = ehsize + len(payload)
    strtab_off = symtab_off + len(symtab)
    shstrtab_off = strtab_off + len(strtab)
    shoff = align4(shstrtab_off + len(shstrtab))

    def shdr(name, type_, flags, addr, off, size, link, info, align, entsize):
        return struct.pack('<IIQQQQIIQQ', name, type_, flags, addr, off,
                           size, link, info, align, entsize)

    shdrs = [shdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)]
    for c, off in zip(chunks, offsets):
        shdrs.append(shdr(text_name, SHT_PROGBITS,
                          SHF_ALLOC | SHF_EXECINSTR, c.addr, off,
                          len(c.data), 0, 0, 4, 0))
    shdrs.append(shdr(symtab_name, SHT_SYMTAB, 0, 0, symtab_off,
                      len(symtab), strtab_idx, 1 + len(chunks), 8, 24))
    shdrs.append(shdr(strtab_name, SHT_STRTAB, 0, 0, strtab_off,
                      len(strtab), 0, 0, 1, 0))
    shdrs.append(shdr(shstrtab_name, SHT_STRTAB, 0, 0, shstrtab_off,
                      len(shstrtab), 0, 0, 1, 0))

    ehdr = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
                       b'\x7fELF', 2, 1, 1, 0, 0,   # 64-bit LSB SysV
                       1, 183,                      # ET_REL, EM_AARCH64
                       1, 0, 0, shoff, 0,
                       ehsize, 0, 0, shentsize, nsections, shstrtab_idx)

    with open(path, 'wb') as f:
        f.write(ehdr)
        f.write(payload)
        f.write(symtab)
        f.write(strtab)
        f.write(shstrtab)
        f.write(b'\0' * (shoff - shstrtab_off - len(shstrtab)))
        for s in shdrs:
            f.write(s)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('dump', help='SpiderMonkey armlint disasm dump (- for stdin)')
    ap.add_argument('-o', '--output', default='smcode.elf')
    ap.add_argument('--max-sections', type=int, default=60000,
                    help='chunks per ELF before splitting the output')
    ap.add_argument('--map', help='also write "name 0xaddr size" lines here')
    args = ap.parse_args()

    if args.dump == '-':
        chunks = parse_dump(sys.stdin)
    else:
        with open(args.dump, 'r', errors='replace') as fp:
            chunks = parse_dump(fp)
    if not chunks:
        print('no code found in dump', file=sys.stderr)
        return 1

    if args.map:
        with open(args.map, 'w') as f:
            for c in chunks:
                f.write('%s 0x%x %d\n' % (c.name, c.addr, len(c.data)))

    total = sum(len(c.data) for c in chunks)
    if len(chunks) <= args.max_sections:
        write_elf(chunks, args.output)
        outs = [args.output]
    else:
        outs = []
        for i in range(0, len(chunks), args.max_sections):
            part = '%s.%d' % (args.output, len(outs) + 1)
            write_elf(chunks[i:i + args.max_sections], part)
            outs.append(part)
    print('%d chunks, %d code bytes -> %s' %
          (len(chunks), total, ' '.join(outs)), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
