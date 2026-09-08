#!/usr/bin/env python3
"""Convert a JavaScriptCore JIT code dump into ELF objects for armlint.

The dump is produced by a locally instrumented JSC: LinkBuffer's
finalizeCodeWithoutDisassemblyImpl() appends one record per linked block
of machine code when JSC_ARMLINT_DUMP names an output file.  Each record is

    "JSCA" | u64 address | u32 code size | u32 name length | name | code

where the name carries the LinkBuffer::Profile (Baseline, DFG, FTL,
InlineCache, YarrJIT, WasmOMG, ...) followed by the CodeBlock/thunk name,
so armlint -v findings and the -i census attribute back to a JIT tier.

Each record becomes its own SHF_EXECINSTR section at its original JIT
address with an STT_FUNC symbol, which also stops armlint's adjacency
matcher and its bounded liveness scans from walking across unrelated
code blocks.

Usage: jscdump2elf.py DUMP [-o OUT.elf] [--max-sections N]
Multiple ELFs (OUT.elf.1, OUT.elf.2, ...) are emitted when the record
count exceeds the ELF uint16 section limit.
"""

import argparse
import os
import re
import struct
import sys

SANITIZE_RE = re.compile(r'[^A-Za-z0-9_.@:<>/-]')


class Chunk:
    __slots__ = ('name', 'addr', 'data')

    def __init__(self, name, addr, data):
        self.name = name
        self.addr = addr
        self.data = data


def parse_dump(path):
    """Yield Chunk objects from a JSC armlint dump file."""
    chunks = []
    seen = {}
    with open(path, 'rb') as f:
        blob = f.read()
    off = 0
    end = len(blob)
    truncated = 0
    while off < end:
        if blob[off:off + 4] != b'JSCA':
            truncated = end - off
            break
        if off + 20 > end:
            truncated = end - off
            break
        addr, size, namelen = struct.unpack_from('<QII', blob, off + 4)
        rec_end = off + 20 + namelen + size
        if rec_end > end:
            truncated = end - off
            break
        name = blob[off + 20:off + 20 + namelen].decode('utf-8', 'replace')
        data = blob[off + 20 + namelen:rec_end]
        off = rec_end
        if not size or size % 4:
            continue
        base = SANITIZE_RE.sub('_', name)[:90] or 'anonymous'
        n = seen.get(base, 0) + 1
        seen[base] = n
        chunks.append(Chunk(base if n == 1 else '%s.%d' % (base, n),
                            addr, data))
    if truncated:
        print('warning: %d trailing bytes are not a complete record'
              % truncated, file=sys.stderr)
    return chunks


# === Minimal ELF64 writer (shared with v8dump2elf.py) ===

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
        offsets.append(ehsize + len(payload))
        payload += c.data
        payload += b'\0' * (align4(len(payload)) - len(payload))

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
    ap.add_argument('dump', help='JSC armlint dump file')
    ap.add_argument('-o', '--output', default='jsccode.elf')
    ap.add_argument('--max-sections', type=int, default=60000,
                    help='chunks per ELF before splitting the output')
    ap.add_argument('--map', help='also write "name 0xaddr size" lines here')
    args = ap.parse_args()

    chunks = parse_dump(args.dump)
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
    print('%d chunks, %d code bytes -> %s'
          % (len(chunks), total, ' '.join(outs)), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
