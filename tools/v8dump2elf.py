#!/usr/bin/env python3
"""Convert V8 --print-opt-code style dumps into ELF objects for armlint.

V8's code printer (d8/node --print-opt-code, --print-maglev-code,
--print-code, --print-regexp-code with v8_enable_disassembler=true)
emits, per code object, a header block (name/kind/compiler) followed by

  Instructions (size = 224)
  0x1182c4120     0  a9bf7bfd       stp fp, lr, [sp, #-16]!
  ...
  0x1182c41c8    a8  580000bf       constant pool begin (num_const = 5)
  0x1182c41cc    ac  d63f03e0       constant

This script reassembles the instruction words into an ELF ET_REL
image armlint can scan:

  * one SHF_EXECINSTR section per *contiguous* run of instructions,
    with sh_addr set to the original JIT address, so armlint findings
    print addresses that cross-reference back into the dump;
  * constant-pool words -- the "constant pool begin" marker (V8
    encodes it as LDR XZR, (literal) whose imm19 counts the data
    words) and its "constant" entries -- are kept in place, so the
    section stays contiguous and armlint's "LDR literal foldable to
    MOV/FMOV" check can read the pooled values. Scan the output with
    armlint -m v8pool, which steps over the self-describing pools
    instead of decoding their data as instructions;
  * an STT_FUNC symbol per section carrying the compiler tier and the
    JS function name (TF_foo, ML_foo, BL_foo, RE_<pattern>, ...), so
    -v findings and the -i census attribute to the generating tier.

Separate sections also stop armlint's adjacency-based peephole
matcher and its bounded liveness scans from walking across unrelated
code objects.

Usage: v8dump2elf.py DUMP [-o OUT.elf] [--max-sections N]
Multiple ELFs (OUT.1.elf, OUT.2.elf, ...) are emitted when the chunk
count exceeds the ELF uint16 section limit.
"""

import argparse
import re
import struct
import sys

INSN_RE = re.compile(
    r'^0x([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]{8})\s+(.*)$')
HEADER_FIELD_RE = re.compile(r'^(name|kind|compiler)\s*=\s*(.*)$')
INSTRUCTIONS_RE = re.compile(r'^Instructions\s*\(size')

KIND_PREFIX = {
    'TURBOFAN_JS': 'TF',
    'TURBOFAN': 'TF',
    'MAGLEV': 'ML',
    'BASELINE': 'BL',
    'REGEXP': 'RE',
    'WASM_FUNCTION': 'WA',
    'BUILTIN': 'BI',
    'BYTECODE_HANDLER': 'BH',
    'FOR_TESTING': 'XX',
}

SANITIZE_RE = re.compile(r'[^A-Za-z0-9_.@:<>/-]')


class Chunk:
    __slots__ = ('name', 'addr', 'data')

    def __init__(self, name, addr):
        self.name = name
        self.addr = addr
        self.data = bytearray()


def parse_dump(fp):
    """Yield Chunk objects from a V8 code dump stream."""
    chunks = []
    name = ''
    kind = ''
    in_code = False
    cur = None
    seen = {}

    def display_name():
        prefix = KIND_PREFIX.get(kind, kind[:8] if kind else 'UN')
        base = SANITIZE_RE.sub('_', name)[:80] or 'anonymous'
        full = '%s_%s' % (prefix, base)
        n = seen.get(full, 0) + 1
        seen[full] = n
        return full if n == 1 else '%s.%d' % (full, n)

    for line in fp:
        line = line.rstrip('\n')
        if in_code:
            m = INSN_RE.match(line)
            if m:
                # Constant-pool lines ("constant pool begin" marker and
                # "constant" data words) are kept: the marker's imm19
                # self-describes the pool, armlint -m v8pool skips it,
                # and the literal-fold check reads the pooled values.
                addr = int(m.group(1), 16)
                word = int(m.group(3), 16)
                if cur is None or addr != cur.addr + len(cur.data):
                    if cur is not None and cur.data:
                        chunks.append(cur)
                    cur = Chunk(display_name(), addr)
                cur.data += struct.pack('<I', word)
                continue
            if not line.strip() or line.lstrip().startswith(';;'):
                continue
            # Any other line shape (Safepoints, RelocInfo, Constant
            # Pool, "--- End code ---", benchmark output, ...) ends the
            # listing; fall through so "--- " still resets the header.
            if cur is not None and cur.data:
                chunks.append(cur)
            cur = None
            in_code = False
        if line.startswith('--- '):
            # Header boundary: forget the previous object's identity so
            # an unnamed object does not inherit its predecessor's name.
            name = ''
            kind = ''
            continue
        m = HEADER_FIELD_RE.match(line)
        if m:
            if m.group(1) == 'name':
                name = m.group(2).strip()
            elif m.group(1) == 'kind':
                kind = m.group(2).strip()
            continue
        if INSTRUCTIONS_RE.match(line):
            in_code = True
            cur = None
            continue
    if cur is not None and cur.data:
        chunks.append(cur)
    return chunks


# === Minimal ELF64 writer ===

SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 0, 1, 2, 3
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4


def align4(n):
    return (n + 3) & ~3


def write_elf(chunks, path):
    ehsize = 64
    shentsize = 64

    # Section data payload, 4-aligned back to back after the header.
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

    nsections = 1 + len(chunks) + 3         # null, chunks, symtab/strtab/shstrtab
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
    ap.add_argument('dump', help='V8 code dump (- for stdin)')
    ap.add_argument('-o', '--output', default='v8code.elf')
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
