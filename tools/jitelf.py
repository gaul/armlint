"""Shared ELF output for the JIT-dump converters.

v8dump2elf.py, smdump2elf.py and jscdump2elf.py each parse their
engine's dump format into Chunks -- runs of contiguous code at their
original JIT address -- and hand them here, which writes the ELF ET_REL
images armlint and the scanners read:

  * one SHF_EXECINSTR section per chunk, sh_addr set to the chunk's JIT
    address so findings cross-reference back into the dump;
  * an STB_LOCAL STT_FUNC symbol per section carrying the chunk's name.

The converters import this module from their own directory, so run
them in place (tools/v8dump2elf.py), not copied elsewhere alone.
"""

import re
import struct
import sys

# Characters a symbol name keeps; any other becomes '_'.
SANITIZE_RE = re.compile(r'[^A-Za-z0-9_.@:<>/-]')


class Chunk:
    __slots__ = ('name', 'addr', 'data')

    def __init__(self, name, addr, data=None):
        self.name = name
        self.addr = addr
        self.data = bytearray() if data is None else data


def unique_name(seen, name):
    """Return NAME, or NAME.2, NAME.3, ... for its later uses.

    JIT addresses and function names both repeat across a dump (code is
    discarded and its memory reused), and each symbol should still name
    one chunk. SEEN is the caller's dict of counts so far."""
    n = seen.get(name, 0) + 1
    seen[name] = n
    return name if n == 1 else '%s.%d' % (name, n)


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


# === Command line shared by the converters ===

def add_output_args(ap, default_output):
    """Add the -o, --max-sections and --map options to parser AP."""
    ap.add_argument('-o', '--output', default=default_output)
    ap.add_argument('--max-sections', type=int, default=60000,
                    help='chunks per ELF before splitting the output')
    ap.add_argument('--map', help='also write "name 0xaddr size" lines here')


def write_outputs(chunks, args):
    """Write CHUNKS as add_output_args' options ask; return the exit code.

    Past --max-sections chunks (the ELF section count is a uint16) the
    output is split into OUTPUT.1, OUTPUT.2, ..."""
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
