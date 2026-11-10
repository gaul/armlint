#!/usr/bin/env python3
"""Convert SpiderMonkey JS_ARMLINT_DISASM dumps into ELF objects.

The armlint hook in SpiderMonkey's jit::Linker (JS_ARMLINT=1, with
JS_ARMLINT_DISASM=all or a CodeKind name) dumps every linked code blob
as

  ==== DISASM kind=Baseline base=0x1703b71cc010 len=50304 ====
    +0x0000: a9bf7bfd stp x29, x30, [sp, #-0x10]!
    +0x0004: 00000000 .word (undecoded)

This script reassembles the encoding words into ELF ET_REL images for
pairscan / shapescan / armlint, in the layout jitelf.py writes:

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
Multiple ELFs (OUT.elf.1, OUT.elf.2, ...) are emitted when the blob
count exceeds the ELF uint16 section limit.
"""

import argparse
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jitelf import Chunk, add_output_args, unique_name, write_outputs  # noqa: E402

HEADER_RE = re.compile(
    r'^==== DISASM kind=(\S+) base=0x([0-9a-f]+) len=(\d+) ====$')
INSN_RE = re.compile(r'^\s+\+0x([0-9a-f]+): ([0-9a-f]{8}) ')

KIND_PREFIX = {
    'Ion': 'ION',
    'Baseline': 'BL',
    'RegExp': 'RE',
    'Other': 'TR',
}


def parse_dump(fp):
    chunks = []
    kind = ''
    base = 0
    cur = None
    seen = {}

    def display_name(addr):
        prefix = KIND_PREFIX.get(kind, kind[:8] if kind else 'UN')
        return unique_name(seen, '%s_%x' % (prefix, addr))

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


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('dump', help='SpiderMonkey armlint disasm dump (- for stdin)')
    add_output_args(ap, 'smcode.elf')
    args = ap.parse_args()

    if args.dump == '-':
        chunks = parse_dump(sys.stdin)
    else:
        with open(args.dump, 'r', errors='replace') as fp:
            chunks = parse_dump(fp)
    return write_outputs(chunks, args)


if __name__ == '__main__':
    sys.exit(main())
