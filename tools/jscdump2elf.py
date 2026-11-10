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
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jitelf import (Chunk, SANITIZE_RE, add_output_args,  # noqa: E402
                    unique_name, write_outputs)


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
        chunks.append(Chunk(unique_name(seen, base), addr, data))
    if truncated:
        print('warning: %d trailing bytes are not a complete record'
              % truncated, file=sys.stderr)
    return chunks


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('dump', help='JSC armlint dump file')
    add_output_args(ap, 'jsccode.elf')
    args = ap.parse_args()

    return write_outputs(parse_dump(args.dump), args)


if __name__ == '__main__':
    sys.exit(main())
