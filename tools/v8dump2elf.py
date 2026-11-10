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
    armlint -m v8, which steps over the self-describing pools
    instead of decoding their data as instructions;
  * an STT_FUNC symbol per section carrying the compiler tier and the
    JS function name (TF_foo, ML_foo, BL_foo, RE_<pattern>, ...), so
    -v findings and the -i census attribute to the generating tier.

Separate sections also stop armlint's adjacency-based peephole
matcher and its bounded liveness scans from walking across unrelated
code objects.

Usage: v8dump2elf.py DUMP [-o OUT.elf] [--max-sections N]
Multiple ELFs (OUT.elf.1, OUT.elf.2, ...) are emitted when the chunk
count exceeds the ELF uint16 section limit.
"""

import argparse
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jitelf import (Chunk, SANITIZE_RE, add_output_args,  # noqa: E402
                    unique_name, write_outputs)

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
        return unique_name(seen, '%s_%s' % (prefix, base))

    for line in fp:
        line = line.rstrip('\n')
        if in_code:
            m = INSN_RE.match(line)
            if m:
                # Constant-pool lines ("constant pool begin" marker and
                # "constant" data words) are kept: the marker's imm19
                # self-describes the pool, armlint -m v8 skips it,
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


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('dump', help='V8 code dump (- for stdin)')
    add_output_args(ap, 'v8code.elf')
    args = ap.parse_args()

    if args.dump == '-':
        chunks = parse_dump(sys.stdin)
    else:
        with open(args.dump, 'r', errors='replace') as fp:
            chunks = parse_dump(fp)
    return write_outputs(chunks, args)


if __name__ == '__main__':
    sys.exit(main())
