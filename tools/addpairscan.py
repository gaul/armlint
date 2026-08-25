#!/usr/bin/env python3
"""addpairscan: population of the ADD-immediate + LDP/STP family.

shapescan's `add scratch,#big ; ldp/stp [scratch]` row counts the
whole family with one loose pair mask. That conflates two candidates
with very different value:

  in range   add x19, x26, #0xb8 ; ldp x21, x20, [x19, #-0xb8]
             -> ldp x21, x20, [x26]                      2 insns -> 1

  overflow   add x27, x27, #0xa80 ; ldp x3, x4, [x27]
             -> ldr x3, [x27, #0xa80] ; ldr x4, [x27, #0xa88]
                                                         2 insns -> 2

Only the first shortens the code, and it needs the SIGNED, pre-scaled
imm7 of the pair forms -- the combined offset routinely lands on the
far side of the new base, which the unsigned-offset single-access fold
cannot express at all. This tool splits the two and reports the tiers
the checker distinguishes (structural kill vs deferred liveness scan),
so the figures in TODO.md and analyses.md can be reproduced.

The in-range half is implemented (check_add_ldr_imm_offset's pair arm);
the counts here are CANDIDATES, an upper bound on what armlint reports
once the liveness scan has had its say. Run armlint itself for the
realized number.

Usage:
    tools/addpairscan.py --selftest       # verify every mask
    tools/addpairscan.py BINARY...        # per-binary population

Requires numpy. --selftest additionally requires clang and otool.
"""

import argparse
import collections
import os
import struct
import subprocess
import sys
import tempfile

try:
    import numpy as np
except ImportError:
    sys.exit("addpairscan requires numpy (pip install numpy)")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shapescan import text_words                      # noqa: E402

# ADD Xd, Xn, #imm12 {, lsl #12}: sf=1, op=0, S=0, 100010. Bit 22 is
# the shift flag and stays free; SUB (bit 30) and the S forms (bit 29)
# are excluded -- a flag-setting or subtracting producer is not this
# fold.
ADD_IMM_X = (0xFF800000, 0x91000000, "add x0, x1, #4")

# Load/store pair, signed-offset (no-writeback) form only: the
# writeback spellings belong to the pre-/post-index checks. Mask pins
# opc, V, the addressing mode and L, leaving imm7/Rt2/Rn/Rt free.
PAIRS = [
    ("stp_w",  0xFFC00000, 0x29000000, 4,  False, "stp w0, w1, [x2]"),
    ("ldp_w",  0xFFC00000, 0x29400000, 4,  True,  "ldp w0, w1, [x2]"),
    ("stp_x",  0xFFC00000, 0xA9000000, 8,  False, "stp x0, x1, [x2]"),
    ("ldp_x",  0xFFC00000, 0xA9400000, 8,  True,  "ldp x0, x1, [x2]"),
    ("ldpsw",  0xFFC00000, 0x69400000, 4,  True,  "ldpsw x0, x1, [x2]"),
    ("stp_s",  0xFFC00000, 0x2D000000, 4,  False, "stp s0, s1, [x2]"),
    ("ldp_s",  0xFFC00000, 0x2D400000, 4,  True,  "ldp s0, s1, [x2]"),
    ("stp_d",  0xFFC00000, 0x6D000000, 8,  False, "stp d0, d1, [x2]"),
    ("ldp_d",  0xFFC00000, 0x6D400000, 8,  True,  "ldp d0, d1, [x2]"),
    ("stp_q",  0xFFC00000, 0xAD000000, 16, False, "stp q0, q1, [x2]"),
    ("ldp_q",  0xFFC00000, 0xAD400000, 16, True,  "ldp q0, q1, [x2]"),
]
FP_FORMS = {"stp_s", "ldp_s", "stp_d", "ldp_d", "stp_q", "ldp_q"}


def _s7(v):
    """Sign-extend the 7-bit pair immediate."""
    return np.where(v & 64, v.astype(np.int64) - 128, v.astype(np.int64))


def scan(path):
    w, _base = text_words(path)
    a, b = w[:-1], w[1:]
    add_mask, add_val, _ = ADD_IMM_X
    is_add = (a & np.uint32(add_mask)) == np.uint32(add_val)
    a_rd = a & np.uint32(0x1F)
    # Rd = 31 in ADD-imm is SP, not ZR: folding would discard an
    # observable stack-pointer update, so the opener never fires.
    is_add &= a_rd != np.uint32(31)
    add_imm = (((a >> np.uint32(10)) & np.uint32(0xFFF)).astype(np.int64)
               << np.where((a >> np.uint32(22)) & np.uint32(1), 12, 0))

    res = collections.Counter()
    for name, mask, val, scale, is_load, _ref in PAIRS:
        sel = is_add & ((b & np.uint32(mask)) == np.uint32(val)) \
            & (((b >> np.uint32(5)) & np.uint32(0x1F)) == a_rd)
        idx = np.flatnonzero(sel)
        if idx.size == 0:
            continue
        imm7 = _s7((b[idx] >> np.uint32(15)) & np.uint32(0x7F))
        combined = add_imm[idx] + imm7 * scale
        aligned = (add_imm[idx] % scale) == 0
        scaled = combined // scale
        fits = aligned & (scaled >= -64) & (scaled <= 63)

        rt = (b[idx] & np.uint32(0x1F)).astype(np.int64)
        rt2 = ((b[idx] >> np.uint32(10)) & np.uint32(0x1F)).astype(np.int64)
        rd = a_rd[idx].astype(np.int64)
        # SIMD&FP data registers live in the other file: they can
        # never alias the integer base, whatever the register number.
        aliases = (rt == rd) | (rt2 == rd)
        if name in FP_FORMS:
            aliases = np.zeros_like(aliases)

        if is_load:
            # A pair load whose destinations cover Rd overwrites the
            # address register: the sum is dead with no scan needed.
            res["fold 2->1 (structural)"] += int((fits & aliases).sum())
            res["fold 2->1 (deferred)"] += int((fits & ~aliases).sum())
        else:
            # A pair store carrying Rd as data never folds: the
            # rewritten store would read the deleted sum.
            res["fold 2->1 (deferred)"] += int((fits & ~aliases).sum())
            res["rejected (store reads the sum)"] += int((fits & aliases).sum())
        res["split 2->2 (offset overflows imm7)"] += int((~fits).sum())
    return res


def selftest():
    entries = [("add_imm_x",) + ADD_IMM_X] + \
              [(n, m_, v, r) for n, m_, v, _s, _l, r in PAIRS]
    src = ["    .text", "    .arch armv8.5-a"]
    src += ["    " + e[3] for e in entries]
    with tempfile.TemporaryDirectory() as td:
        asm, obj = os.path.join(td, "s.s"), os.path.join(td, "s.o")
        with open(asm, "w") as f:
            f.write("\n".join(src) + "\n")
        cc = subprocess.run(["clang", "-arch", "arm64", "-c", "-o", obj, asm],
                            capture_output=True, text=True)
        if cc.returncode:
            print(cc.stderr, file=sys.stderr)
            return 1
        dump = subprocess.run(["otool", "-t", obj], capture_output=True,
                              text=True)
        words = []
        for line in dump.stdout.splitlines()[2:]:
            words += [int(x, 16) for x in line.split()[1:]]
    if len(words) != len(entries):
        print(f"selftest: assembled {len(words)} words for {len(entries)} masks",
              file=sys.stderr)
        return 1

    failures = 0
    for (name, mask, val, ref), word in zip(entries, words):
        matches = (word & mask) == val
        collide = [e[0] for e, w2 in zip(entries, words)
                   if e[0] != name and (w2 & mask) == val]
        ok = matches and not collide
        failures += not ok
        note = ""
        if not matches:
            note = f"  -- does not match its own encoding 0x{word:08X}"
        elif collide:
            note = f"  -- also matches {', '.join(collide)}"
        print(f"  {'ok  ' if ok else 'FAIL'} {name:10s} {ref:22s}"
              f"&0x{mask:08X}==0x{val:08X}{note}")
    print(f"\n{len(entries) - failures}/{len(entries)} masks verified")
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("binaries", nargs="*")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.binaries:
        ap.error("give at least one binary, or --selftest")

    order = ["fold 2->1 (structural)", "fold 2->1 (deferred)",
             "split 2->2 (offset overflows imm7)",
             "rejected (store reads the sum)"]
    grand = collections.Counter()
    width = max(len(k) for k in order) + 2
    names = [os.path.basename(p) for p in args.binaries]
    cols = max(11, max(len(n) for n in names) + 2)
    print(f"{'':{width}}" + "".join(f"{n[:cols-1]:>{cols}}" for n in names)
          + f"{'TOTAL':>10}")
    per = []
    for p in args.binaries:
        r = scan(p)
        per.append(r)
        grand.update(r)
    for k in order:
        row = "".join(f"{r[k]:>{cols},}" for r in per)
        print(f"{k:{width}}{row}{grand[k]:>10,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
