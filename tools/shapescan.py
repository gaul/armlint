#!/usr/bin/env python3
"""shapescan: count candidate instruction shapes across a binary corpus.

Where pairscan ranks *every* adjacent pair by a normalized shape to
discover what is frequent, shapescan counts a fixed list of *specific*
candidates -- the ones TODO.md is tracking -- with their real operand
and encodability conditions applied. That difference matters: a raw
pair count routinely overstates a candidate by one to two orders of
magnitude, because most of the pairs fail a range check, an
encodability check, or a register condition that the normalized shape
throws away. `adrp` + `add` is the standing example: 753,648 adjacent
dependent pairs in the corpus, of which 43,434 have a target inside
ADR's +-1MB reach.

Where a condition was added after the unconditioned figure had already
been published, both are reported as sibling rows -- see the two
`cond-branch +8 over b L` entries, 507 against 2,437. The older number
appears in TODO.md, and the difference should read as a missing test
rather than as the tool disagreeing with the docs.

Usage:
    tools/shapescan.py --selftest             # verify every mask
    tools/shapescan.py BINARY...              # ranked population table
    tools/shapescan.py -e SHAPE BINARY        # print example sites

--selftest is not optional hygiene, and it has two halves.

The precision half assembles a reference instance of each mask with
clang and checks that the mask matches its own instruction and no
*other* instruction in the reference set. A mask one bit too loose
silently matches a neighbouring instruction in the same encoding
class: a MOVI mask that also caught USHLL, an "is this a pure register
write" class that included the BFM aliases (which merge into their
destination, so they read it). Each inflated a reported population by
40x or more.

The recall half, ALSO below, is the other direction, and the more
dangerous one, because its failures are silent. AArch64 spells most
operations more than one way -- both register widths, scaled and
unscaled addressing, integer and SIMD&FP register classes -- and a
mask pinned to one spelling reports a small number rather than a wrong
one, so nothing looks broken. ALSO names every spelling a mask is
meant to cover and the self-test requires each to match. Adding it
found six masks that were counting a fraction of their shape: LDP/STP
that saw no SIMD&FP pair, STR that saw no STUR, and the degenerate
copy spellings that saw only the 32-bit form.

Requires numpy. --selftest additionally requires clang and otool.
"""

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile

try:
    import numpy as np
except ImportError:
    sys.exit("shapescan requires numpy (pip install numpy)")


# === Binary parsing ===
#
# Only the executable text is scanned. Mach-O linker glue (__stubs and
# friends) and ELF .plt sections are deliberately left out for the same
# reason armlint's own scan excludes them: their shape is the dynamic
# linker's business, not the compiler's.

CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19


def _macho_slices(buf):
    """Yield (cputype, offset) for each slice; thin files yield one."""
    magic, = struct.unpack_from(">I", buf, 0)
    if magic in (0xCAFEBABE, 0xCAFEBABF):        # universal, big-endian
        count, = struct.unpack_from(">I", buf, 4)
        wide = magic == 0xCAFEBABF
        entry = 32 if wide else 20
        for i in range(count):
            base = 8 + i * entry
            fmt = ">iiQQI" if wide else ">iiIII"
            cputype, _sub, offset, _size, _align = struct.unpack_from(fmt, buf, base)
            yield cputype, offset
    else:
        yield None, 0


def _macho_text(buf):
    for cputype, off in _macho_slices(buf):
        if cputype is not None and cputype != CPU_TYPE_ARM64:
            continue
        magic, = struct.unpack_from("<I", buf, off)
        if magic != 0xFEEDFACF:                  # 64-bit little-endian only
            continue
        ncmds, = struct.unpack_from("<I", buf, off + 16)
        p = off + 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", buf, p)
            if cmd == LC_SEGMENT_64:
                nsects, = struct.unpack_from("<I", buf, p + 64)
                sp = p + 72
                for _s in range(nsects):
                    sect = buf[sp:sp + 16].rstrip(b"\0")
                    seg = buf[sp + 16:sp + 32].rstrip(b"\0")
                    if sect == b"__text" and seg == b"__TEXT":
                        addr, size = struct.unpack_from("<QQ", buf, sp + 32)
                        foff, = struct.unpack_from("<I", buf, sp + 48)
                        raw = buf[off + foff: off + foff + (size & ~3)]
                        return raw, addr
                    sp += 80
            p += cmdsize
    return None


def _elf_text(buf):
    if buf[:4] != b"\x7fELF" or buf[4] != 2 or buf[5] != 1:
        return None                              # 64-bit little-endian only
    shoff, = struct.unpack_from("<Q", buf, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", buf, 0x3A)
    strhdr = shoff + shstrndx * shentsize
    stroff, = struct.unpack_from("<Q", buf, strhdr + 0x18)
    for i in range(shnum):
        h = shoff + i * shentsize
        name_off, = struct.unpack_from("<I", buf, h)
        end = buf.index(b"\0", stroff + name_off)
        if buf[stroff + name_off:end] == b".text":
            addr, off, size = struct.unpack_from("<QQQ", buf, h + 0x10)
            return buf[off: off + (size & ~3)], addr
    return None


def text_words(path):
    """Return (uint32 array of the executable text, its virtual address)."""
    with open(path, "rb") as f:
        buf = f.read()
    got = _macho_text(buf) or _elf_text(buf)
    if got is None:
        raise ValueError(f"no aarch64 text section in {path}")
    raw, addr = got
    return np.frombuffer(raw, dtype="<u4"), addr


# === Encoding masks ===
#
# Every entry is (mask, value, reference assembly). The reference is
# what --selftest assembles to prove the mask both matches the
# instruction it names and matches nothing else in this table. Any
# further spelling the mask must also cover goes in ALSO below.

MASKS = {
    # Data processing, register forms. Rm = 31 is the zero register.
    "orr_zr":     (0x7FFFFC00, 0x2A1F0000, "orr w0, w1, wzr"),
    "add_zr":     (0x7FFFFC00, 0x0B1F0000, "add w0, w1, wzr"),
    "sub_zr":     (0x7FFFFC00, 0x4B1F0000, "sub w0, w1, wzr"),
    "eor_zr":     (0x7FFFFC00, 0x4A1F0000, "eor w0, w1, wzr"),
    "and_zr":     (0x7FFFFC00, 0x0A1F0000, "and w0, w1, wzr"),
    "mul_zr":     (0x7FFFFC00, 0x1B1F7C00, "mul w0, w1, wzr"),
    # Degenerate width/copy spellings.
    "and_lo32":   (0xFFFFFC00, 0x92407C00, "and x0, x1, #0xffffffff"),
    "ubfx_lo32":  (0xFFFFFC00, 0xD3407C00, "ubfx x0, x1, #0, #32"),
    # LSL #0 and EXTR #0 need one entry per width: the W form is
    # UBFM/EXTR with N = 0 and imms = 31, the X form N = 1 and imms =
    # 63, so no single mask spans them.
    "lsl0_w":     (0xFFFFFC00, 0x53007C00, "lsl w0, w1, #0"),
    "lsl0_x":     (0xFFFFFC00, 0xD340FC00, "lsl x0, x1, #0"),
    "extr_w0":    (0xFFFFFC00, 0x13810000, "extr w0, w1, w1, #0"),
    "extr_x0":    (0xFFFFFC00, 0x93C10000, "extr x0, x1, x1, #0"),
    # Cross-file moves.
    "umov_s0":    (0xFFFFFC00, 0x0E043C00, "umov w0, v1.s[0]"),
    "umov_d0":    (0xFFFFFC00, 0x4E083C00, "umov x0, v1.d[0]"),
    "fmov_to_s":  (0xFFFFFC00, 0x1E270000, "fmov s0, w1"),
    "fmov_to_d":  (0xFFFFFC00, 0x9E670000, "fmov d0, x1"),
    "fmov_from_s": (0xFFFFFC00, 0x1E260000, "fmov w0, s1"),
    "fmov_from_d": (0xFFFFFC00, 0x9E660000, "fmov x0, d1"),
    "fcvtzs_ws":  (0xFFFFFC00, 0x1E380000, "fcvtzs w0, s1"),
    "fcvtzs_xd":  (0xFFFFFC00, 0x9E780000, "fcvtzs x0, d1"),
    # Dead writes: a ZR destination in a non-flag-setting form.
    "add_to_zr":  (0x7FE0FC1F, 0x0B00001F, "add wzr, w1, w2"),
    "sub_to_zr":  (0x7FE0FC1F, 0x4B00001F, "sub wzr, w1, w2"),
    "orr_to_zr":  (0x7FE0FC1F, 0x2A00001F, "orr wzr, w1, w2"),
    "eor_to_zr":  (0x7FE0FC1F, 0x4A00001F, "eor wzr, w1, w2"),
    "and_to_zr":  (0x7FE0FC1F, 0x0A00001F, "and wzr, w1, w2"),
    "madd_to_zr": (0x7FE0801F, 0x1B00001F, "madd wzr, w1, w2, w3"),
    "csel_to_zr": (0x7FE00C1F, 0x1A80001F, "csel wzr, w1, w2, eq"),
    # Branches.
    "bcond":      (0xFF000010, 0x54000000, "b.eq ."),
    "b_uncond":   (0xFC000000, 0x14000000, "b ."),
    "cbz":        (0x7E000000, 0x34000000, "cbz w0, ."),
    "tbz":        (0x7E000000, 0x36000000, "tbz w0, #3, ."),
    # Addressing.
    "adrp":       (0x9F000000, 0x90000000, "adrp x0, Lz@PAGE"),
    "add_imm":    (0x7F800000, 0x11000000, "add w0, w1, #4"),
    "sub_imm":    (0x7F800000, 0x51000000, "sub w0, w1, #4"),
    "ldp":        (0x7EC00000, 0x28400000, "ldp x0, x1, [x2]"),
    "stp":        (0x7EC00000, 0x28000000, "stp x0, x1, [x2]"),
    # The integer masks pin V = 0, so they see no SIMD&FP pair at all --
    # and a Q-register spill through a scratch ADD is the shape LLVM
    # emits most. opc is bits 31..30 and runs 00/01/10 for S/D/Q, so
    # neither bit can be pinned; opc = 11 is unallocated and unreachable.
    "ldp_fp":     (0x3EC00000, 0x2C400000, "ldp q0, q1, [x2, #32]"),
    "stp_fp":     (0x3EC00000, 0x2C000000, "stp q0, q1, [x2, #32]"),
    # A store is a store in all four addressing forms. Pinning bits
    # 25..24 to the unsigned-offset spelling is the mistake that hid
    # LDUR/STUR from the LDP/STP coalescer for as long as it did, so
    # these leave 25..24 (and the register-offset bit 21) free and pin
    # only size, V and opc.
    "str_w_any":  (0xFCC00000, 0xB8000000, "str w0, [x1, #4]"),
    "str_x_any":  (0xFCC00000, 0xF8000000, "str x0, [x1, #8]"),
    # Vector three-same logic. U (bit 29) and size (23..22) separate
    # AND/BIC/ORR/ORN from EOR/BSL/BIT/BIF; both must be pinned.
    "v_and":      (0xBFE0FC00, 0x0E201C00, "and v0.16b, v1.16b, v2.16b"),
    "v_bic":      (0xBFE0FC00, 0x0E601C00, "bic v0.16b, v1.16b, v2.16b"),
    "v_orr":      (0xBFE0FC00, 0x0EA01C00, "orr v0.16b, v1.16b, v2.16b"),
    "v_eor":      (0xBFE0FC00, 0x2E201C00, "eor v0.16b, v1.16b, v2.16b"),
    "v_sub":      (0xBF20FC00, 0x2E208400, "sub v0.4s, v1.4s, v2.4s"),
    "v_mul":      (0xBF20FC00, 0x0E209C00, "mul v0.4s, v1.4s, v2.4s"),
    "v_fmul":     (0xBF20FC00, 0x2E20DC00, "fmul v0.4s, v1.4s, v2.4s"),
    "v_mla":      (0xBF20FC00, 0x0E209400, "mla v0.4s, v1.4s, v2.4s"),
    "v_fmla":     (0xBF20FC00, 0x0E20CC00, "fmla v0.4s, v1.4s, v2.4s"),
    "v_dup_elem": (0xBF20FC00, 0x0E000400, "dup v0.4s, v1.s[1]"),
    # MOVI/MVNI need bits 28..19 pinned: a mask that stops at bit 23
    # also matches USHLL/SHLL, which sit in the neighbouring
    # shift-by-immediate class. Bit 29 is the op bit, so it has to be
    # pinned as well or MVNI reads as MOVI.
    "v_movi":     (0xBFF80C00, 0x0F000400, "movi v0.4s, #1"),
    # op (bit 29) alone does not separate MOVI from MVNI: with cmode =
    # 1110 an op of 1 is the 64-bit MOVI (`movi v0.2d, #0`), and with
    # cmode = 1111 it is the vector FMOV. So this entry is the op = 1
    # half of the immediate-move class, not MVNI alone. Both shapes
    # that use it take the union with v_movi, so the count is right;
    # the name is the approximation.
    "v_mvni":     (0xBFF80C00, 0x2F000400, "mvni v0.4s, #1"),
}


# === Recall references ===
#
# The spellings each mask must ALSO match. The collision half of
# --selftest proves a mask is not too loose; nothing proves a mask is
# not too NARROW unless a second spelling of the same operation is
# assembled and required to match, because a narrow mask fails by
# reporting a small population rather than a wrong one.
#
# The rule for adding an entry: it must be a genuinely different
# encoding of an instruction the shape's rewrite would accept, not a
# different assembler spelling of the same bits. `ubfm x0, x1, #0, #31`
# adds nothing over `ubfx x0, x1, #0, #32`; `stur w0, [x1, #-4]` adds a
# whole addressing class.

ALSO = {
    # sf is free in the ZR-operand and ZR-destination masks, so both
    # register widths must land.
    "orr_zr":     ("orr x0, x1, xzr",),
    "add_zr":     ("add x0, x1, xzr",),
    "sub_zr":     ("sub x0, x1, xzr",),
    "eor_zr":     ("eor x0, x1, xzr",),
    "and_zr":     ("and x0, x1, xzr",),
    "mul_zr":     ("mul x0, x1, xzr",),
    "add_to_zr":  ("add xzr, x1, x2",),
    "sub_to_zr":  ("sub xzr, x1, x2",),
    "orr_to_zr":  ("orr xzr, x1, x2",),
    "eor_to_zr":  ("eor xzr, x1, x2",),
    "and_to_zr":  ("and xzr, x1, x2",),
    "madd_to_zr": ("madd xzr, x1, x2, x3",),
    "csel_to_zr": ("csel xzr, x1, x2, ne",),
    # cond (bits 3..0) is free below the bit-4 pin that keeps BC.cond out.
    "bcond":      ("b.ne .",),
    # op (bit 24) and sf are both free: CBNZ and TBNZ count too.
    "cbz":        ("cbnz x0, .",),
    "tbz":        ("tbnz x0, #40, .",),
    # Both widths, and the lsl #12 shift (bit 22).
    "add_imm":    ("add x0, x1, #4", "add x0, x1, #4, lsl #12"),
    "sub_imm":    ("sub x0, x1, #4", "sub x0, x1, #4, lsl #12"),
    # Integer pairs are W or X; opc = 01 is LDPSW, which has its own
    # fold and is deliberately out of this entry.
    "ldp":        ("ldp w0, w1, [x2]",),
    "stp":        ("stp w0, w1, [x2]",),
    "ldp_fp":     ("ldp s0, s1, [x2]", "ldp d0, d1, [x2, #16]"),
    "stp_fp":     ("stp s0, s1, [x2]", "stp d0, d1, [x2, #16]"),
    # All four addressing forms of the same store.
    "str_w_any":  ("stur w0, [x1, #-4]", "str w0, [x1], #4",
                   "str w0, [x1, #4]!", "str w0, [x1, x2]"),
    "str_x_any":  ("stur x0, [x1, #-8]", "str x0, [x1], #8",
                   "str x0, [x1, #8]!", "str x0, [x1, x2]"),
    # Q (bit 30) is free in the three-same classes, and size (23..22) in
    # those that pin only the opcode.
    "v_and":      ("and v0.8b, v1.8b, v2.8b",),
    "v_bic":      ("bic v0.8b, v1.8b, v2.8b",),
    "v_orr":      ("orr v0.8b, v1.8b, v2.8b",),
    "v_eor":      ("eor v0.8b, v1.8b, v2.8b",),
    "v_sub":      ("sub v0.16b, v1.16b, v2.16b", "sub v0.2d, v1.2d, v2.2d"),
    "v_mul":      ("mul v0.8b, v1.8b, v2.8b",),
    "v_fmul":     ("fmul v0.2d, v1.2d, v2.2d",),
    "v_mla":      ("mla v0.8h, v1.8h, v2.8h",),
    "v_fmla":     ("fmla v0.2d, v1.2d, v2.2d",),
    "v_dup_elem": ("dup v0.2d, v1.d[1]", "dup v0.8b, v1.b[3]"),
    # cmode (bits 15..12) is free, which is the whole immediate range.
    "v_movi":     ("movi v0.16b, #1", "movi v0.8h, #1",
                   "movi v0.4s, #1, lsl #8"),
    "v_mvni":     ("mvni v0.8h, #1", "mvni v0.4s, #1, lsl #8",
                   "movi v0.2d, #0"),
}


def m(w, key):
    mask, val, _ref = MASKS[key]
    return (w & np.uint32(mask)) == np.uint32(val)


def any_of(w, *keys):
    out = m(w, keys[0])
    for k in keys[1:]:
        out = out | m(w, k)
    return out


def rd(w): return w & np.uint32(0x1F)
def rn(w): return (w >> np.uint32(5)) & np.uint32(0x1F)
def rm(w): return (w >> np.uint32(16)) & np.uint32(0x1F)
def ra(w): return (w >> np.uint32(10)) & np.uint32(0x1F)
def sf(w): return (w >> np.uint32(31)) & np.uint32(1)


def _sext(v, bits):
    lim = 1 << (bits - 1)
    return np.where(v >= lim, v - (1 << bits), v)


# === Shape definitions ===
#
# Each takes a context with `w` (all words), `a`/`b` (the two halves of
# every adjacent pair) and `addr` (the text's virtual address), and
# returns a boolean array. For a pair shape the array is indexed by the
# FIRST instruction of the pair.

class Ctx:
    def __init__(self, words, addr):
        self.w = words
        self.a = words[:-1]
        self.b = words[1:]
        self.addr = addr


def s_zr_operand(c):
    w = c.w
    out = np.zeros(len(w), dtype=bool)
    for k in ("orr_zr", "add_zr", "sub_zr", "eor_zr", "and_zr"):
        out |= m(w, k) & (rd(w) != 31) & (rn(w) != 31)
    return out | (m(w, "mul_zr") & (rd(w) != 31))


def s_and_lo32(c):
    return any_of(c.w, "and_lo32", "ubfx_lo32") & (rd(c.w) != 31)


def s_degenerate_copy(c):
    w = c.w
    return any_of(w, "lsl0_w", "lsl0_x") \
        | (any_of(w, "extr_w0", "extr_x0") & (rm(w) == rn(w)))


def s_umov(c):
    return any_of(c.w, "umov_s0", "umov_d0")


def s_dead_zr_write(c):
    w = c.w
    return any_of(w, "add_to_zr", "sub_to_zr", "orr_to_zr", "eor_to_zr",
                  "and_to_zr", "madd_to_zr", "csel_to_zr")


def s_constant_branch(c):
    w = c.w
    always = m(w, "bcond") & ((w & np.uint32(0xF)) >= np.uint32(14))
    return always | (any_of(w, "cbz", "tbz") & (rd(w) == 31))


def s_vector_selfop(c):
    # `orr Vd, Vn, Vn` with Rd != Rn is the canonical vector MOV
    # spelling, not a foldable self-op; only the Rd == Rn form (a pure
    # no-op) and the genuinely collapsing ops belong here.
    w = c.w
    same = rn(w) == rm(w)
    return ((m(w, "v_eor") | m(w, "v_sub") | m(w, "v_and")) & same) \
        | (m(w, "v_orr") & same & (rd(w) == rn(w)))


def _pure_writer(x):
    """Instructions whose destination is written without being read.

    BFM (BFI/BFXIL) is deliberately absent: it merges into its
    destination, so the destination is a source too. Including it makes
    every bitfield-insert chain look like a dead write.

    These masks are built inline rather than through MASKS, so
    --selftest never sees them -- which is how the CSEL mask below kept
    a loose bit for two days. Anything added here is unverified by
    construction; prefer a registry entry when the shape has one.

    A mask must also pin the bits that separate its class from
    UNALLOCATED space, not just from its neighbours. --selftest cannot
    help with that half even for a registry mask: its precision test
    asks whether a mask matches some *other reference instruction*, and
    an unallocated encoding is in nobody's reference set. It passes,
    and the scanner reports data as code.
    """
    k = m(x, "add_imm") | m(x, "sub_imm")
    k |= (x & np.uint32(0x7F800000)) == np.uint32(0x52800000)   # movz
    k |= (x & np.uint32(0x7F800000)) == np.uint32(0x12800000)   # movn
    for base in (0x0B000000, 0x4B000000, 0x0A000000, 0x2A000000, 0x4A000000):
        k |= (x & np.uint32(0x7F200000)) == np.uint32(base)     # ALU, shifted reg
    for base in (0x12000000, 0x32000000, 0x52000000):
        k |= (x & np.uint32(0x7F800000)) == np.uint32(base)     # logical imm
    k |= (x & np.uint32(0x7F208000)) == np.uint32(0x1B000000)   # madd
    k |= (x & np.uint32(0x7F208000)) == np.uint32(0x1B008000)   # msub
    for base in (0x53000000, 0x13000000):
        k |= (x & np.uint32(0x7F800000)) == np.uint32(base)     # ubfm/sbfm
    # CSEL family: sf op S 11010100 Rm cond op2 Rn Rd, with op2 at bits
    # 11..10 selecting CSEL/CSINV (00) and CSINC/CSNEG (01). op2 = 1x is
    # unallocated, so bit 11 belongs in the mask -- armlint.c's own
    # matcher (check_mov_zero_to_xzr arm (d)) has always pinned it.
    # Leaving it free matched 0x5A827999, which is not an instruction at
    # all: it is SHA-1's round constant K1, four copies of it in the
    # literal pool at the head of libcrypto's and dyld's __text. That
    # accounted for 6 of this shape's 10 reported sites, none of which
    # armlint could ever report -- Capstone refuses the word, so the
    # driver skips it as data.
    for base in (0x1A800000, 0x5A800000):
        k |= (x & np.uint32(0x7FE00800)) == np.uint32(base)     # csel family
    return k


def _reads(x, reg):
    movw = ((x & np.uint32(0x7F800000)) == np.uint32(0x52800000)) \
        | ((x & np.uint32(0x7F800000)) == np.uint32(0x12800000))
    has_rm = np.zeros(len(x), dtype=bool)
    for base in (0x0B000000, 0x4B000000, 0x0A000000, 0x2A000000, 0x4A000000):
        has_rm |= (x & np.uint32(0x7F200000)) == np.uint32(base)
    has_ra = ((x & np.uint32(0x7F208000)) == np.uint32(0x1B000000)) \
        | ((x & np.uint32(0x7F208000)) == np.uint32(0x1B008000))
    has_rm |= has_ra
    for base in (0x1A800000, 0x5A800000):
        has_rm |= (x & np.uint32(0x7FE00800)) == np.uint32(base)
    return ((~movw) & (rn(x) == reg)) | (has_rm & (rm(x) == reg)) \
        | (has_ra & (ra(x) == reg))


def s_waw(c):
    a, b = c.a, c.b
    return _pure_writer(a) & _pure_writer(b) & (rd(b) == rd(a)) \
        & (rd(a) != 31) & ~_reads(b, rd(a))


def _addsub_chain(c):
    """Adjacent add/sub immediates on the same register whose sum encodes.

    The compiler's own split of a wide constant (`add x8, x8, #0x1,
    lsl #12 ; add x8, x8, #0x20`) is already minimal; it falls out here
    without a special case, because its sum is neither an imm12 nor a
    multiple of 4096.
    """
    a, b = c.a, c.b
    sh = lambda x: (x >> np.uint32(22)) & np.uint32(1)
    imm = lambda x: np.where(
        sh(x) == 1,
        ((x >> np.uint32(10)) & np.uint32(0xFFF)).astype(np.int64) << 12,
        ((x >> np.uint32(10)) & np.uint32(0xFFF)).astype(np.int64))
    sgn = lambda x: np.where(m(x, "sub_imm"), -1, 1)
    pair = (m(a, "add_imm") | m(a, "sub_imm")) \
        & (m(b, "add_imm") | m(b, "sub_imm")) \
        & (rn(b) == rd(a)) & (sf(a) == sf(b))
    mag = np.abs(sgn(a) * imm(a) + sgn(b) * imm(b))
    encodes = (mag <= 4095) | (((mag & 0xFFF) == 0) & ((mag >> 12) <= 4095))
    return pair & encodes


def s_addsub_structural(c):
    return _addsub_chain(c) & (rd(c.b) == rd(c.a))


def s_addsub_deferred(c):
    return _addsub_chain(c) & (rd(c.b) != rd(c.a))


def s_adrp_add_in_range(c):
    """adrp + add whose resolved target is inside ADR's +-1MB reach.

    Counting the pair alone overstates this candidate roughly 17x: most
    adrp targets are megabytes away in another segment.
    """
    a, b = c.a, c.b
    pair = m(a, "adrp") & m(b, "add_imm") & (rn(b) == rd(a))
    immlo = ((a >> np.uint32(29)) & np.uint32(3)).astype(np.int64)
    immhi = ((a >> np.uint32(5)) & np.uint32(0x7FFFF)).astype(np.int64)
    page = _sext((immhi << 2) | immlo, 21)
    pc = c.addr + 4 * np.arange(len(a), dtype=np.int64)
    lo = ((b >> np.uint32(10)) & np.uint32(0xFFF)).astype(np.int64)
    disp = (pc & ~np.int64(0xFFF)) + (page << 12) + lo - pc
    return pair & (disp >= -(1 << 20)) & (disp < (1 << 20))


def s_ldp_via_scratch(c):
    a, b = c.a, c.b
    return m(a, "add_imm") & any_of(b, "ldp", "stp", "ldp_fp", "stp_fp") \
        & (rn(b) == rd(a)) & (rd(a) != 31)


def _branch_over_b(c):
    """The `cond +8 ; b L` shape, saying nothing about where L is.

    Returns (matched, is_narrow); is_narrow marks the TBZ/TBNZ members,
    whose displacement field is four bits shorter than the others'.
    """
    a, b = c.a, c.b
    i19 = _sext(((a >> np.uint32(5)) & np.uint32(0x7FFFF)).astype(np.int64), 19)
    i14 = _sext(((a >> np.uint32(5)) & np.uint32(0x3FFF)).astype(np.int64), 14)
    narrow = m(a, "tbz") & (i14 == 2)
    wide = (m(a, "bcond") | m(a, "cbz")) & (i19 == 2)
    return (wide | narrow) & m(b, "b_uncond"), narrow


def s_branch_over_b(c):
    """... and whether the inverted branch can still reach it.

    The fold moves the target from the unconditional branch's imm26
    (+-128MB) onto the conditional's own field: imm19 (+-1MB) for
    B.cond and CBZ/CBNZ, imm14 (+-32KB) for TBZ/TBNZ. A target outside
    the narrower range cannot be expressed at all, so the site is not a
    candidate however sound the rewrite would otherwise be.

    This bites hardest exactly where the shape is most common. The
    `tbz +8 ; b L` idiom exists BECAUSE the compiler needed a target
    beyond TBZ's reach, so folding it back is impossible almost by
    construction: 43 of librustc_driver's 1,803 such sites reach,
    against 464 of 634 for the imm19 forms.
    """
    hit, narrow = _branch_over_b(c)
    # The rewritten conditional sits where the original one did, so it
    # spans one instruction more than the unconditional branch did.
    disp = _sext((c.b & np.uint32(0x3FFFFFF)).astype(np.int64), 26) + 1
    lim = np.where(narrow, np.int64(1) << 13, np.int64(1) << 18)
    return hit & (disp >= -lim) & (disp <= lim - 1)


def s_branch_over_b_any(c):
    """The shape with no range test -- the figure published before it."""
    return _branch_over_b(c)[0]


def s_dup_by_element(c):
    a, b = c.a, c.b
    consumer = any_of(b, "v_mul", "v_fmul", "v_mla", "v_fmla")
    return m(a, "v_dup_elem") & consumer & ((rm(b) == rd(a)) | (rn(b) == rd(a)))


def s_movi_vector_logic(c):
    a, b = c.a, c.b
    return any_of(a, "v_movi", "v_mvni") & any_of(b, "v_and", "v_orr", "v_bic") \
        & ((rm(b) == rd(a)) | (rn(b) == rd(a)))


def s_fmov_roundtrip(c):
    a, b = c.a, c.b
    to_fp = lambda x: any_of(x, "fmov_to_s", "fmov_to_d")
    to_gp = lambda x: any_of(x, "fmov_from_s", "fmov_from_d")
    return ((to_fp(a) & to_gp(b)) | (to_gp(a) & to_fp(b))) & (rn(b) == rd(a))


def s_fcvtzs_str(c):
    a, b = c.a, c.b
    return any_of(a, "fcvtzs_ws", "fcvtzs_xd") \
        & any_of(b, "str_w_any", "str_x_any") & (rd(b) == rd(a))


# label -> (is_pair, predicate). Labels match the TODO.md rows.
SHAPES = [
    ("adrp + add -> adr, target in +-1MB", True, s_adrp_add_in_range),
    ("add/sub #a ; add/sub #b, needs dead-producer scan", True, s_addsub_deferred),
    ("add/sub #a ; add/sub #b, sum encodes + temp dies", True, s_addsub_structural),
    ("add scratch,#big ; ldp/stp [scratch]", True, s_ldp_via_scratch),
    ("cond-branch +8 over b L (issue #7)", True, s_branch_over_b),
    ("cond-branch +8 over b L (target unchecked)", True, s_branch_over_b_any),
    ("umov Wd,Vn.s[0] / Xd,Vn.d[0] -> fmov", False, s_umov),
    ("vector self-op -> movi #0 / mov", False, s_vector_selfop),
    ("ZR-operand ALU spelling -> mov / mov #0", False, s_zr_operand),
    ("and #0xffffffff / ubfx #0,#32 -> mov Wd,Wn", False, s_and_lo32),
    ("movi/mvni + vector and/orr/bic", True, s_movi_vector_logic),
    ("constant-condition branch", False, s_constant_branch),
    ("pure write immediately clobbered", True, s_waw),
    ("fcvtzs Wd,Sn ; str Wd", True, s_fcvtzs_str),
    ("degenerate lsl #0 / extr #0 -> mov", False, s_degenerate_copy),
    ("side-effect-free write to a ZR destination", False, s_dead_zr_write),
    ("dup Vt,Vn.e[i] + mul/fmul/mla/fmla", True, s_dup_by_element),
    ("fmov GPR<->FP round trip", True, s_fmov_roundtrip),
]


# === Self-test ===

def _assemble(lines):
    """Assemble one instruction per line; return their encodings."""
    src = ["    .text", "    .arch armv8.5-a", "Lz:"] + ["    " + l for l in lines]
    with tempfile.TemporaryDirectory() as td:
        asm, obj = os.path.join(td, "s.s"), os.path.join(td, "s.o")
        with open(asm, "w") as f:
            f.write("\n".join(src) + "\n")
        cc = subprocess.run(["clang", "-arch", "arm64", "-c", "-o", obj, asm],
                            capture_output=True, text=True)
        if cc.returncode:
            print(cc.stderr, file=sys.stderr)
            return None
        dump = subprocess.run(["otool", "-t", obj], capture_output=True, text=True)
        words = []
        for line in dump.stdout.splitlines()[2:]:
            words += [int(x, 16) for x in line.split()[1:]]
    if len(words) != len(lines):
        print(f"selftest: assembled {len(words)} words for {len(lines)} lines",
              file=sys.stderr)
        return None
    return words


def selftest():
    """Check every mask for recall (ALSO) and precision (collisions)."""
    refs = []                       # (owning key, assembly)
    for key in MASKS:
        refs.append((key, MASKS[key][2]))
        for extra in ALSO.get(key, ()):
            refs.append((key, extra))
    unknown = set(ALSO) - set(MASKS)
    if unknown:
        print(f"selftest: ALSO names masks that do not exist: "
              f"{', '.join(sorted(unknown))}", file=sys.stderr)
        return 1
    words = _assemble([a for _k, a in refs])
    if words is None:
        return 1

    failures = 0
    for key in MASKS:
        mask, val, ref = MASKS[key]
        mine = [(a, w) for (o, a), w in zip(refs, words) if o == key]
        misses = [(a, w) for a, w in mine if (w & mask) != val]
        collide = [(o, a) for (o, a), w in zip(refs, words)
                   if o != key and (w & mask) == val]
        ok = not misses and not collide
        failures += not ok
        extra = f"  +{len(mine) - 1}" if len(mine) > 1 else "    "
        print(f"  {'ok  ' if ok else 'FAIL'} {key:12s} {ref:34s}"
              f"&0x{mask:08X}==0x{val:08X}{extra}")
        for a, w in misses:
            print(f"         misses {a!r} (0x{w:08X})")
        for o, a in collide:
            print(f"         also matches {a!r}, which belongs to {o}")

    print(f"\n{len(MASKS) - failures}/{len(MASKS)} masks verified against "
          f"{len(refs)} reference instructions "
          f"({len(refs) - len(MASKS)} of them recall references)")
    return 1 if failures else 0


# === Reporting ===

def examples(path, label, limit):
    match = [s for s in SHAPES if s[0].startswith(label)]
    if len(match) != 1:
        names = "\n  ".join(s[0] for s in SHAPES)
        sys.exit(f"-e must name exactly one shape; known shapes:\n  {names}")
    name, is_pair, fn = match[0]
    words, addr = text_words(path)
    hits = np.flatnonzero(fn(Ctx(words, addr)))[:limit]
    dis = subprocess.run(["otool", "-tv", path], capture_output=True, text=True).stdout
    table = {}
    for line in dis.splitlines():
        parts = line.split("\t")
        head = parts[0].strip()
        if len(parts) >= 2 and head and re.fullmatch(r"[0-9a-f]+", head):
            table[int(head, 16)] = "\t".join(p for p in parts[1:] if p)
    print(f"{name}: {int(np.count_nonzero(fn(Ctx(words, addr)))):,} "
          f"in {os.path.basename(path)}")
    for i in hits:
        at = addr + 4 * int(i)
        line = f"  {at:#010x}: {table.get(at, '?')}"
        if is_pair:
            line += f"   ;;   {table.get(at + 4, '?')}"
        print(line)


def report(paths):
    counts, totals = {}, {}
    for path in paths:
        words, addr = text_words(path)
        ctx = Ctx(words, addr)
        name = os.path.basename(path)
        totals[name] = len(words)
        counts[name] = {label: int(np.count_nonzero(fn(ctx)))
                        for label, _pair, fn in SHAPES}
    names = list(counts)
    grand = sum(totals.values())
    width = max(len(s[0]) for s in SHAPES) + 2
    print(f"{'shape':{width}s}" + "".join(f"{n[:10]:>12s}" for n in names)
          + f"{'TOTAL':>10s}")
    print(f"{'instructions':{width}s}" + "".join(f"{totals[n]:>12,}" for n in names)
          + f"{grand:>10,}")
    print("-" * (width + 12 * len(names) + 10))
    for label, _pair, _fn in sorted(
            SHAPES, key=lambda s: -sum(counts[n][s[0]] for n in names)):
        total = sum(counts[n][label] for n in names)
        print(f"{label:{width}s}" + "".join(f"{counts[n][label]:>12,}" for n in names)
              + f"{total:>10,}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true",
                    help="verify every mask against the assembler and exit")
    ap.add_argument("-e", "--examples", metavar="SHAPE",
                    help="print example sites for the named shape (prefix match)")
    ap.add_argument("-n", type=int, default=8, help="examples to print (default 8)")
    ap.add_argument("binaries", nargs="*")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.binaries:
        ap.error("give at least one binary, or --selftest")
    if args.examples:
        for path in args.binaries:
            examples(path, args.examples, args.n)
        return 0
    report(args.binaries)
    return 0


if __name__ == "__main__":
    sys.exit(main())
