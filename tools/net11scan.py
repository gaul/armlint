#!/usr/bin/env python3
"""net11scan: census of the candidates TODO.md takes from the .NET 11 post.

"Performance Improvements in .NET 11" (devblogs.microsoft.com, 2026) shows
Arm64 diffs for code the new JIT stopped emitting. Most are shapes armlint
already folds; this scanner counts the rest, with the operand conditions
each rewrite needs, over the same Mach-O and ELF inputs as shapescan plus
the multi-section ELF objects that tools/v8dump2elf.py and
tools/smdump2elf.py build from JIT dumps (every executable section is
scanned, with a UDF word between sections so no shape straddles two).

Each shape prints two columns. ALL is every match of the shape with its
encodability or equivalence condition applied. STRICT is the subset whose
rewrite needs no further proof beyond what the column says:

  asr_and        asr Rd, Rs, #n ; and Rd2, Rd, #(2^w-1), n+w <= size
                 -> ubfx Rd2, Rs, #n, #w.            STRICT: Rd2 == Rd
  lsr_and_ref    the LSR twin, which check_lsr_and_to_ubfx takes only
                 in place.                            STRICT: Rd2 == Rd
  cmp_zext_hi    mov Xc, #C (2^32-4095 <= C < 2^32) ; cmp Xn, Xc
                 -> cmn Wn, #(2^32-C) when Xn's top half is zero.
                 STRICT: a W-form producer of Xn in the 4 insns before
  cmeq0_not      cmeq Vd, Vn, #0 (or cmtst Vd, Vn, Vn) ; not Vd2, Vd
                 -> cmtst Vd2, Vn, Vn (cmeq #0).     STRICT: Vd2 == Vd
  and_and_orr    and t1, x, #a ; and t2, x, #b ; orr d, t1, t2
                 -> and d, x, #(a|b).                STRICT: a|b encodes
  smull_ovf      lsr/asr Xa, Xb, #32 ; cmp Wa, Wb, asr #31
                 -> cmp Xb, Wb, sxtw (EQ/NE).         STRICT: = ALL
  cmp_sxtw_ref   cmp Xb, Wb, sxtw, the folded form, for reference
  stp_xzr_run    runs of stp xzr, xzr over consecutive 16-byte slots
                 -> movi + stp q.                     STRICT: runs >= 4
  csel_zr_zr     csel Rd, zr, zr, cond -> mov Rd, #0.  STRICT: = ALL
  neg_zero_test  neg Rt, Rn ; cbz/cbnz Rt (or cmp Rt, #0)
                 -> test Rn.                          STRICT: the CB forms
  ccmp_chain     cmp/cmn Rn, #a ; ccmp/ccmn Rn, #b, ... ; first flag
                 reader.  STRICT: the chain decides exactly what one
                 cmp/cmn Rn, #k does under some condition
  mask_chain     and/uxt*/sxt*/mov Wd,Wm ; an and/ands/tst/uxt*/sxt* of its
                 result that reads only what the first passed through,
                 or a second mask -> one instruction (see the model
                 above s_mask_chain).                 STRICT: in place

No deadness, side-entry or flag-liveness proof is applied, so ALL is a
ceiling on findings, not a prediction of them.

Usage:
    tools/net11scan.py --selftest           # recall and precision per shape
    tools/net11scan.py BINARY...            # ALL/STRICT table
    tools/net11scan.py -e SHAPE BINARY      # example sites

--selftest assembles positive and near-miss references with clang and
checks each shape matches every positive spelling (recall) and none of
the near misses (precision) -- the two-sided discipline TODO.md sets for
shapescan -- and checks the mask-chain model's one-instruction rewrite
against the two-instruction chain for every pair it classifies among a
spread of 863 AND/ANDS/UBFM/SBFM/MOV encodings.  Examples disassemble with
llvm-mc when LLVM_MC or PATH has one, and print raw words otherwise.
Requires numpy.
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shapescan import _macho_text  # noqa: E402

import numpy as np  # noqa: E402

U = np.uint32


# === Loading ===

def _elf_exec_sections(buf):
    if buf[:4] != b"\x7fELF" or buf[4] != 2 or buf[5] != 1:
        return None
    shoff, = struct.unpack_from("<Q", buf, 0x28)
    shentsize, shnum, _ = struct.unpack_from("<HHH", buf, 0x3A)
    parts = []
    for i in range(shnum):
        h = shoff + i * shentsize
        sh_type, sh_flags = struct.unpack_from("<IQ", buf, h + 4)
        addr, off, size = struct.unpack_from("<QQQ", buf, h + 0x10)
        if sh_type == 1 and (sh_flags & 0x4) and size >= 4:   # PROGBITS, EXECINSTR
            parts.append((addr, buf[off: off + (size & ~3)]))
    return parts


def load(path):
    """(words, addresses) of the executable code in PATH."""
    with open(path, "rb") as f:
        buf = f.read()
    got = _macho_text(buf)
    if got is not None:
        raw, addr = got
        w = np.frombuffer(raw, dtype="<u4").copy()
        return w, addr + 4 * np.arange(len(w), dtype=np.uint64)
    parts = _elf_exec_sections(buf)
    if not parts:
        raise ValueError(f"no aarch64 code in {path}")
    ws, adrs = [], []
    for addr, raw in parts:
        w = np.frombuffer(raw, dtype="<u4")
        ws.append(w)
        adrs.append(addr + 4 * np.arange(len(w), dtype=np.uint64))
        ws.append(np.zeros(1, dtype=np.uint32))                  # UDF separator
        adrs.append(np.zeros(1, dtype=np.uint64))
    return np.concatenate(ws), np.concatenate(adrs)


# === Fields and immediates ===

def fld(w, sh, n):
    return (w >> U(sh)) & U((1 << n) - 1)


def rd(x): return fld(x, 0, 5)
def rn(x): return fld(x, 5, 5)
def rm(x): return fld(x, 16, 5)
def sf(x): return fld(x, 31, 1)
def immr(x): return fld(x, 16, 6)
def imms(x): return fld(x, 10, 6)


def decode_bitmask(n, r, s, width):
    """DecodeBitMasks' wmask, or None for a reserved encoding."""
    x = (n << 6) | (~s & 0x3F)
    if x == 0:
        return None
    esize = 1 << (x.bit_length() - 1)
    if esize > width:
        return None
    levels = esize - 1
    s, r = s & levels, r & levels
    if s == levels:
        return None
    elem = (1 << (s + 1)) - 1
    elem = ((elem >> r) | (elem << (esize - r))) & ((1 << esize) - 1)
    v = 0
    for i in range(width // esize):
        v |= elem << (i * esize)
    return v


_ENCODABLE = {}


def encodable(v, width):
    """Is V a logical immediate at WIDTH?"""
    key = (v, width)
    if key not in _ENCODABLE:
        _ENCODABLE[key] = any(
            decode_bitmask(n, r, s, width) == v
            for n in ((0, 1) if width == 64 else (0,))
            for r in range(64 if n else 32) for s in range(64))
    return _ENCODABLE[key]


def logimm_value(x):
    x = int(x)
    width = 64 if x >> 31 else 32
    return decode_bitmask((x >> 22) & 1, (x >> 16) & 63, (x >> 10) & 63, width), width


def is_logimm(x, opc):
    """Logical (immediate), opc AND=0 ORR=1 EOR=2 ANDS=3; N=1 only at X."""
    return ((fld(x, 23, 6) == U(0b100100)) & (fld(x, 29, 2) == U(opc))
            & ((fld(x, 22, 1) == U(0)) | (sf(x) == U(1))))


def is_bfm(x, opc):
    """Bitfield, opc SBFM=0 BFM=1 UBFM=2, with N == sf."""
    return ((fld(x, 23, 6) == U(0b100110)) & (fld(x, 29, 2) == U(opc))
            & (fld(x, 22, 1) == sf(x)))


def is_lowmask_and(x):
    """AND Rd, Rn, #(2^w - 1) with 1 <= w < datasize."""
    return (is_logimm(x, 0) & (immr(x) == U(0)) & (fld(x, 22, 1) == sf(x))
            & (imms(x) < (U(31) + U(32) * sf(x))))


# === Shapes ===
#
# Each takes the word array and returns (all, strict) boolean arrays
# indexed by the shape's first instruction.

SHAPES = {}


def shape(name):
    def deco(fn):
        SHAPES[name] = fn
        return fn
    return deco


@shape("asr_and")
def s_asr_and(w):
    a, b = w[:-1], w[1:]
    top = U(31) + U(32) * sf(a)
    asr = is_bfm(a, 0) & (imms(a) == top) & (immr(a) != U(0))
    m = asr & is_lowmask_and(b) & (rn(b) == rd(a)) & (sf(a) == sf(b))
    m &= (immr(a) + imms(b) + U(1)) <= top + U(1)                # n + w <= size
    return m, m & (rd(b) == rd(a))


@shape("lsr_and_ref")
def s_lsr_and(w):
    a, b = w[:-1], w[1:]
    top = U(31) + U(32) * sf(a)
    lsr = is_bfm(a, 2) & (imms(a) == top) & (immr(a) != U(0))
    m = lsr & is_lowmask_and(b) & (rn(b) == rd(a)) & (sf(a) == sf(b))
    return m, m & (rd(b) == rd(a))


def _const_value(x):
    """Value one constant-materializing instruction leaves in the X
    register (W forms zero-extended), else None."""
    x = int(x)
    if (x & 0x7F8003E0) == 0x320003E0:                           # ORR Rd, ZR, #imm
        return logimm_value(x)[0]
    hw = (x >> 21) & 3
    imm = ((x >> 5) & 0xFFFF) << (16 * hw)
    if (x & 0x7F800000) == 0x52800000:                           # MOVZ
        return imm if (x >> 31) or hw < 2 else None
    if (x & 0x7F800000) == 0x12800000:                           # MOVN
        if x >> 31:
            return ~imm & 0xFFFFFFFFFFFFFFFF
        return (~imm & 0xFFFFFFFF) if hw < 2 else None
    return None


def _writes_w(p):
    """Does P write a W register, zeroing bits 63..32 of its X register?"""
    if (p >> 31) == 0 and ((p >> 26) & 7) == 0b100:             # DP-imm, sf=0
        return True
    if (p >> 31) == 0 and ((p >> 25) & 7) == 0b101:             # DP-reg, sf=0
        return True
    # LDRB/LDRH/LDR W (every addressing mode): size != 11, V=0, opc=01
    return (((p >> 27) & 7) == 7 and ((p >> 26) & 1) == 0
            and ((p >> 22) & 3) == 1 and ((p >> 30) & 3) != 3)


@shape("cmp_zext_hi")
def s_cmp_zext_hi(w):
    a, b = w[:-1], w[1:]
    cmpx = (b & U(0xFFE0FC1F)) == U(0xEB00001F)                  # cmp Xn, Xm (LSL #0)
    const = (((a & U(0x7F800000)) == U(0x52800000))
             | ((a & U(0x7F800000)) == U(0x12800000))
             | ((a & U(0x7F8003E0)) == U(0x320003E0)))
    cand = const & cmpx & (rm(b) == rd(a)) & (rn(b) != rd(a))
    m = np.zeros(len(a), dtype=bool)
    z = np.zeros(len(a), dtype=bool)
    for i in np.flatnonzero(cand):
        c = _const_value(a[i])
        if c is None or not (2**32 - 4095 <= c <= 2**32 - 1):
            continue
        m[i] = True
        n = int(rn(b[i]))
        for j in range(i - 1, max(i - 5, -1), -1):
            p = int(w[j])
            if (p & 31) == n:
                z[i] = _writes_w(p)
                break
    return m, z


@shape("cmeq0_not")
def s_cmeq0_not(w):
    a, b = w[:-1], w[1:]
    cmeq0 = (a & U(0xBF3FFC00)) == U(0x0E209800)
    cmtst_self = ((a & U(0xBF20FC00)) == U(0x0E208C00)) & (rn(a) == rm(a))
    notv = (b & U(0xBFFFFC00)) == U(0x2E205800)
    m = ((cmeq0 | cmtst_self) & notv & (rn(b) == rd(a))
         & (fld(a, 30, 1) == fld(b, 30, 1)))
    return m, m & (rd(b) == rd(a))


@shape("and_and_orr")
def s_and_and_orr(w):
    a, b, c = w[:-2], w[1:-1], w[2:]
    orr = (c & U(0x7FE0FC00)) == U(0x2A000000)                   # orr Rd, Rn, Rm (LSL #0)
    ands = (is_logimm(a, 0) & is_logimm(b, 0) & (rn(a) == rn(b))
            & (sf(a) == sf(b)) & (sf(c) == sf(a)))
    m = ands & orr & (((rn(c) == rd(a)) & (rm(c) == rd(b)))
                      | ((rn(c) == rd(b)) & (rm(c) == rd(a))))
    m &= (rd(a) != rd(b)) & (rd(a) != rn(a))
    enc = np.zeros(len(a), dtype=bool)
    for i in np.flatnonzero(m):
        va, width = logimm_value(a[i])
        vb, _ = logimm_value(b[i])
        enc[i] = va is not None and vb is not None and encodable(va | vb, width)
    return m, enc


@shape("smull_ovf")
def s_smull_ovf(w):
    a, b = w[:-1], w[1:]
    hi = (((a & U(0xFFFFFC00)) == U(0xD360FC00))                 # lsr x, x, #32
          | ((a & U(0xFFFFFC00)) == U(0x9360FC00)))              # asr x, x, #32
    cmp = (b & U(0xFFE0FC1F)) == U(0x6B807C1F)                   # cmp wa, wb, asr #31
    m = hi & cmp & (rn(b) == rd(a)) & (rm(b) == rn(a))
    return m, m


@shape("cmp_sxtw_ref")
def s_cmp_sxtw(w):
    m = ((w & U(0xFFE0FC1F)) == U(0xEB20C01F)) & (rm(w) == rn(w))
    return m, m


@shape("stp_xzr_run")
def s_stp_xzr_run(w):
    z = (w & U(0xFFC07C1F)) == U(0xA9007C1F)                     # stp xzr, xzr, [Xn, #o]
    off = fld(w, 15, 7).astype(np.int32)
    off = np.where(off >= 64, off - 128, off)
    pair = (z[:-1] & z[1:] & (rn(w[:-1]) == rn(w[1:]))
            & (np.abs(off[1:] - off[:-1]) == 2))
    m = np.zeros(len(w) - 1, dtype=bool)
    s = np.zeros(len(w) - 1, dtype=bool)
    i, n = 0, len(pair)
    while i < n:
        if not pair[i]:
            i += 1
            continue
        j = i
        while j < n and pair[j]:
            j += 1
        m[i] = True
        s[i] = j - i + 1 >= 4
        i = j
    return m, s


@shape("csel_zr_zr")
def s_csel_zr_zr(w):
    m = ((w & U(0x7FFF0FE0)) == U(0x1A9F03E0)) & (rd(w) != U(31))  # csel Rd, zr, zr, cond
    return m, m


@shape("neg_zero_test")
def s_neg_zero_test(w):
    a, b = w[:-1], w[1:]
    neg = (a & U(0x7FE0FFE0)) == U(0x4B0003E0)                   # neg Rd, Rm (LSL #0)
    cb = (((b & U(0x7E000000)) == U(0x34000000)) & (rd(b) == rd(a))
          & (sf(a) == sf(b)))
    cmp0 = (((b & U(0x7FFFFC1F)) == U(0x7100001F)) & (rn(b) == rd(a))
            & (sf(a) == sf(b)))
    m = neg & (cb | cmp0) & (rd(a) != U(31))
    return m, m & cb


# --- CCMP chains ---

def _cond_holds(cond, n, z, c, v):
    r = [z, c, n, v, c and not z, n == v, (n == v) and not z, True][cond >> 1]
    return (not r) if (cond & 1) and cond != 15 else r


def _compare(x, k, width, is_cmn):
    """NZCV of CMP (or CMN) X, #K at WIDTH."""
    mask = (1 << width) - 1
    x &= mask
    k &= mask
    top = width - 1
    if is_cmn:
        full = x + k
        res, carry = full & mask, full > mask
        v = (x >> top) == (k >> top) and (res >> top) != (x >> top)
    else:
        res, carry = (x - k) & mask, x >= k
        v = (x >> top) != (k >> top) and (res >> top) != (x >> top)
    return bool(res >> top), res == 0, carry, v


def _chain_flags(links, x, width):
    k0, cmn0 = links[0]
    f = _compare(x, k0, width, cmn0)
    for k, cmn, nzcv, cond in links[1:]:
        if _cond_holds(cond, *f):
            f = _compare(x, k, width, cmn)
        else:
            f = (bool(nzcv & 8), bool(nzcv & 4), bool(nzcv & 2), bool(nzcv & 1))
    return f


def _reader_cond(x):
    x = int(x)
    if (x & 0xFF000010) == 0x54000000:                           # b.cond
        return x & 15
    if (x & 0x1FE00800) == 0x1A800000:                           # csel/csinc/csinv/csneg
        return (x >> 12) & 15
    return None


def _writes_flags(x):
    x = int(x)
    if (x & 0x1F000000) in (0x11000000, 0x0B000000) and (x >> 29) & 1:
        return True                                              # adds/subs
    if (x & 0x1F800000) == 0x12000000 and ((x >> 29) & 3) == 3:
        return True                                              # ands (immediate)
    if (x & 0x1F000000) == 0x0A000000 and ((x >> 29) & 3) == 3:
        return True                                              # ands/bics (register)
    return (x & 0x1FE00000) == 0x1A400000                        # ccmp/ccmn


def _single_compare_equivalent(links, cond, width):
    """Does some single CMP/CMN Rn, #k (k <= 4095) under some condition
    decide what the chain decides under COND? Exact: the sample holds
    every interval boundary any of the compares involved can have (k,
    k+1, the signed wrap and k + 2^(width-1)), so both predicates are
    constant between consecutive samples."""
    mask = (1 << width) - 1
    half = 1 << (width - 1)
    consts = {((-k) & mask) if cmn else k for k, cmn, *_ in links}
    cands = {(k + d) & mask for k in consts for d in range(-2, 3)}
    pts = {0, 1, 2, mask, half - 1, half, half + 1}
    for k in consts | cands:
        for d in (-1, 0, 1):
            pts.add((k + d) & mask)
            pts.add((k + half + d) & mask)
    pts = sorted(pts)
    want = [_cond_holds(cond, *_chain_flags(links, x, width)) for x in pts]
    for k in cands:
        for is_cmn, kk in ((False, k), (True, (-k) & mask)):
            if kk > 4095:
                continue
            flags = [_compare(x, kk, width, is_cmn) for x in pts]
            for c in range(14):
                if all(_cond_holds(c, *f) == t for f, t in zip(flags, want)):
                    return True
    return False


@shape("ccmp_chain")
def s_ccmp_chain(w):
    cmpimm = (((w & U(0x3F80001F)) == U(0x3100001F))              # cmp/cmn Rn, #imm12
              & (fld(w, 22, 1) == U(0)))
    ccmpimm = (w & U(0x3FE00C10)) == U(0x3A400800)               # ccmp/ccmn Rn, #imm5
    start = (cmpimm[:-1] & ccmpimm[1:] & (rn(w[:-1]) == rn(w[1:]))
             & (sf(w[:-1]) == sf(w[1:])))
    m = np.zeros(len(w) - 1, dtype=bool)
    s = np.zeros(len(w) - 1, dtype=bool)
    for i in np.flatnonzero(start):
        x0 = int(w[i])
        width = 64 if x0 >> 31 else 32
        reg = (x0 >> 5) & 31
        links = [((x0 >> 10) & 0xFFF, ((x0 >> 30) & 1) == 0)]
        j = i + 1
        while (j < len(w) and ccmpimm[j] and int(rn(w[j])) == reg
               and (int(w[j]) >> 31) == (x0 >> 31)):
            y = int(w[j])
            links.append(((y >> 16) & 31, ((y >> 30) & 1) == 0, y & 15, (y >> 12) & 15))
            j += 1
        cond = None
        for t in range(j, min(j + 4, len(w))):
            cond = _reader_cond(w[t])
            if cond is not None or _writes_flags(w[t]):
                break
        if cond is None:
            continue
        m[i] = True
        s[i] = _single_compare_equivalent(links, cond, width)
    return m, s


# --- Extension or mask narrowed by a later mask ---
#
# The reference model for check_mask_chain_fold. A producer P writes
# Rt from Rs and an adjacent consumer C reads Rt; each is an AND-type
# op (AND #imm, UXTB/UXTH/UBFX #0, MOV Wd, Wm -- a mask) or a
# SXT-type one (SXTB/SXTH/SXTW/SBFX #0 -- a sign extension of a low
# field). C may also be ANDS/TST #imm, whose flags follow from the same
# value at the same width. The pair is one instruction when:
#   narrow   C reads only bits P passes through unchanged: C, reading Rs
#   merge    two masks: and Rd, Rs, #(a & b), when that encodes
#   zero     two masks whose intersection is empty: mov Rd, #0
#   resext   SXT then a wider SXT: P's extension at C's width
#   retarget C adds nothing to P's value: P, writing Rd
# Excluded: C in place (Rd == Rt) and a no-op given P -- the
# redundant-extension checks' shape (delete C) -- and an in-place SXT
# made dead by an in-place zero-extension, check_redundant_sext's
# second arm.

def mask_role(x):
    """(kind, k, width, rd, rn, spelling): kind 'and' with its mask or
    'sext' with its field width; None when X is neither."""
    width = 64 if x >> 31 else 32
    d, n = x & 31, (x >> 5) & 31
    if (x & 0xFFE0FFE0) == 0x2A0003E0:                           # mov Wd, Wm
        return ("and", 0xFFFFFFFF, 32, d, (x >> 16) & 31, "mov")
    if ((x >> 23) & 0x3F) == 0b100100 and ((x >> 29) & 3) in (0, 3):
        if not (x >> 31) and (x >> 22) & 1:
            return None
        v, _ = logimm_value(x)
        spell = "ands" if ((x >> 29) & 3) == 3 else "and"
        return None if v is None else ("and", v, width, d, n, spell)
    if (((x >> 23) & 0x3F) == 0b100110 and ((x >> 16) & 63) == 0
            and ((x >> 22) & 1) == (x >> 31)):
        s = (x >> 10) & 63
        if not (x >> 31) and s >= 32:
            return None
        field = s + 1
        if field >= width:
            return None
        opc = (x >> 29) & 3
        if opc == 2:
            return ("and", (1 << field) - 1, width, d, n, "ubfm")
        if opc == 0:
            return ("sext", field, width, d, n, "sbfm")
    return None


def _apply(r, x):
    kind, k, width = r[0], r[1], r[2]
    if kind == "and":
        return x & k
    low = x & ((1 << k) - 1)
    if low >> (k - 1):
        low |= ((1 << width) - 1) & ~((1 << k) - 1)
    return low


def classify_mask_chain(x, y):
    p, c = mask_role(x), mask_role(y)
    if p is None or c is None or p[5] in ("ands",) or c[5] == "mov":
        return None
    if p[3] == 31 or p[4] == 31 or c[4] != p[3]:
        return None
    flags = c[5] == "ands"
    if c[3] == 31 and not flags:
        return None                                              # AND to SP
    cw, pw = c[2], p[2]
    cmask = (1 << cw) - 1
    in_place = c[3] == p[3]
    if p[0] == "and" and c[0] == "and":
        noop = (p[1] & ~c[1]) == 0
    elif p[0] == "sext" and c[0] == "sext":
        noop = c[1] >= p[1] and cw == pw
    elif p[0] == "and":
        noop = p[1] < (1 << (c[1] - 1))
    else:
        noop = (((1 << pw) - 1) & ~c[1]) == 0
    if noop and in_place:
        return None
    reads = (c[1] if c[0] == "and" else (1 << c[1]) - 1) & cmask
    passes = p[1] if p[0] == "and" else (1 << p[1]) - 1
    if (reads & passes) == reads and not noop:
        if (p[0] == "sext" and p[4] == p[3] and in_place and c[0] == "and"
                and c[5] in ("ubfm", "and") and (c[1] & (c[1] + 1)) == 0
                and c[1].bit_length() <= p[1]):
            return None                                          # dead SXT
        return "narrow"
    if p[0] == "and" and (c[0] == "and" or noop):
        cm = c[1] if c[0] == "and" else (1 << c[1]) - 1
        m = p[1] & cm & cmask
        if m == 0:
            return None if flags else "zero"
        if encodable(m, cw):
            return "merge"
        if not flags and cw == 64 and m < (1 << 32) and encodable(m, 32):
            return "merge"
        return None
    if flags:
        return None
    if p[0] == "sext" and c[0] == "sext" and p[1] <= c[1] <= pw:
        return "resext"
    if p[0] == "sext" and c[0] == "and" and noop:
        return "retarget"
    return None


def mask_chain_value(x, y, v):
    """What the one-instruction rewrite of (x, y) computes from Rs = v."""
    p, c = mask_role(x), mask_role(y)
    cat = classify_mask_chain(x, y)
    cw = c[2]
    if cat == "narrow":
        return _apply(c, v)
    if cat == "zero":
        return 0
    if cat == "merge":
        cm = c[1] if c[0] == "and" else (1 << c[1]) - 1
        return v & p[1] & cm & ((1 << cw) - 1)
    if cat == "resext":
        return _apply(("sext", p[1], cw), v)
    return _apply(p, v)                                          # retarget


@shape("mask_chain")
def s_mask_chain(w):
    a, b = w[:-1], w[1:]
    prod = (is_logimm(a, 0) | ((is_bfm(a, 2) | is_bfm(a, 0)) & (immr(a) == U(0)))
            | ((a & U(0xFFE0FFE0)) == U(0x2A0003E0)))
    cons = (is_logimm(b, 0) | is_logimm(b, 3)
            | ((is_bfm(b, 2) | is_bfm(b, 0)) & (immr(b) == U(0))))
    cand = prod & cons & (rn(b) == rd(a))
    m = np.zeros(len(a), dtype=bool)
    s = np.zeros(len(a), dtype=bool)
    for i in np.flatnonzero(cand):
        if classify_mask_chain(int(a[i]), int(b[i])) is not None:
            m[i] = True
            s[i] = (int(a[i]) & 31) == (int(b[i]) & 31)
    return m, s


# === Reporting ===

def _llvm_mc():
    return os.environ.get("LLVM_MC") or shutil.which("llvm-mc")


def disasm(words):
    mc = _llvm_mc()
    if mc is None:
        return [f"{x:08x}" for x in words]
    src = " ".join(f"0x{x & 0xff:02x} 0x{(x >> 8) & 0xff:02x} "
                   f"0x{(x >> 16) & 0xff:02x} 0x{x >> 24:02x}" for x in words)
    out = subprocess.run([mc, "--disassemble", "-triple=aarch64",
                          "-mattr=+v8.9a,+sve2,+sme,+cssc"],
                         input=src, capture_output=True, text=True).stdout
    return [" ".join(l.split("//")[0].split()) for l in out.splitlines()
            if l.strip() and not l.strip().startswith(".")]


def report(paths):
    rows = {name: [] for name in SHAPES}
    heads = []
    for path in paths:
        w, _ = load(path)
        heads.append((os.path.basename(path)[:14], len(w)))
        for name, fn in SHAPES.items():
            m, s = fn(w)
            rows[name].append((int(m.sum()), int(s.sum())))
    width = max(len(n) for n in SHAPES) + 2
    print(f"{'ALL / STRICT':{width}s}" + "".join(f"{h:>18s}" for h, _ in heads))
    print(f"{'instructions':{width}s}" + "".join(f"{n:>18,}" for _, n in heads))
    for name, cells in rows.items():
        print(f"{name:{width}s}" + "".join(f"{f'{a:,} / {s:,}':>18s}" for a, s in cells))


def examples(path, name, limit):
    if name not in SHAPES:
        sys.exit(f"-e: unknown shape {name!r}; known: {', '.join(SHAPES)}")
    w, adrs = load(path)
    m, s = SHAPES[name](w)
    print(f"{name}: {int(m.sum()):,} / {int(s.sum()):,} in {os.path.basename(path)}")
    for i in np.flatnonzero(m)[:limit]:
        ctx = [int(x) for x in w[max(i - 1, 0): i + 4]]
        mark = "*" if s[i] else " "
        print(f"  {mark} {int(adrs[i]):#x}: " + " | ".join(disasm(ctx)))


# === Self-test ===

POSITIVE, NEGATIVE = 0, 1

SELF = {
    "asr_and": (
        ["asr w8, w9, #6\nand w8, w8, #0x3f",
         "asr x8, x9, #40\nand x8, x8, #0xffffff",
         "asr w8, w9, #6\nand w10, w8, #0x3f",
         "asr w8, w9, #16\nand w8, w8, #0xffff"],
        ["lsr w8, w9, #6\nand w8, w8, #0x3f",
         "asr w8, w9, #6\nand w8, w8, #0x3f0",
         "asr w8, w9, #20\nand w8, w8, #0x3fff",
         "asr w8, w9, #6\nand x8, x8, #0x3f",
         "asr w8, w9, #6\nand w8, w10, #0x3f"]),
    "lsr_and_ref": (
        ["lsr w8, w9, #6\nand w8, w8, #0x3f", "lsr x8, x9, #6\nand x10, x8, #0xff"],
        ["asr w8, w9, #6\nand w8, w8, #0x3f", "lsr w8, w9, #6\nand w8, w8, #0x3f0"]),
    "cmp_zext_hi": (
        ["mov x4, #0xffffffff\ncmp x3, x4",
         "mov w4, #-1\ncmp x3, x4",
         "mov w4, #0xfffff001\ncmp x3, x4",
         "mov x4, #0xfffffffe\ncmp x3, x4"],
        ["mov x4, #0xffffffff\ncmp w3, w4",
         "mov x4, #0xfffff000\ncmp x3, x4",
         "mov x4, #-1\ncmp x3, x4",
         "mov x4, #0xffffffff\ncmp x4, x3",
         "mov x4, #0x100000000\ncmp x3, x4"]),
    "cmeq0_not": (
        ["cmeq v16.16b, v16.16b, #0\nmvn v16.16b, v16.16b",
         "cmeq v1.4s, v2.4s, #0\nnot v3.16b, v1.16b",
         "cmeq v1.2d, v2.2d, #0\nnot v1.16b, v1.16b",
         "cmeq v1.8b, v2.8b, #0\nnot v1.8b, v1.8b",
         "cmtst v1.8h, v2.8h, v2.8h\nnot v1.16b, v1.16b"],
        ["cmeq v1.4s, v2.4s, v3.4s\nnot v1.16b, v1.16b",
         "cmeq v1.4s, v2.4s, #0\nnot v1.16b, v4.16b",
         "cmge v1.4s, v2.4s, #0\nnot v1.16b, v1.16b",
         "cmeq v1.8b, v2.8b, #0\nnot v1.16b, v1.16b",
         "cmtst v1.8h, v2.8h, v3.8h\nnot v1.16b, v1.16b"]),
    "and_and_orr": (
        ["and w1, w0, #4\nand w0, w0, #8\norr w0, w1, w0",
         "and x1, x0, #0xf0\nand x2, x0, #0xf00\norr x3, x2, x1"],
        ["and w1, w0, #4\nand w0, w2, #8\norr w0, w1, w0",
         "and w1, w0, #4\nand w0, w0, #8\neor w0, w1, w0",
         "and w1, w0, #4\nand w2, w0, #8\norr w0, w1, w0, lsl #1",
         "and w1, w0, #0xf\nand w2, w0, #0xf00\norr w3, w1, w2"]),
    "smull_ovf": (
        ["lsr x2, x0, #32\ncmp w2, w0, asr #31",
         "asr x2, x0, #32\ncmp w2, w0, asr #31"],
        ["lsr x2, x0, #32\ncmp w2, w0, lsr #31",
         "lsr x2, x0, #31\ncmp w2, w0, asr #31",
         "lsr x2, x0, #32\ncmp w2, w1, asr #31",
         "lsr x2, x0, #32\ncmp w3, w0, asr #31"]),
    "cmp_sxtw_ref": (["cmp x0, w0, sxtw"], ["cmp x0, w1, sxtw", "cmp x0, w0, uxtw"]),
    "stp_xzr_run": (
        ["stp xzr, xzr, [x0]\nstp xzr, xzr, [x0, #16]",
         "stp xzr, xzr, [sp, #-32]\nstp xzr, xzr, [sp, #-16]"],
        ["stp xzr, xzr, [x0]\nstp xzr, xzr, [x1, #16]",
         "stp xzr, xzr, [x0]\nstp xzr, xzr, [x0, #32]",
         "stp xzr, x1, [x0]\nstp xzr, xzr, [x0, #16]"]),
    "csel_zr_zr": (["csel w0, wzr, wzr, eq", "csel x3, xzr, xzr, lt"],
                   ["csel w0, w1, wzr, eq", "csel w0, wzr, w1, eq", "csinc w0, wzr, wzr, eq",
                    "csinv x0, xzr, xzr, ne", "csel wzr, wzr, wzr, eq"]),
    "neg_zero_test": (
        ["neg w1, w0\ncbz w1, .", "neg x1, x0\ncbnz x1, .", "neg w1, w0\ncmp w1, #0"],
        ["neg w1, w0\ncbz w2, .", "neg w1, w0\ncmp w1, #1",
         "neg w1, w0, lsl #2\ncbz w1, .", "neg w1, w0\ncbz x1, ."]),
    "ccmp_chain": (
        ["cmp w0, #1\nccmp w0, #2, #6, gt\nccmp w0, #3, #6, gt\nccmp w0, #4, #6, gt\ncsel w0, w1, w2, le",
         "cmp w0, #0\nccmp w0, #1, #4, ne\nccmp w0, #2, #4, ne\ncset w0, eq",
         "cmp w8, #254\nccmp w8, #21, #0, ne\nb.eq .",
         "cmn x8, #2\nccmn x8, #1, #4, ne\nb.ne .",
         "cmp x0, #10\nccmp x0, #20, #0, hi\nb.hi ."],
        ["cmp w0, #1\nccmp w0, #5, #4, ne\ncset w0, eq",
         "cmp w0, #1\nccmp w1, #2, #6, gt\ncsel w0, w1, w2, le",
         "cmp w0, #0\nccmp w0, #2, #4, ne\ncset w0, eq",
         "cmp w8, #254\nccmp w8, #21, #4, ne\nb.eq ."]),
    "mask_chain": (
        ["and w8, w8, #0xff\nand w8, w8, #0x3f",
         "and w8, w9, #0xffff\nand w8, w8, #0x1ff",
         "mov w0, w2\nand x19, x0, #0x7fffffff",
         "sxtw x0, w1\nsxtb w0, w0",
         "uxth w8, w9\nsxtb w8, w8",
         "and w8, w9, #0xff00ff\nand w10, w8, #0xff",
         "and w8, w9, #0xf0f0f0f0\nand w8, w8, #0xff00ff00",
         "sxth w8, w9\nand w8, w8, #0xff",
         "and x8, x9, #0xffffffff\nsxtw x8, w8",
         "and w8, w9, #0xf0\nand w8, w8, #0xf",
         "and w8, w9, #0xff\nands w8, w8, #0xf",
         "and w8, w9, #0xffff\ntst w8, #0x1ff"],
        ["and w8, w8, #0xff\nand w8, w8, #0xff",
         "and w8, w9, #0xf0\ntst w8, #0xf",
         "ands w8, w9, #0xff\nand w10, w8, #0xf",
         "and w8, w9, #0xff\nand w8, w8, #0xffff",
         "sxtb w8, w9\nsxth w8, w8",
         "sxtb w8, w9\nand w8, w8, #0xffff",
         "and w8, w9, #0xff\nand w8, w10, #0xf",
         "mov w0, w2\nmov w0, w0",
         "lsr w8, w9, #4\nand w8, w8, #0xf",
         "and w8, w9, #0xf0f0f0f0\nand w8, w8, #0xffffff00"]),
}

# Shapes whose positives must land in STRICT, not just ALL.
STRICT_SELF = {"ccmp_chain", "and_and_orr"}

CLASSIFY = {
    "and w8, w8, #0xff\nand w8, w8, #0x3f": "narrow",
    "sxtw x0, w1\nsxtb w0, w0": "narrow",
    "mov w0, w2\nand x19, x0, #0x7fffffff": "narrow",
    "and w8, w9, #0xffff\ntst w8, #0x1ff": "narrow",
    "and w8, w9, #0xf0f0f0f0\nand w8, w8, #0xff00ff00": "merge",
    "and w8, w8, #0x1\nand w0, w8, #0x1": "merge",
    "and x8, x21, #0xffffffff\nand x8, x8, #0xfffffffffffffffd": "merge",
    "and w8, w9, #0xf0\nand w8, w8, #0xf": "zero",
    "sxtb w9, w9\nsxtw x8, w9": "resext",
    "sxtb w8, w9\nand x10, x8, #0xffffffff": "retarget",
    "and w8, w8, #0xff\nand w8, w8, #0xff": None,
    "sxth w8, w8\nand w8, w8, #0xff": None,
    "and w8, w9, #0xf0\ntst w8, #0xf": None,
    "and x8, x21, #0xffffffff\nands x8, x8, #0xfffffffffffffffd": None,
}


def _semantic_sample():
    """Every classified pair among a spread of encodings computes, as a
    one-instruction rewrite, what the two-instruction chain computes."""
    import random
    rng = random.Random(1)
    ops = []
    for sfv in (0, 1):
        for sv in range(0, 64 if sfv else 32):
            for opc in (0, 2):
                ops.append((sfv << 31) | (opc << 29) | (0b100110 << 23)
                           | (sfv << 22) | (sv << 10) | (9 << 5) | 8)
        for nv in ((0, 1) if sfv else (0,)):
            for rv in range(0, 64 if nv else 32, 5):
                for sv in range(0, 64, 5):
                    for opc in (0, 3):
                        ops.append((sfv << 31) | (opc << 29) | (0b100100 << 23) | (nv << 22)
                                   | (rv << 16) | (sv << 10) | (9 << 5) | 8)
    ops.append(0x2A0903E8)                                       # mov w8, w9
    ops = [o for o in ops if mask_role(o)]
    vals = [rng.getrandbits(64) for _ in range(24)] + [0, (1 << 64) - 1, 1 << 63,
                                                       1 << 31, 0xFFFFFFFF, 0x80, 0x8000]
    checked = bad = 0
    for x in ops:
        for y0 in ops:
            for dst in (8, 10, 31):
                y = (y0 & ~0x3FF) | (8 << 5) | dst
                if classify_mask_chain(x, y) is None:
                    continue
                checked += 1
                for v in vals:
                    want = _apply(mask_role(y), _apply(mask_role(x), v))
                    if mask_chain_value(x, y, v) != want:
                        bad += 1
                        break
    return checked, bad


def _assemble(src):
    lines = ["    .text", "    .arch armv8.5-a"] + ["    " + l for l in src.split("\n")]
    with tempfile.TemporaryDirectory() as td:
        asm, obj = os.path.join(td, "s.s"), os.path.join(td, "s.o")
        with open(asm, "w") as f:
            f.write("\n".join(lines) + "\n")
        cc = subprocess.run(["clang", "-arch", "arm64", "-c", "-o", obj, asm],
                            capture_output=True, text=True)
        if cc.returncode:
            sys.exit(f"selftest: clang rejected {src!r}:\n{cc.stderr}")
        w, _ = load(obj)
    return w


def selftest():
    failures = 0
    for name, (pos, neg) in SELF.items():
        fn = SHAPES[name]
        pick = 1 if name in STRICT_SELF else 0
        for kind, refs in ((POSITIVE, pos), (NEGATIVE, neg)):
            for src in refs:
                hit = fn(_assemble(src))[pick].any()
                if hit != (kind == POSITIVE):
                    what = "misses" if kind == POSITIVE else "wrongly matches"
                    print(f"  FAIL {name} {what} {src!r}")
                    failures += 1
        print(f"  ok   {name:14s} {len(pos)} positive, {len(neg)} near-miss references")
    for src, want in CLASSIFY.items():
        w = _assemble(src)
        got = classify_mask_chain(int(w[0]), int(w[1]))
        if got != want:
            print(f"  FAIL mask_chain classifies {src!r} as {got}, want {want}")
            failures += 1
    checked, bad = _semantic_sample()
    print(f"  {'ok  ' if bad == 0 else 'FAIL'} mask_chain     {checked:,} classified pairs "
          f"agree with the two-instruction chain" + (f" ({bad} do not)" if bad else ""))
    failures += bad
    print("selftest:", "OK" if failures == 0 else f"{failures} failures")
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("-e", metavar="SHAPE", help="print example sites of SHAPE")
    ap.add_argument("-n", type=int, default=10, help="examples to print (default 10)")
    ap.add_argument("binaries", nargs="*")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.binaries:
        ap.error("no binaries given")
    if args.e:
        for path in args.binaries:
            examples(path, args.e, args.n)
        return 0
    report(args.binaries)
    return 0


if __name__ == "__main__":
    sys.exit(main())
