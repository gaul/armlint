/*
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "armlint.h"

#define MOV_CHAIN_MAX 4

typedef struct {
    uint16_t imm16;
    uint8_t  shift_div_16;     // 0..3 (shift = 0/16/32/48)
    uint8_t  opc;              // 0=MOVN, 2=MOVZ, 3=MOVK
} mov_entry;

struct armlint_state {
    // MOV chain (MOVZ/MOVN followed by zero or more MOVKs).
    bool mov_active;
    bool mov_is_64bit;
    unsigned mov_rd;
    uint64_t mov_value;
    size_t mov_start_offset;
    unsigned mov_insn_count;
    mov_entry mov_entries[MOV_CHAIN_MAX];

    // LSL pending a shifted-register consumer.
    bool lsl_active;
    bool lsl_is_64bit;
    unsigned lsl_rd;
    unsigned lsl_rn;
    unsigned lsl_shift;
    size_t lsl_offset;

    // CMP Rn, #0 pending a B.EQ/B.NE consumer.
    bool cmp_active;
    bool cmp_is_64bit;
    unsigned cmp_rn;
    size_t cmp_offset;

    // TST Rn, #(1<<k) pending a B.EQ/B.NE consumer.
    bool tst_active;
    bool tst_is_64bit;
    unsigned tst_rn;
    unsigned tst_bit;       // bit position 0..63
    size_t tst_offset;

    // W-form ALU/move/bitfield result pending a redundant zero-extension
    // consumer (UXTW Xd,Wd or AND Xd,Xd,#0xffffffff with same Rd).
    bool wzx_active;
    unsigned wzx_rd;
    size_t wzx_offset;
    char wzx_producer_disasm[ARMLINT_FINDING_LINE_LEN];

    // Deferred CMP/TST + B.EQ/NE finding awaiting forward NZCV-liveness
    // verification. Only one of CMP or TST can be pending at a time
    // (a CMP would overwrite or be overwritten by a TST), so the
    // storage is shared.
    bool pending_active;
    unsigned pending_window;
    armlint_finding pending_finding;
};

#define LIVENESS_WINDOW 16

armlint_state *armlint_state_create(void)
{
    armlint_state *s = calloc(1, sizeof(*s));
    return s;
}

void armlint_state_destroy(armlint_state *state)
{
    free(state);
}

void armlint_state_reset(armlint_state *state)
{
    memset(state, 0, sizeof(*state));
}

static uint64_t width_mask(unsigned reg_width)
{
    return reg_width == 64 ? ~(uint64_t)0 : ((uint64_t)1 << reg_width) - 1;
}

bool is_bitmask_immediate(uint64_t imm, unsigned reg_width)
{
    if (reg_width != 32 && reg_width != 64) {
        return false;
    }

    uint64_t mask_w = width_mask(reg_width);
    imm &= mask_w;
    if (imm == 0 || imm == mask_w) {
        return false;
    }

    // Smallest esize for which imm replicates determines encodability:
    // at any larger esize the chunk has at least as many cyclic 1-runs,
    // so if the smallest replicating size is not a rotated single run,
    // no other size can rescue it.
    for (unsigned esize = 2; esize <= reg_width; esize *= 2) {
        uint64_t mask_e = esize == 64 ? ~(uint64_t)0 : ((uint64_t)1 << esize) - 1;
        uint64_t chunk = imm & mask_e;

        bool replicates = true;
        for (unsigned pos = esize; pos < reg_width; pos += esize) {
            if (((imm >> pos) & mask_e) != chunk) {
                replicates = false;
                break;
            }
        }
        if (!replicates) {
            continue;
        }

        for (unsigned r = 0; r < esize; r++) {
            uint64_t rot;
            if (r == 0) {
                rot = chunk;
            } else {
                rot = ((chunk >> r) | (chunk << (esize - r))) & mask_e;
            }
            // rot is (2^n - 1) for some 1 <= n <= esize-1 iff
            // rot != 0 and (rot & (rot + 1)) == 0. n != 0 because
            // chunk != 0 at the smallest replicating esize; n != esize
            // because chunk != mask_e.
            if (rot != 0 && (rot & (rot + 1)) == 0) {
                return true;
            }
        }
        return false;
    }
    return false;
}

static void clear_finding_strings(armlint_finding *out)
{
    out->detail[0] = '\0';
    for (unsigned i = 0; i < ARMLINT_FINDING_LINES; i++) {
        out->lines[i][0] = '\0';
    }
}

static bool mov_close(armlint_state *state, armlint_finding *out)
{
    if (!state->mov_active) {
        return false;
    }

    bool produced = false;
    if (state->mov_insn_count >= 2) {
        unsigned reg_width = state->mov_is_64bit ? 64 : 32;
        if (is_bitmask_immediate(state->mov_value, reg_width)) {
            char w_or_x = state->mov_is_64bit ? 'x' : 'w';

            out->name = "suboptimal MOVZ/MOVK sequence";
            out->start_offset = state->mov_start_offset;
            out->insn_count = state->mov_insn_count;
            clear_finding_strings(out);

            snprintf(out->detail, sizeof(out->detail),
                "%c%u = 0x%" PRIx64,
                w_or_x, state->mov_rd, state->mov_value);

            unsigned n = state->mov_insn_count;
            if (n > ARMLINT_FINDING_LINES) {
                n = ARMLINT_FINDING_LINES;
            }
            for (unsigned i = 0; i < n; i++) {
                const mov_entry *e = &state->mov_entries[i];
                const char *mnem = e->opc == 2 ? "movz"
                               : (e->opc == 0 ? "movn" : "movk");
                unsigned shift = (unsigned)e->shift_div_16 * 16;
                if (shift == 0) {
                    snprintf(out->lines[i], sizeof(out->lines[i]),
                        "%s %c%u, #0x%x",
                        mnem, w_or_x, state->mov_rd, e->imm16);
                } else {
                    snprintf(out->lines[i], sizeof(out->lines[i]),
                        "%s %c%u, #0x%x, lsl #%u",
                        mnem, w_or_x, state->mov_rd, e->imm16, shift);
                }
            }
            produced = true;
        }
    }

    state->mov_active = false;
    return produced;
}

bool armlint_flush(armlint_state *state, armlint_finding *out)
{
    // The LSL, CMP, and TST checks never produce a finding from flush
    // alone -- an isolated LSL, CMP, or TST is not actionable -- but
    // their state must be cleared so a new region starts fresh. Any
    // pending CMP+B.EQ/NE or TST+B.EQ/NE finding is discarded too:
    // without seeing a safe stopper before end-of-region, we cannot
    // prove the fold is sound.
    state->lsl_active = false;
    state->cmp_active = false;
    state->tst_active = false;
    state->wzx_active = false;
    state->pending_active = false;
    return mov_close(state, out);
}

static void mov_record_entry(armlint_state *state, unsigned opc,
                             unsigned imm16, unsigned hw)
{
    if (state->mov_insn_count == 0
            || state->mov_insn_count > MOV_CHAIN_MAX) {
        return;
    }
    unsigned slot = state->mov_insn_count - 1;
    if (slot >= MOV_CHAIN_MAX) {
        return;
    }
    state->mov_entries[slot].opc = (uint8_t)opc;
    state->mov_entries[slot].imm16 = (uint16_t)imm16;
    state->mov_entries[slot].shift_div_16 = (uint8_t)hw;
}

// Decode the move-wide-immediate fields directly from the 4-byte
// little-endian encoding. Going through the raw bits avoids ambiguity
// from Capstone's alias selection (MOVZ/MOVN/ORR-bitmask-imm all share
// the MOV mnemonic).
bool check_movz_movk_bitmask(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        return mov_close(state, out);
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    bool is_move_wide = (op & 0x1f800000u) == 0x12800000u;
    if (!is_move_wide) {
        return mov_close(state, out);
    }

    unsigned opc = (op >> 29) & 0x3u;
    unsigned sf = (op >> 31) & 0x1u;
    unsigned hw = (op >> 21) & 0x3u;
    unsigned imm16 = (op >> 5) & 0xffffu;
    unsigned rd = op & 0x1fu;

    // opc=01 is unallocated in this encoding class; rd=31 is XZR (not
    // SP for these aliases) and discards the constant. Treat both as
    // sequence-breakers.
    if (opc == 1 || rd == 31) {
        return mov_close(state, out);
    }

    unsigned reg_width = sf ? 64 : 32;
    unsigned shift = hw * 16;
    uint64_t mask_w = width_mask(reg_width);

    if (opc == 3) {
        // MOVK extends an active sequence only if rd and width match.
        if (state->mov_active && state->mov_rd == rd
                && state->mov_is_64bit == (reg_width == 64)) {
            uint64_t clear = ~((uint64_t)0xffffu << shift);
            state->mov_value = (state->mov_value & clear)
                | ((uint64_t)imm16 << shift);
            state->mov_value &= mask_w;
            state->mov_insn_count++;
            mov_record_entry(state, opc, imm16, hw);
            return false;
        }
        return mov_close(state, out);
    }

    // opc == 0 (MOVN) or opc == 2 (MOVZ): start a new sequence,
    // closing any previous one first.
    bool produced = mov_close(state, out);

    state->mov_active = true;
    state->mov_rd = rd;
    state->mov_is_64bit = (reg_width == 64);
    state->mov_start_offset = offset;
    state->mov_insn_count = 1;
    if (opc == 2) {
        state->mov_value = ((uint64_t)imm16 << shift) & mask_w;
    } else {
        state->mov_value = (~((uint64_t)imm16 << shift)) & mask_w;
    }
    mov_record_entry(state, opc, imm16, hw);

    return produced;
}

// Detect LSL (immediate) as the canonical UBFM alias:
//   sf | 10 | 100110 | N | immr(6) | imms(6) | Rn(5) | Rd(5)
// with N == sf, imms != datasize-1, and immr == imms+1 (mod datasize).
// shift = (datasize - 1) - imms.
static bool decode_lsl_imm(uint32_t op,
                           unsigned *out_sf, unsigned *out_rd,
                           unsigned *out_rn, unsigned *out_shift)
{
    if ((op & 0x7f800000u) != 0x53000000u) {
        return false;
    }
    unsigned sf = (op >> 31) & 0x1u;
    unsigned N = (op >> 22) & 0x1u;
    if (N != sf) {
        return false;
    }
    unsigned immr = (op >> 16) & 0x3fu;
    unsigned imms = (op >> 10) & 0x3fu;
    unsigned datasize = sf ? 64 : 32;
    unsigned imms_max = datasize - 1;

    // For sf=0 the high bits of immr/imms must be zero. The encoding
    // would otherwise be UNALLOCATED.
    if (!sf && (imms >= 32 || immr >= 32)) {
        return false;
    }
    // LSL alias requires imms != imms_max (that case is the MOV alias
    // / UBFX-all). Also immr == (imms + 1) mod datasize.
    if (imms == imms_max) {
        return false;
    }
    unsigned expected_immr = (imms + 1) % datasize;
    if (immr != expected_immr) {
        return false;
    }

    *out_sf = sf;
    *out_rd = op & 0x1fu;
    *out_rn = (op >> 5) & 0x1fu;
    *out_shift = imms_max - imms;
    return true;
}

// Detect arithmetic-shifted-register (ADD/SUB and S-variants) or
// logical-shifted-register (AND/ORR/EOR + N-variants and S-variants)
// whose immediate shift amount is zero, so the LSL can be folded in.
//
// Fills *out_mnem with the canonical underlying mnemonic (without the
// CMP/CMN/TST/MOV/MVN/NEG aliases -- those have Rd==31 or Rn==31 which
// the caller will inspect separately if needed).
static bool decode_shifted_register_consumer(
    uint32_t op,
    unsigned *out_sf,
    unsigned *out_rd,
    unsigned *out_rn,
    unsigned *out_rm,
    const char **out_mnem)
{
    bool is_arith = (op & 0x1f200000u) == 0x0b000000u;
    bool is_logic = (op & 0x1f000000u) == 0x0a000000u;
    if (!is_arith && !is_logic) {
        return false;
    }

    // Arithmetic shift type at bits 23..22; value 11 is RESERVED for
    // arithmetic. Capstone should have rejected such inputs, but
    // defensively skip if we see one.
    unsigned shift_type = (op >> 22) & 0x3u;
    if (is_arith && shift_type == 0x3u) {
        return false;
    }

    unsigned imm6 = (op >> 10) & 0x3fu;
    if (imm6 != 0) {
        return false;
    }
    unsigned sf = (op >> 31) & 0x1u;
    if (!sf && imm6 >= 32) {
        // Defensive: with sf=0 the imm6 must be < 32.
        return false;
    }

    *out_sf = sf;
    *out_rd = op & 0x1fu;
    *out_rn = (op >> 5) & 0x1fu;
    *out_rm = (op >> 16) & 0x1fu;

    if (is_arith) {
        unsigned arith_op = (op >> 30) & 0x1u;
        unsigned S = (op >> 29) & 0x1u;
        static const char *names[4] = { "add", "adds", "sub", "subs" };
        *out_mnem = names[(arith_op << 1) | S];
    } else {
        unsigned opc = (op >> 29) & 0x3u;
        unsigned N = (op >> 21) & 0x1u;
        static const char *names[8] = {
            "and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"
        };
        *out_mnem = names[(opc << 1) | N];
    }
    return true;
}

bool check_lsl_fold(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->lsl_active = false;
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    // (1) Try to close: is this instruction a shifted-register consumer
    //     of the pending LSL?
    if (state->lsl_active) {
        unsigned c_sf, c_rd, c_rn, c_rm;
        const char *c_mnem;
        if (decode_shifted_register_consumer(op, &c_sf, &c_rd, &c_rn, &c_rm,
                                             &c_mnem)
                && c_sf == (state->lsl_is_64bit ? 1u : 0u)
                && c_rm == state->lsl_rd
                && c_rd == state->lsl_rd
                && state->lsl_rd != 31) {
            char w_or_x = state->lsl_is_64bit ? 'x' : 'w';

            out->name = "LSL foldable into shifted-register form";
            out->start_offset = state->lsl_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            snprintf(out->detail, sizeof(out->detail),
                "-> %s %c%u, %c%u, %c%u, lsl #%u",
                c_mnem,
                w_or_x, c_rd,
                w_or_x, c_rn,
                w_or_x, state->lsl_rn,
                state->lsl_shift);

            snprintf(out->lines[0], sizeof(out->lines[0]),
                "lsl %c%u, %c%u, #%u",
                w_or_x, state->lsl_rd,
                w_or_x, state->lsl_rn,
                state->lsl_shift);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %c%u, %c%u, %c%u",
                c_mnem,
                w_or_x, c_rd,
                w_or_x, c_rn,
                w_or_x, c_rm);

            produced = true;
        }
        // Strict adjacency: any non-matching instruction expires the LSL.
        state->lsl_active = false;
    }

    // (2) Try to open: is this an LSL (immediate)?
    unsigned sf, rd, rn, shift;
    if (decode_lsl_imm(op, &sf, &rd, &rn, &shift)) {
        // Writing to XZR makes the LSL pointless and there is nothing
        // for a consumer to fold against; skip.
        if (rd != 31) {
            state->lsl_active = true;
            state->lsl_is_64bit = (sf != 0);
            state->lsl_rd = rd;
            state->lsl_rn = rn;
            state->lsl_shift = shift;
            state->lsl_offset = offset;
        }
    }

    return produced;
}

// Detect CMP Rn, #0, i.e. SUBS XZR, Rn, #0 in the immediate form with
// no LSL #12 shift.
//
//   sf | 1 | 1 | 100010 | sh | imm12 | Rn | Rd
//
// We require op=1 (SUB), S=1 (set flags), sh=0, imm12=0, Rd=31.
static bool decode_cmp_imm_zero(uint32_t op,
                                unsigned *out_sf, unsigned *out_rn)
{
    // Mask covers bit 30 (op), bit 29 (S), bits 28..23 (encoding class),
    // bit 22 (sh), bits 21..10 (imm12), bits 4..0 (Rd). Bit 31 (sf) is
    // left out so the comparison matches either operand width.
    if ((op & 0x7FFFFC1Fu) != 0x7100001Fu) {
        return false;
    }
    *out_sf = (op >> 31) & 0x1u;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// Detect B.cond with cond in {EQ, NE}. Returns the (sign-extended)
// 19-bit branch offset in *out_imm19.
//
//   0 1010100 0 imm19 0 cond
//
// (bits 31..24 = 01010100, bit 4 = 0, bits 3..0 = cond)
static bool decode_b_eq_or_ne(uint32_t op, bool *out_is_eq,
                              int32_t *out_imm19)
{
    if ((op & 0xFF000010u) != 0x54000000u) {
        return false;
    }
    unsigned cond = op & 0xFu;
    if (cond != 0 && cond != 1) {
        return false;
    }
    *out_is_eq = (cond == 0);
    int32_t imm19 = (int32_t)((op >> 5) & 0x7FFFFu);
    // Sign-extend from 19 bits to 32.
    imm19 = (imm19 ^ 0x40000) - 0x40000;
    *out_imm19 = imm19;
    return true;
}

// Flag-liveness classification of a single instruction observed during
// the forward scan that runs after a CMP+B.EQ/B.NE candidate.
typedef enum {
    LIV_UNKNOWN,        // no effect on NZCV; keep scanning
    LIV_OVERWRITE,      // writes all NZCV without reading them first
    LIV_READ,           // reads any of NZCV
    LIV_TERM_SAFE,      // terminator after which prior NZCV is unobservable
    LIV_TERM_UNSAFE,    // terminator whose target may observe NZCV
} liveness_t;

// Classify `op` for the NZCV liveness scan. Conservative on both ends:
// instructions we don't recognize are LIV_UNKNOWN (keep scanning until
// the window expires), and ambiguous reads/writes are erred toward
// LIV_READ.
static liveness_t classify_liveness(uint32_t op)
{
    // B.cond reads NZCV (which flags depend on cond).
    if ((op & 0xFF000010u) == 0x54000000u) {
        return LIV_READ;
    }
    // CFINV (Armv8.4): inverts C, depends on prior C value.
    if (op == 0xD500401Fu) {
        return LIV_READ;
    }
    // Conditional select family CSEL/CSINC/CSINV/CSNEG: reads NZCV.
    if ((op & 0x3FE00000u) == 0x1A800000u) {
        return LIV_READ;
    }
    // Conditional compare CCMP/CCMN: reads NZCV via cond then writes
    // either the compare result or the immediate nzcv. The read makes
    // the fold unsound regardless.
    if ((op & 0x3FE00000u) == 0x3A400000u) {
        return LIV_READ;
    }
    // Add/Subtract with carry (ADC/ADCS/SBC/SBCS): reads C. The same
    // encoding prefix also covers a handful of rare flag-touching
    // instructions (RMIF, SETF8, SETF16); classifying them as a read
    // is conservatively correct.
    if ((op & 0x1FE00000u) == 0x1A000000u) {
        return LIV_READ;
    }

    // ADDS/SUBS immediate (S=1): bit 29 = 1, bits 28..23 = 100010.
    if ((op & 0x3F800000u) == 0x31000000u) {
        return LIV_OVERWRITE;
    }
    // ADDS/SUBS shifted-register and extended-register (S=1):
    //   bit 29 = 1, bits 28..24 = 01011.
    if ((op & 0x3F000000u) == 0x2B000000u) {
        return LIV_OVERWRITE;
    }
    // ANDS immediate (bits 30..29 = 11, bits 28..23 = 100100).
    if ((op & 0x7F800000u) == 0x72000000u) {
        return LIV_OVERWRITE;
    }
    // ANDS/BICS shifted-register (bits 30..29 = 11, bits 28..24 = 01010).
    if ((op & 0x7F000000u) == 0x6A000000u) {
        return LIV_OVERWRITE;
    }
    // FCMP/FCMPE (any FP type): bits 31..24 = 00011110, bit 21 = 1,
    // bits 15..10 = 001000, bits 2..0 = 000. Covers register-register
    // and register-zero variants. FCSEL and FCCMP/FCCMPE -- which DO
    // read NZCV -- have different bits 11..10 (11 and 01 respectively)
    // and will not match this mask.
    if ((op & 0xFF20FC07u) == 0x1E202000u) {
        return LIV_OVERWRITE;
    }

    // BL (function call): callee may clobber NZCV per the AArch64 PCS.
    if ((op & 0xFC000000u) == 0x94000000u) {
        return LIV_TERM_SAFE;
    }
    // B (unconditional immediate): target may read NZCV; we don't
    // follow targets in v1.
    if ((op & 0xFC000000u) == 0x14000000u) {
        return LIV_TERM_UNSAFE;
    }
    // Unconditional branch (register): BR, BLR, RET, ERET, plus arm64e
    // PAC variants. opc at bits 24..21 distinguishes:
    //   0001 = BLR / 1001 = BLRA[A|B][Z]  -> safe (callee clobbers)
    //   0010 = RET / 1010 = RETA[A|B]     -> safe (function ends)
    //   0000 = BR  / 0100 = ERET / etc.   -> unsafe (unknown target)
    if ((op & 0xFE000000u) == 0xD6000000u) {
        unsigned opc = (op >> 21) & 0xFu;
        if (opc == 0x1u || opc == 0x2u
                || opc == 0x9u || opc == 0xAu) {
            return LIV_TERM_SAFE;
        }
        return LIV_TERM_UNSAFE;
    }

    return LIV_UNKNOWN;
}

bool armlint_advance_pending(armlint_state *state, const cs_insn *insn,
                             armlint_finding *out)
{
    if (insn->size != 4) {
        state->pending_active = false;
        return false;
    }
    if (!state->pending_active) {
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    switch (classify_liveness(op)) {
    case LIV_OVERWRITE:
    case LIV_TERM_SAFE:
        *out = state->pending_finding;
        state->pending_active = false;
        return true;
    case LIV_READ:
    case LIV_TERM_UNSAFE:
        state->pending_active = false;
        return false;
    case LIV_UNKNOWN:
        if (state->pending_window == 0
                || --state->pending_window == 0) {
            state->pending_active = false;
        }
        return false;
    }
    return false;
}

bool check_cmp_zero_branch(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out)
{
    (void)out;  // emission goes through armlint_advance_pending

    if (insn->size != 4) {
        state->cmp_active = false;
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    // (1) Close: is this a B.EQ/B.NE consuming the pending CMP?
    if (state->cmp_active) {
        bool is_eq;
        int32_t imm19;
        if (decode_b_eq_or_ne(op, &is_eq, &imm19)) {
            uint64_t target = insn->address
                + (uint64_t)((int64_t)imm19 * 4);
            char w_or_x = state->cmp_is_64bit ? 'x' : 'w';
            const char *cb_mnem = is_eq ? "cbz" : "cbnz";
            const char *bcond_mnem = is_eq ? "b.eq" : "b.ne";

            armlint_finding *p = &state->pending_finding;
            p->name = "compare-zero branch foldable into CBZ/CBNZ";
            p->start_offset = state->cmp_offset;
            p->insn_count = 2;
            clear_finding_strings(p);

            snprintf(p->detail, sizeof(p->detail),
                "-> %s %c%u, 0x%" PRIx64,
                cb_mnem, w_or_x, state->cmp_rn, target);

            snprintf(p->lines[0], sizeof(p->lines[0]),
                "cmp %c%u, #0", w_or_x, state->cmp_rn);
            snprintf(p->lines[1], sizeof(p->lines[1]),
                "%s 0x%" PRIx64, bcond_mnem, target);

            // Defer emission until a forward-liveness stopper confirms
            // no downstream code observes the dropped N/C/V (and Z
            // beyond the branch itself).
            state->pending_active = true;
            state->pending_window = LIVENESS_WINDOW;
        }
        // Strict adjacency: any non-matching instruction expires the CMP.
        state->cmp_active = false;
    }

    // (2) Open: is this a CMP Rn, #0 (Rn != XZR)?
    unsigned sf, rn;
    if (decode_cmp_imm_zero(op, &sf, &rn) && rn != 31) {
        state->cmp_active = true;
        state->cmp_is_64bit = (sf != 0);
        state->cmp_rn = rn;
        state->cmp_offset = offset;
    }

    return false;
}

// TST Rn, #(1<<k) = ANDS XZR, Rn, #imm where the logical immediate
// decodes to a single bit. ANDS-immediate encoding:
//   sf | 11 | 100100 | N | immr(6) | imms(6) | Rn | Rd
// Rd = 31 selects the TST alias; a single-bit pattern has imms = 0
// (S = 0, i.e. one '1'), with N == sf so the element size equals the
// full register width.
static bool decode_tst_single_bit(uint32_t op,
                                  unsigned *out_sf,
                                  unsigned *out_rn,
                                  unsigned *out_bit)
{
    if ((op & 0x7F800000u) != 0x72000000u) {
        return false;
    }
    if ((op & 0x1Fu) != 0x1Fu) {
        return false;
    }
    unsigned sf = (op >> 31) & 1u;
    unsigned N = (op >> 22) & 1u;
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;

    if (imms != 0) {
        return false;
    }
    if (sf == 0) {
        if (N != 0 || (immr & 0x20u)) {
            return false;
        }
        *out_bit = (32u - immr) % 32u;
    } else {
        if (N != 1) {
            return false;
        }
        *out_bit = (64u - immr) % 64u;
    }
    *out_sf = sf;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

bool check_tst_branch(armlint_state *state, const cs_insn *insn,
                     size_t offset, armlint_finding *out)
{
    (void)out;  // emission goes through armlint_advance_pending

    if (insn->size != 4) {
        state->tst_active = false;
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    // (1) Close: is this a B.EQ/B.NE consuming the pending TST?
    if (state->tst_active) {
        bool is_eq;
        int32_t imm19;
        if (decode_b_eq_or_ne(op, &is_eq, &imm19)) {
            // The proposed TBZ replaces the TST at the same address,
            // i.e. 4 bytes before the B.cond. Its required imm14 (in
            // instruction units) is therefore imm19 + 1. TBZ's imm14
            // is signed 14-bit, giving a ~32 KB reach.
            int64_t tbz_disp = (int64_t)imm19 + 1;
            if (tbz_disp >= -8192 && tbz_disp <= 8191) {
                uint64_t target = insn->address
                    + (uint64_t)((int64_t)imm19 * 4);
                char w_or_x = state->tst_is_64bit ? 'x' : 'w';
                const char *tb_mnem = is_eq ? "tbz" : "tbnz";
                const char *bcond_mnem = is_eq ? "b.eq" : "b.ne";

                armlint_finding *p = &state->pending_finding;
                p->name = "TST+B.EQ/NE foldable into TBZ/TBNZ";
                p->start_offset = state->tst_offset;
                p->insn_count = 2;
                clear_finding_strings(p);

                snprintf(p->detail, sizeof(p->detail),
                    "-> %s %c%u, #%u, 0x%" PRIx64,
                    tb_mnem, w_or_x, state->tst_rn,
                    state->tst_bit, target);

                if (state->tst_bit < 32) {
                    snprintf(p->lines[0], sizeof(p->lines[0]),
                        "tst %c%u, #0x%x",
                        w_or_x, state->tst_rn,
                        1u << state->tst_bit);
                } else {
                    snprintf(p->lines[0], sizeof(p->lines[0]),
                        "tst %c%u, #0x%" PRIx64,
                        w_or_x, state->tst_rn,
                        (uint64_t)1 << state->tst_bit);
                }
                snprintf(p->lines[1], sizeof(p->lines[1]),
                    "%s 0x%" PRIx64, bcond_mnem, target);

                state->pending_active = true;
                state->pending_window = LIVENESS_WINDOW;
            }
        }
        state->tst_active = false;
    }

    // (2) Open: is this a TST Rn, #(1<<k) (Rn != XZR)?
    unsigned sf, rn, bit;
    if (decode_tst_single_bit(op, &sf, &rn, &bit) && rn != 31) {
        state->tst_active = true;
        state->tst_is_64bit = (sf != 0);
        state->tst_rn = rn;
        state->tst_bit = bit;
        state->tst_offset = offset;
    }

    return false;
}

// UXTW Xd, Wn  =  UBFM Xd, Xn, #0, #31
//   sf=1, N=1, immr=000000, imms=011111, opc=10 (UBFM).
//   Fixed bits (Rn/Rd masked out): 0xD3407C00.
static bool decode_uxtw(uint32_t op, unsigned *out_rd, unsigned *out_rn)
{
    if ((op & 0xFFFFFC00u) != 0xD3407C00u) {
        return false;
    }
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// AND Xd, Xn, #0xffffffff  =  AND-immediate with sf=1, opc=00, N=1,
// immr=000000, imms=011111. Fixed bits: 0x92407C00.
static bool decode_and_x_lo32_mask(uint32_t op,
                                   unsigned *out_rd, unsigned *out_rn)
{
    if ((op & 0xFFFFFC00u) != 0x92407C00u) {
        return false;
    }
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// True if `op` is a W-form (sf=0) instruction whose Rd is at bits 4..0
// and which therefore leaves bits 63..32 of the corresponding X register
// zeroed. Conservative: matches well-known data-processing classes only;
// loads are deferred.
//
// Masks exclude the opc bits within each class so all variants match.
// E.g. 0x1F800000 selects bits 28..23 (the class identifier in the
// data-processing-immediate space), leaving bits 31..29 free; 0x1FE00000
// adds bits 22..21 (used to subdivide the data-processing-register
// space). The early bit-31 check forces sf=0.
static bool decode_w_form_zext(uint32_t op, unsigned *out_rd)
{
    unsigned rd = op & 0x1Fu;
    if (rd == 31) {
        return false;
    }
    if ((op & 0x80000000u) != 0) {
        return false;
    }

    // Data-processing immediate (bits 28..23 identify the class).
    if ((op & 0x1F800000u) == 0x11000000u           // ADD/SUB imm (+S)
            || (op & 0x1F800000u) == 0x12000000u    // AND/ORR/EOR/ANDS imm
            || (op & 0x1F800000u) == 0x12800000u    // MOVN/MOVZ/MOVK
            || (op & 0x1F800000u) == 0x13000000u    // SBFM/BFM/UBFM
            || (op & 0x1F800000u) == 0x13800000u) { // EXTR
        *out_rd = rd;
        return true;
    }
    // Data-processing register.
    //   01010 = logical shifted register
    //   01011 = add/sub shifted or extended register
    //   11010000 (bits 28..21) = add/sub with carry
    //   11010100 = conditional select (CSEL/CSINC/CSINV/CSNEG)
    //   11011    = data-processing 3-source (MADD/MSUB/MUL/...)
    //   11010110 with bit 30=0 = data-processing 2-source
    //   11010110 with bit 30=1 = data-processing 1-source
    if ((op & 0x1F000000u) == 0x0A000000u
            || (op & 0x1F000000u) == 0x0B000000u
            || (op & 0x1FE00000u) == 0x1A000000u
            || (op & 0x1FE00000u) == 0x1A800000u
            || (op & 0x1F000000u) == 0x1B000000u
            || (op & 0x7FE00000u) == 0x1AC00000u
            || (op & 0x7FE00000u) == 0x5AC00000u) {
        *out_rd = rd;
        return true;
    }
    return false;
}

bool check_redundant_zext(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->wzx_active = false;
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    // (1) Close: is this a redundant UXTW or AND-#0xffffffff consumer?
    if (state->wzx_active) {
        unsigned c_rd, c_rn;
        bool is_uxtw = decode_uxtw(op, &c_rd, &c_rn);
        bool is_and  = !is_uxtw && decode_and_x_lo32_mask(op, &c_rd, &c_rn);

        if ((is_uxtw || is_and)
                && c_rd == state->wzx_rd
                && c_rn == state->wzx_rd) {
            out->name = "redundant zero-extension after W-form op";
            out->start_offset = state->wzx_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            const char *mnem = is_uxtw ? "uxtw" : "and";
            snprintf(out->detail, sizeof(out->detail),
                "%s x%u, ... is a no-op (W-form already zero-extends)",
                mnem, c_rd);
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->wzx_producer_disasm);
            if (is_uxtw) {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "uxtw x%u, w%u", c_rd, c_rn);
            } else {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "and x%u, x%u, #0xffffffff", c_rd, c_rn);
            }
            produced = true;
        }
        // Strict adjacency: any non-matching instruction expires.
        state->wzx_active = false;
    }

    // (2) Open: is this a W-form Rd-writing producer?
    unsigned p_rd;
    if (decode_w_form_zext(op, &p_rd)) {
        state->wzx_active = true;
        state->wzx_rd = p_rd;
        state->wzx_offset = offset;
        snprintf(state->wzx_producer_disasm,
            sizeof(state->wzx_producer_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return produced;
}

static void report_finding(const armlint_finding *finding)
{
    if (finding->detail[0] != '\0') {
        printf("%s at offset: 0x%zx: %s (%u instructions)\n",
            finding->name, finding->start_offset,
            finding->detail, finding->insn_count);
    } else {
        printf("%s at offset: 0x%zx (%u instructions)\n",
            finding->name, finding->start_offset, finding->insn_count);
    }
    for (unsigned i = 0; i < ARMLINT_FINDING_LINES; i++) {
        if (finding->lines[i][0] != '\0') {
            printf("  %s\n", finding->lines[i]);
        }
    }
    printf("\n");
}

// Stream the byte buffer one instruction at a time. cs_disasm would
// require allocating a cs_insn for every instruction up front (5+ GB on
// a 100 MB text section) and silently stops at the first undecodable
// 4-byte slot. cs_disasm_iter recycles a single cs_insn and lets us
// skip past data-in-text by hand.
int check_instructions(csh handle, const uint8_t *inst, size_t len,
                       uint64_t base_addr)
{
    armlint_state *state = armlint_state_create();
    if (state == NULL) {
        return -1;
    }
    cs_insn *insn = cs_malloc(handle);
    if (insn == NULL) {
        armlint_state_destroy(state);
        return -1;
    }

    int errors = 0;
    const uint8_t *code = inst;
    size_t size = len;
    uint64_t address = base_addr;

    while (size >= 4) {
        uint64_t insn_addr = address;
        if (cs_disasm_iter(handle, &code, &size, &address, insn)) {
            armlint_finding finding;
            size_t offset = (size_t)(insn_addr - base_addr);
            // Advance deferred CMP/TST findings before running the
            // per-instruction checks, so that a check setting a new
            // pending in its step (1) isn't immediately re-advanced
            // against the same instruction.
            if (armlint_advance_pending(state, insn, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_movz_movk_bitmask(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_lsl_fold(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_cmp_zero_branch(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_tst_branch(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_redundant_zext(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
        } else {
            // Treat the slot as opaque data and skip a single A64
            // word. Flush first so an in-progress sequence cannot
            // straddle the gap.
            armlint_finding finding;
            if (armlint_flush(state, &finding)) {
                report_finding(&finding);
                errors++;
            }
            code += 4;
            size -= 4;
            address += 4;
        }
    }

    armlint_finding finding;
    if (armlint_flush(state, &finding)) {
        report_finding(&finding);
        errors++;
    }

    cs_free(insn, 1);
    armlint_state_destroy(state);
    return errors;
}
