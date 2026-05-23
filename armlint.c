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

    // LSL pending an LSR/ASR consumer for UBFX/SBFX folding. The state
    // is tracked separately from lsl_* because that check expects a
    // shifted-register consumer while this one expects a bitfield
    // consumer; a non-matching follow-up should not affect the other.
    bool bsx_active;
    bool bsx_is_64bit;
    unsigned bsx_rd;
    unsigned bsx_rn;
    unsigned bsx_shift;
    size_t bsx_offset;

    // LSR pending an AND-mask consumer for the "shift-right then mask"
    // UBFX idiom. Separate from bsx_* because that check is keyed on
    // an LSL producer; here we want an LSR producer.
    bool lra_active;
    bool lra_is_64bit;
    unsigned lra_rd;
    unsigned lra_rn;
    unsigned lra_shift;
    size_t lra_offset;

    // Zero-test of Rn (CMP Rn,#0 / CMP Rn,XZR / TST Rn,Rn) pending a
    // B.EQ/B.NE consumer.
    bool cmp_active;
    bool cmp_is_64bit;
    unsigned cmp_rn;
    size_t cmp_offset;
    char cmp_disasm[ARMLINT_FINDING_LINE_LEN];

    // TST Rn, #(1<<k) pending a B.EQ/B.NE consumer.
    bool tst_active;
    bool tst_is_64bit;
    unsigned tst_rn;
    unsigned tst_bit;       // bit position 0..63
    size_t tst_offset;

    // Producer of bits-above-N guaranteed zero, pending a redundant
    // zero-extension consumer that re-zeros those bits. wzx_zero_from
    // is the threshold P: the producer guarantees bits >= P are zero.
    //   W-form ALU / LDR Wt / LDRSB/LDRSH Wt -> P=32
    //   LDRH Wt -> P=16
    //   LDRB Wt -> P=8
    // A consumer that clears bits >= C is redundant iff P <= C.
    bool wzx_active;
    unsigned wzx_rd;
    unsigned wzx_zero_from;
    size_t wzx_offset;
    char wzx_producer_disasm[ARMLINT_FINDING_LINE_LEN];

    // Producer of "Rd[W-1..S] = sign(Rd[S-1])" pending a redundant
    // sign-extension consumer. Parallel to wzx_* but tracks two values:
    // sxt_signed_from = S, the lowest bit above which the sign of bit
    // S-1 is replicated; sxt_upper = W, the (exclusive) upper bound of
    // that region (32 for W-form, 64 for X-form).
    //   LDRSB Wt / SXTB Wd, Wn         -> (S=8,  W=32)
    //   LDRSH Wt / SXTH Wd, Wn         -> (S=16, W=32)
    //   LDRSB Xt / SXTB Xd, Wn         -> (S=8,  W=64)
    //   LDRSH Xt / SXTH Xd, Wn         -> (S=16, W=64)
    //   LDRSW Xt / SXTW Xd, Wn         -> (S=32, W=64)
    //   ASR Rd, Rn, #k (W/X)           -> (S=datasize-k, W=datasize)
    // A consumer SXTB/SXTH/SXTW with thresholds (S_c, W_c) is
    // redundant iff S_p <= S_c AND W_p == W_c AND Rd == Rn ==
    // producer.Rd. W_p == W_c (not <=) is required because a W-form
    // consumer zeros X[63:32], differing from an X-form producer's
    // sign-extended high half.
    bool sxt_active;
    unsigned sxt_rd;
    unsigned sxt_signed_from;
    unsigned sxt_upper;
    size_t sxt_offset;
    char sxt_producer_disasm[ARMLINT_FINDING_LINE_LEN];

    // Deferred CMP/TST + B.EQ/NE finding awaiting forward NZCV-liveness
    // verification. Only one of CMP or TST can be pending at a time
    // (a CMP would overwrite or be overwritten by a TST), so the
    // storage is shared.
    bool pending_active;
    unsigned pending_window;
    armlint_finding pending_finding;

    // Flag-setting ALU (S-variant: ADDS/SUBS/ANDS/BICS/ADCS/SBCS)
    // pending a CMP/TST-zero of its Rd. All members of the set put
    // Z = (Rd == 0), so a follow-up CMP Rd, #0 / CMP Rd, ZR / TST
    // Rd, Rd is recomputing the same Z.
    bool sv_active;
    bool sv_is_64bit;
    unsigned sv_rd;
    size_t sv_offset;
    char sv_disasm[ARMLINT_FINDING_LINE_LEN];

    // CMP/TST-zero of sv_rd observed adjacent to the S-variant,
    // awaiting a B.EQ/B.NE consumer. v1 requires the B.EQ/B.NE so
    // the same downstream NZCV-liveness scan as check_cmp_zero_branch
    // can verify that dropping the CMP is sound (downstream may not
    // observe N/C/V before they are overwritten).
    bool sv_cmp_active;
    size_t sv_cmp_offset;
    char sv_cmp_disasm[ARMLINT_FINDING_LINE_LEN];

    // Deferred "redundant zero-CMP/TST after S-variant" finding,
    // parallel to pending_*. Advanced by armlint_advance_pending_sv
    // with the same classify_liveness logic.
    bool pending_sv_active;
    unsigned pending_sv_window;
    armlint_finding pending_sv_finding;

    // Most-recent instruction was ADR / ADRP with the recorded Rd.
    // Used by check_add_sub_zero to skip the canonical
    // "ADRP Rd, page ; ADD Rd, Rd, #pageoff" addressing pair when
    // the linker resolved pageoff to 0: removing the ADD requires
    // re-linking, not a code rewrite, so it's not actionable.
    bool adr_recent;
    unsigned adr_recent_rd;
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
    state->bsx_active = false;
    state->lra_active = false;
    state->cmp_active = false;
    state->tst_active = false;
    state->wzx_active = false;
    state->sxt_active = false;
    state->sv_active = false;
    state->sv_cmp_active = false;
    state->pending_active = false;
    state->pending_sv_active = false;
    state->adr_recent = false;
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

// LSR (immediate) is UBFM with imms = datasize-1 and any non-zero immr;
// the shift amount equals immr. Decoder rejects immr=0 (which is the
// MOV-of-whole-register alias).
static bool decode_lsr_imm(uint32_t op, unsigned *out_sf,
                           unsigned *out_rd, unsigned *out_rn,
                           unsigned *out_shift)
{
    unsigned sf = (op >> 31) & 1u;
    unsigned N = (op >> 22) & 1u;
    if (N != sf) {
        return false;
    }
    uint32_t base = sf ? 0xD3400000u : 0x53000000u;
    if ((op & 0xFFC00000u) != base) {
        return false;
    }
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;
    unsigned datasize = sf ? 64u : 32u;
    if (imms != datasize - 1) {
        return false;
    }
    if (immr == 0) {
        return false;
    }
    if (!sf && (immr >= 32 || imms >= 32)) {
        return false;
    }
    *out_sf = sf;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_shift = immr;
    return true;
}

// ASR (immediate) is SBFM with imms = datasize-1 and any non-zero immr.
static bool decode_asr_imm(uint32_t op, unsigned *out_sf,
                           unsigned *out_rd, unsigned *out_rn,
                           unsigned *out_shift)
{
    unsigned sf = (op >> 31) & 1u;
    unsigned N = (op >> 22) & 1u;
    if (N != sf) {
        return false;
    }
    uint32_t base = sf ? 0x93400000u : 0x13000000u;
    if ((op & 0xFFC00000u) != base) {
        return false;
    }
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;
    unsigned datasize = sf ? 64u : 32u;
    if (imms != datasize - 1) {
        return false;
    }
    if (immr == 0) {
        return false;
    }
    if (!sf && (immr >= 32 || imms >= 32)) {
        return false;
    }
    *out_sf = sf;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_shift = immr;
    return true;
}

bool check_lsl_lsr_to_ubfx(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->bsx_active = false;
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    // (1) Close: is this LSR/ASR Rd, Rd, #b consuming the pending LSL?
    if (state->bsx_active) {
        unsigned c_sf, c_rd, c_rn, c_shift;
        bool is_lsr = decode_lsr_imm(op, &c_sf, &c_rd, &c_rn, &c_shift);
        bool is_asr = !is_lsr
            && decode_asr_imm(op, &c_sf, &c_rd, &c_rn, &c_shift);

        if ((is_lsr || is_asr)
                && c_sf == (state->bsx_is_64bit ? 1u : 0u)
                && c_rd == state->bsx_rd
                && c_rn == state->bsx_rd) {
            unsigned datasize = state->bsx_is_64bit ? 64u : 32u;
            unsigned a = state->bsx_shift;
            unsigned b = c_shift;
            unsigned lsb, width;
            const char *fold_mnem;
            // b >= a -> bitfield extraction: bits Rs[datasize-a-1 .. b-a]
            //   become Rd[datasize-b-1 .. 0], rest zero/sign-fill.
            // b < a  -> bitfield insertion: bits Rs[datasize-a-1 .. 0]
            //   become Rd[datasize-b-1 .. a-b], with Rd[a-b-1 .. 0] = 0
            //   and Rd above filled by zero (LSR) or sign of Rs[datasize-
            //   a-1] (ASR).
            if (b < a) {
                lsb = a - b;
                width = datasize - a;
                fold_mnem = is_asr ? "sbfiz" : "ubfiz";
            } else {
                lsb = b - a;
                width = datasize - b;
                fold_mnem = is_asr ? "sbfx" : "ubfx";
            }
            char w_or_x = state->bsx_is_64bit ? 'x' : 'w';
            const char *shift_mnem = is_asr ? "asr" : "lsr";

            out->name = "LSL+LSR/ASR foldable into bitfield op";
            out->start_offset = state->bsx_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            snprintf(out->detail, sizeof(out->detail),
                "-> %s %c%u, %c%u, #%u, #%u",
                fold_mnem, w_or_x, c_rd, w_or_x, state->bsx_rn,
                lsb, width);

            snprintf(out->lines[0], sizeof(out->lines[0]),
                "lsl %c%u, %c%u, #%u",
                w_or_x, state->bsx_rd, w_or_x, state->bsx_rn, a);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %c%u, %c%u, #%u",
                shift_mnem, w_or_x, c_rd, w_or_x, c_rn, b);
            produced = true;
        }
        // Strict adjacency: any non-matching instruction expires.
        state->bsx_active = false;
    }

    // (2) Open: is this LSL Rd, Rs, #a (shift > 0, Rd != XZR)?
    unsigned sf, rd, rn, shift;
    if (decode_lsl_imm(op, &sf, &rd, &rn, &shift)
            && rd != 31 && shift > 0) {
        state->bsx_active = true;
        state->bsx_is_64bit = (sf != 0);
        state->bsx_rd = rd;
        state->bsx_rn = rn;
        state->bsx_shift = shift;
        state->bsx_offset = offset;
    }

    return produced;
}

static bool decode_and_imm_lowmask(uint32_t op, unsigned *out_c,
                                   unsigned *out_rd, unsigned *out_rn);

bool check_lsr_and_to_ubfx(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->lra_active = false;
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    // (1) Close: AND Rd, Rd, #(1<<w)-1 consuming the pending LSR?
    if (state->lra_active) {
        unsigned width, c_rd, c_rn;
        unsigned consumer_sf = (op >> 31) & 1u;
        if (decode_and_imm_lowmask(op, &width, &c_rd, &c_rn)
                && consumer_sf == (state->lra_is_64bit ? 1u : 0u)
                && c_rd == state->lra_rd
                && c_rn == state->lra_rd) {
            unsigned datasize = state->lra_is_64bit ? 64u : 32u;
            // Cap the UBFX width at the number of valid bits in the
            // LSR output: bits >= datasize-shift are zero from the
            // LSR, so a wider mask doesn't extract more.
            unsigned ubfx_width = width;
            if (ubfx_width + state->lra_shift > datasize) {
                ubfx_width = datasize - state->lra_shift;
            }
            char w_or_x = state->lra_is_64bit ? 'x' : 'w';

            out->name = "LSR+AND foldable into UBFX";
            out->start_offset = state->lra_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            snprintf(out->detail, sizeof(out->detail),
                "-> ubfx %c%u, %c%u, #%u, #%u",
                w_or_x, c_rd, w_or_x, state->lra_rn,
                state->lra_shift, ubfx_width);

            snprintf(out->lines[0], sizeof(out->lines[0]),
                "lsr %c%u, %c%u, #%u",
                w_or_x, state->lra_rd, w_or_x, state->lra_rn,
                state->lra_shift);

            uint64_t mask = (width >= 64) ? ~(uint64_t)0
                                          : ((uint64_t)1 << width) - 1;
            if (state->lra_is_64bit && mask > 0xFFFFFFFFull) {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "and %c%u, %c%u, #0x%" PRIx64,
                    w_or_x, c_rd, w_or_x, c_rn, mask);
            } else {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "and %c%u, %c%u, #0x%x",
                    w_or_x, c_rd, w_or_x, c_rn, (unsigned)mask);
            }
            produced = true;
        }
        // Strict adjacency.
        state->lra_active = false;
    }

    // (2) Open: is this LSR Rd, Rs, #n (Rd != XZR)?
    unsigned sf, rd, rn, shift;
    if (decode_lsr_imm(op, &sf, &rd, &rn, &shift) && rd != 31) {
        state->lra_active = true;
        state->lra_is_64bit = (sf != 0);
        state->lra_rd = rd;
        state->lra_rn = rn;
        state->lra_shift = shift;
        state->lra_offset = offset;
    }

    return produced;
}

// Detect an instruction that sets Z=1 iff Rn==0, leaving NZCV in a state
// usable only for an equality-with-zero branch. Three encodings count:
//
//   CMP Rn, #0     = SUBS X/WZR, Rn, #0       (immediate; sh=0, imm12=0)
//   CMP Rn, X/WZR  = SUBS X/WZR, Rn, X/WZR    (shifted-reg; Rm=31,
//                                              shift=LSL, imm6=0)
//   TST Rn, Rn     = ANDS X/WZR, Rn, Rn       (logical shifted-reg;
//                                              Rm=Rn, shift=LSL, N=0,
//                                              imm6=0)
//
// All three have Rd=31. Bit 31 (sf) is left free so either operand
// width matches; for the TST form Rm and Rn must agree, which is
// verified after the mask check.
static bool decode_zero_test(uint32_t op,
                             unsigned *out_sf, unsigned *out_rn)
{
    // CMP Rn, #0 (SUBS-imm with Rd=31, sh=0, imm12=0).
    if ((op & 0x7FFFFC1Fu) == 0x7100001Fu) {
        *out_sf = (op >> 31) & 1u;
        *out_rn = (op >> 5) & 0x1Fu;
        return true;
    }
    // CMP Rn, XZR/WZR (SUBS shifted-reg with Rd=31, Rm=31, shift=LSL,
    // imm6=0).
    if ((op & 0x7FFFFC1Fu) == 0x6B1F001Fu) {
        *out_sf = (op >> 31) & 1u;
        *out_rn = (op >> 5) & 0x1Fu;
        return true;
    }
    // TST Rn, Rn (ANDS shifted-reg with Rd=31, shift=LSL, N=0, imm6=0,
    // and Rm == Rn).
    if ((op & 0x7FE0FC1Fu) == 0x6A00001Fu) {
        unsigned rm = (op >> 16) & 0x1Fu;
        unsigned rn = (op >> 5) & 0x1Fu;
        if (rm == rn) {
            *out_sf = (op >> 31) & 1u;
            *out_rn = rn;
            return true;
        }
    }
    return false;
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

static bool advance_one_pending(uint32_t op, bool *active, unsigned *window,
                                const armlint_finding *finding,
                                armlint_finding *out)
{
    if (!*active) {
        return false;
    }
    switch (classify_liveness(op)) {
    case LIV_OVERWRITE:
    case LIV_TERM_SAFE:
        *out = *finding;
        *active = false;
        return true;
    case LIV_READ:
    case LIV_TERM_UNSAFE:
        *active = false;
        return false;
    case LIV_UNKNOWN:
        if (*window == 0 || --*window == 0) {
            *active = false;
        }
        return false;
    }
    return false;
}

bool armlint_advance_pending(armlint_state *state, const cs_insn *insn,
                             armlint_finding *out)
{
    if (insn->size != 4) {
        state->pending_active = false;
        return false;
    }
    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);
    return advance_one_pending(op, &state->pending_active,
                               &state->pending_window,
                               &state->pending_finding, out);
}

bool armlint_advance_pending_sv(armlint_state *state, const cs_insn *insn,
                                armlint_finding *out)
{
    if (insn->size != 4) {
        state->pending_sv_active = false;
        return false;
    }
    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);
    return advance_one_pending(op, &state->pending_sv_active,
                               &state->pending_sv_window,
                               &state->pending_sv_finding, out);
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
                "%s", state->cmp_disasm);
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

    // (2) Open: is this a zero-test of Rn (Rn != XZR)?
    unsigned sf, rn;
    if (decode_zero_test(op, &sf, &rn) && rn != 31) {
        state->cmp_active = true;
        state->cmp_is_64bit = (sf != 0);
        state->cmp_rn = rn;
        state->cmp_offset = offset;
        snprintf(state->cmp_disasm, sizeof(state->cmp_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return false;
}

// Detect an integer flag-setting "S-variant" ALU that writes Rd
// (Rd != 31) and puts Z = (Rd == 0). Members: ADDS, SUBS, ANDS, BICS
// (immediate and shifted-register / extended-register where defined),
// and ADCS, SBCS. Aliases with Rd == 31 (CMP, CMN, TST) are rejected
// here because they don't write a useful destination -- they belong
// to the consumer side of check_redundant_cmp_after_s_variant.
static bool decode_s_variant_alu(uint32_t op, unsigned *out_sf,
                                 unsigned *out_rd)
{
    unsigned rd = op & 0x1Fu;
    if (rd == 31) {
        return false;
    }

    // ADDS/SUBS immediate: bit 29 = S = 1, bits 28..23 = 100010.
    if ((op & 0x3F800000u) == 0x31000000u) {
        *out_sf = (op >> 31) & 1u;
        *out_rd = rd;
        return true;
    }
    // ADDS/SUBS shifted-register and extended-register: bit 29 = 1,
    // bits 28..24 = 01011.
    if ((op & 0x3F000000u) == 0x2B000000u) {
        *out_sf = (op >> 31) & 1u;
        *out_rd = rd;
        return true;
    }
    // ANDS immediate: bits 30..29 = 11, bits 28..23 = 100100.
    if ((op & 0x7F800000u) == 0x72000000u) {
        *out_sf = (op >> 31) & 1u;
        *out_rd = rd;
        return true;
    }
    // ANDS/BICS shifted-register: bits 30..29 = 11, bits 28..24 = 01010.
    if ((op & 0x7F000000u) == 0x6A000000u) {
        *out_sf = (op >> 31) & 1u;
        *out_rd = rd;
        return true;
    }
    // ADCS/SBCS: bit 29 = S = 1, bits 28..21 = 11010000. (ADC/SBC have
    // S = 0 and are not flag-setting.)
    if ((op & 0x3FE00000u) == 0x3A000000u) {
        *out_sf = (op >> 31) & 1u;
        *out_rd = rd;
        return true;
    }

    return false;
}

bool check_redundant_cmp_after_s_variant(armlint_state *state,
                                         const cs_insn *insn,
                                         size_t offset,
                                         armlint_finding *out)
{
    (void)out;  // emission goes through armlint_advance_pending_sv

    if (insn->size != 4) {
        state->sv_active = false;
        state->sv_cmp_active = false;
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    // (1) Stage 3: B.EQ/B.NE consuming the sv+cmp chain?
    if (state->sv_cmp_active) {
        bool is_eq;
        int32_t imm19;
        if (decode_b_eq_or_ne(op, &is_eq, &imm19)) {
            uint64_t target = insn->address
                + (uint64_t)((int64_t)imm19 * 4);
            const char *bcond_mnem = is_eq ? "b.eq" : "b.ne";

            armlint_finding *p = &state->pending_sv_finding;
            p->name = "redundant zero-CMP/TST after flag-setting ALU";
            p->start_offset = state->sv_offset;
            p->insn_count = 3;
            clear_finding_strings(p);

            snprintf(p->detail, sizeof(p->detail),
                "drop %s -- Z already set by %s",
                state->sv_cmp_disasm, state->sv_disasm);
            snprintf(p->lines[0], sizeof(p->lines[0]),
                "%s", state->sv_disasm);
            snprintf(p->lines[1], sizeof(p->lines[1]),
                "%s", state->sv_cmp_disasm);
            snprintf(p->lines[2], sizeof(p->lines[2]),
                "%s 0x%" PRIx64, bcond_mnem, target);

            state->pending_sv_active = true;
            state->pending_sv_window = LIVENESS_WINDOW;
        }
        state->sv_cmp_active = false;
    }

    // (2) Stage 2: CMP/TST-zero of sv_rd consuming sv_active?
    if (state->sv_active) {
        unsigned cmp_sf, cmp_rn;
        if (decode_zero_test(op, &cmp_sf, &cmp_rn)
                && cmp_rn == state->sv_rd
                && cmp_sf == (state->sv_is_64bit ? 1u : 0u)) {
            state->sv_cmp_active = true;
            state->sv_cmp_offset = offset;
            snprintf(state->sv_cmp_disasm,
                sizeof(state->sv_cmp_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
        state->sv_active = false;
    }

    // (3) Stage 1: open S-variant pending state.
    unsigned sf, rd;
    if (decode_s_variant_alu(op, &sf, &rd)) {
        state->sv_active = true;
        state->sv_is_64bit = (sf != 0);
        state->sv_rd = rd;
        state->sv_offset = offset;
        snprintf(state->sv_disasm, sizeof(state->sv_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
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

// Decode a zero-extending UBFM alias (UXTB / UXTH / UXTW or the X-form
// "UBFM Xd, Xn, #0, #K-1" variants). On match returns C, the bit
// position above which the consumer guarantees zeros: 8 (UXTB), 16
// (UXTH) or 32 (UXTW). The W-form (sf=0, N=0) and X-form (sf=1, N=1)
// share the same low 22 bits; both forms produce the same zero-extended
// result. The imms-31 W-form (which would be "UXT-W" with sf=0) is
// excluded because that's the MOV/UBFX-of-the-whole-register alias and
// belongs to a different check.
static bool decode_ubfm_zext(uint32_t op, unsigned *out_c,
                             unsigned *out_rd, unsigned *out_rn)
{
    // UBFM general: sf 10 100110 N immr imms Rn Rd, with N == sf.
    // Mask bits 31..22 (class + N), leaving immr/imms/Rn/Rd free.
    unsigned sf = (op >> 31) & 1u;
    uint32_t base_val = sf ? 0xD3400000u : 0x53000000u;
    if ((op & 0xFFC00000u) != base_val) {
        return false;
    }
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;
    if (immr != 0) {
        return false;
    }
    unsigned c;
    switch (imms) {
    case 7:  c = 8;  break;
    case 15: c = 16; break;
    case 31:
        // sf=0 with imms=31 is "MOV Wd, Wn" (UBFM all-of-W) -- not
        // really a zero-extension consumer in the sense we want.
        if (sf == 0) {
            return false;
        }
        c = 32;
        break;
    default:
        return false;
    }
    *out_c = c;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// Decode an AND-immediate consumer with mask (1<<w) - 1 (a contiguous
// run of w low bits, no rotation), for any width w in 1..datasize-1.
//
// Encoding: sf 00 100100 N immr imms Rn Rd, with immr=0 and (N, imms)
// encoding S=w-1 at the appropriate element size. For sf=1, N must be
// 1 (esize=64) and imms ranges over [0, 62]. For sf=0, N must be 0 and
// imms[5] must be 0 (esize=32), with imms in [0, 30]; both all-ones
// boundaries (imms=31 in W, imms=63 in X) are excluded by the
// bitmask-immediate rules.
//
// Returns w in *out_c so the caller can compute "bits >= w are zero"
// (the consumer's clearing threshold for check_redundant_zext) or use
// it directly as the UBFX width (for check_lsr_and_to_ubfx).
static bool decode_and_imm_lowmask(uint32_t op, unsigned *out_c,
                                   unsigned *out_rd, unsigned *out_rn)
{
    unsigned sf = (op >> 31) & 1u;
    uint32_t base = sf ? 0x92400000u : 0x12000000u;
    if ((op & 0xFFC00000u) != base) {
        return false;
    }
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;
    if (immr != 0) {
        return false;
    }
    unsigned width;
    if (sf) {
        if (imms >= 63) {
            return false;
        }
        width = imms + 1;
    } else {
        if (imms >= 31) {
            return false;
        }
        width = imms + 1;
    }
    *out_c = width;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// Decode the W-form MOV-to-self consumer: ORR Wd, WZR, Wd, LSL #0
// (the MOV Wd, Wm register alias with Rm == Rd). Writing any W-form
// register zeros bits 63..32 of the underlying X register, so this is
// the C=32 consumer of the redundant-zero-extension check. Rejects
// Rd=31 (MOV WZR, WZR has no observable effect either way and the
// producer side already excludes Rd=31).
static bool decode_mov_w_self(uint32_t op, unsigned *out_c, unsigned *out_rd)
{
    if ((op & 0xFFE0FFE0u) != 0x2A0003E0u) {
        return false;
    }
    unsigned rm = (op >> 16) & 0x1Fu;
    unsigned rd = op & 0x1Fu;
    if (rm != rd || rd == 31) {
        return false;
    }
    *out_c = 32;
    *out_rd = rd;
    return true;
}

// True if `op` is an instruction whose Rd/Rt is at bits 4..0 and which
// leaves bits 63..P of the corresponding X register zeroed for the
// returned P. Conservative: matches W-form data-processing instructions
// (P=32) and W-form integer loads (P=8 for LDRB, 16 for LDRH, 32 for
// LDR / LDRSB / LDRSH).
static bool decode_w_form_zext(uint32_t op, unsigned *out_rd,
                               unsigned *out_zero_from)
{
    unsigned rd = op & 0x1Fu;
    if (rd == 31) {
        return false;
    }

    // W-form data processing (sf=0). See the table in the comment for
    // the per-class masks; the early bit-31 check forces sf=0.
    if ((op & 0x80000000u) == 0) {
        if ((op & 0x1F800000u) == 0x11000000u           // ADD/SUB imm
                || (op & 0x1F800000u) == 0x12000000u    // logical imm
                || (op & 0x1F800000u) == 0x12800000u    // move wide imm
                || (op & 0x1F800000u) == 0x13000000u    // bitfield
                || (op & 0x1F800000u) == 0x13800000u    // extract
                || (op & 0x1F000000u) == 0x0A000000u    // logical sh reg
                || (op & 0x1F000000u) == 0x0B000000u    // add/sub sh/ext
                || (op & 0x1FE00000u) == 0x1A000000u    // adc/sbc
                || (op & 0x1FE00000u) == 0x1A800000u    // cond select
                || (op & 0x1F000000u) == 0x1B000000u    // DP 3-source
                || (op & 0x7FE00000u) == 0x1AC00000u    // DP 2-source
                || (op & 0x7FE00000u) == 0x5AC00000u) { // DP 1-source
            *out_rd = rd;
            *out_zero_from = 32;
            return true;
        }
    }

    // Integer loads with Wt destination. The "load/store register"
    // family shares bits 29..27 = 111 and bit 26 = 0 (V=0, general
    // register). bits 31..30 = size, bits 23..22 = opc select the
    // operation; bits 25..24 distinguish addressing modes (00 covers
    // unscaled / pre-/post-index / register offset, 01 is the
    // unsigned-immediate offset). The mask 0xFEC00000 leaves bit 24
    // free so all modes match; we exclude bit 25 = 1 (which selects
    // SIMD/FP or atomic-op families).
    //
    //   LDRB  Wt: size=00, opc=01  -> P=8
    //   LDRH  Wt: size=01, opc=01  -> P=16
    //   LDR   Wt: size=10, opc=01  -> P=32
    //   LDRSB Wt: size=00, opc=11  -> P=32 (sign-ext within W;
    //                                       W-form still zeros X63..32)
    //   LDRSH Wt: size=01, opc=11  -> P=32
    if ((op & 0xFEC00000u) == 0x38400000u) { *out_rd = rd; *out_zero_from = 8;  return true; }  // LDRB W
    if ((op & 0xFEC00000u) == 0x78400000u) { *out_rd = rd; *out_zero_from = 16; return true; }  // LDRH W
    if ((op & 0xFEC00000u) == 0xB8400000u) { *out_rd = rd; *out_zero_from = 32; return true; }  // LDR W
    if ((op & 0xFEC00000u) == 0x38C00000u) { *out_rd = rd; *out_zero_from = 32; return true; }  // LDRSB W
    if ((op & 0xFEC00000u) == 0x78C00000u) { *out_rd = rd; *out_zero_from = 32; return true; }  // LDRSH W

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

    // (1) Close: is this a UBFM/AND-imm/MOV-self consumer that clears
    //     bits already known zero?
    if (state->wzx_active) {
        unsigned c, c_rd, c_rn;
        bool is_ubfm = decode_ubfm_zext(op, &c, &c_rd, &c_rn);
        bool is_and  = !is_ubfm && decode_and_imm_lowmask(op, &c, &c_rd, &c_rn);
        bool is_mov  = false;
        if (!is_ubfm && !is_and) {
            is_mov = decode_mov_w_self(op, &c, &c_rd);
            if (is_mov) {
                // MOV Wd, Wd has Rn=WZR in the encoding; Rm==Rd is
                // enforced by the decoder, so the "operand register"
                // that must match the producer's Rd is Rd itself.
                c_rn = c_rd;
            }
        }

        if ((is_ubfm || is_and || is_mov)
                && c_rd == state->wzx_rd
                && c_rn == state->wzx_rd
                && state->wzx_zero_from <= c) {
            out->name = "redundant zero-extension after W-form op";
            out->start_offset = state->wzx_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            snprintf(out->detail, sizeof(out->detail),
                "%s %s is a no-op (bits >= %u already zero)",
                insn->mnemonic, insn->op_str, state->wzx_zero_from);
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->wzx_producer_disasm);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %s", insn->mnemonic, insn->op_str);
            produced = true;
        }
        // Strict adjacency: any non-matching instruction expires.
        state->wzx_active = false;
    }

    // (2) Open: is this a producer that zeros some high-bit region?
    unsigned p_rd, p_zero_from;
    if (decode_w_form_zext(op, &p_rd, &p_zero_from)) {
        state->wzx_active = true;
        state->wzx_rd = p_rd;
        state->wzx_zero_from = p_zero_from;
        state->wzx_offset = offset;
        snprintf(state->wzx_producer_disasm,
            sizeof(state->wzx_producer_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return produced;
}

// Decode an SBFM sign-extending alias (SXTB / SXTH / SXTW). Returns
// the threshold pair (S, W): the alias produces "bits >= S of Rd are
// = sign(bit S-1)" within the upper bound W (32 for the W-form alias,
// 64 for the X-form). The sf=0, imms=31 case is the "full-W copy"
// alias (SBFM Wd, Wn, #0, #31), not an SXT, and is rejected.
static bool decode_sbfm_sext(uint32_t op, unsigned *out_s, unsigned *out_w,
                             unsigned *out_rd, unsigned *out_rn)
{
    unsigned sf = (op >> 31) & 1u;
    uint32_t base = sf ? 0x93400000u : 0x13000000u;
    if ((op & 0xFFC00000u) != base) {
        return false;
    }
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;
    if (immr != 0) {
        return false;
    }
    unsigned s;
    unsigned w = sf ? 64u : 32u;
    switch (imms) {
    case 7:  s = 8;  break;
    case 15: s = 16; break;
    case 31:
        if (!sf) {
            return false;
        }
        s = 32;
        break;
    default:
        return false;
    }
    *out_s = s;
    *out_w = w;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// Detect a sign-extending producer for check_redundant_sext: the SBFM
// SXT* aliases, the ASR (immediate) shift (which sign-extends the
// source's top bit through bits [datasize-k, datasize)), and the
// sign-extending integer loads LDRSB/LDRSH/LDRSW in any addressing
// mode (the load mask leaves bit 24 free so unsigned-immediate,
// unscaled, pre-/post-/register-offset forms all match). Producers
// with Rd=31 are skipped (write goes to ZR).
static bool decode_sext_producer(uint32_t op, unsigned *out_s,
                                 unsigned *out_w, unsigned *out_rd)
{
    unsigned rd_field = op & 0x1Fu;
    if (rd_field == 31) {
        return false;
    }

    unsigned s, w, rd, dummy_rn;
    if (decode_sbfm_sext(op, &s, &w, &rd, &dummy_rn)) {
        *out_s = s;
        *out_w = w;
        *out_rd = rd;
        return true;
    }

    // ASR (immediate): SBFM with imms = datasize-1 and immr = shift > 0.
    // After ASR Rd, Rn, #k, bits [datasize-k, datasize) of Rd equal
    // Rn[datasize-1] = Rd[datasize-k-1], so S = datasize-k, W = datasize
    // (W-form additionally zeros X[63:32] but that's the zext check's
    // concern; here we only track the sign-extended region).
    unsigned asr_sf, asr_rd, asr_rn, asr_shift;
    if (decode_asr_imm(op, &asr_sf, &asr_rd, &asr_rn, &asr_shift)) {
        unsigned datasize = asr_sf ? 64u : 32u;
        *out_s = datasize - asr_shift;
        *out_w = datasize;
        *out_rd = asr_rd;
        return true;
    }

    // Sign-extending loads. (size, opc) -> (S, W):
    //   LDRSB Xt: (00, 10) -> (8,  64)
    //   LDRSB Wt: (00, 11) -> (8,  32)
    //   LDRSH Xt: (01, 10) -> (16, 64)
    //   LDRSH Wt: (01, 11) -> (16, 32)
    //   LDRSW Xt: (10, 10) -> (32, 64)
    if ((op & 0xFEC00000u) == 0x38800000u) { *out_s = 8;  *out_w = 64; *out_rd = rd_field; return true; }
    if ((op & 0xFEC00000u) == 0x38C00000u) { *out_s = 8;  *out_w = 32; *out_rd = rd_field; return true; }
    if ((op & 0xFEC00000u) == 0x78800000u) { *out_s = 16; *out_w = 64; *out_rd = rd_field; return true; }
    if ((op & 0xFEC00000u) == 0x78C00000u) { *out_s = 16; *out_w = 32; *out_rd = rd_field; return true; }
    if ((op & 0xFEC00000u) == 0xB8800000u) { *out_s = 32; *out_w = 64; *out_rd = rd_field; return true; }

    return false;
}

bool check_redundant_sext(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->sxt_active = false;
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    // (1) Close: is this an SXT consumer compatible with the open
    //     producer state?
    if (state->sxt_active) {
        unsigned c_s, c_w, c_rd, c_rn;
        if (decode_sbfm_sext(op, &c_s, &c_w, &c_rd, &c_rn)
                && c_rd == state->sxt_rd
                && c_rn == state->sxt_rd
                && state->sxt_signed_from <= c_s
                && state->sxt_upper == c_w) {
            out->name = "redundant sign-extension after sign-extending op";
            out->start_offset = state->sxt_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            snprintf(out->detail, sizeof(out->detail),
                "%s %s is a no-op (sign already extended from bit %u)",
                insn->mnemonic, insn->op_str,
                state->sxt_signed_from - 1);
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->sxt_producer_disasm);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %s", insn->mnemonic, insn->op_str);
            produced = true;
        }
        // Strict adjacency: any non-matching instruction expires.
        state->sxt_active = false;
    }

    // (2) Open: is this a sign-extending producer?
    unsigned p_s, p_w, p_rd;
    if (decode_sext_producer(op, &p_s, &p_w, &p_rd)) {
        state->sxt_active = true;
        state->sxt_rd = p_rd;
        state->sxt_signed_from = p_s;
        state->sxt_upper = p_w;
        state->sxt_offset = offset;
        snprintf(state->sxt_producer_disasm,
            sizeof(state->sxt_producer_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return produced;
}

bool check_add_sub_zero(armlint_state *state, const cs_insn *insn,
                        size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->adr_recent = false;
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    bool produced = false;

    // ADD/SUB immediate, S=0: bits 28..24 = 10001, bit 29 (S) = 0; sf
    // (bit 31) and op (bit 30) are free.
    if ((op & 0x3F000000u) == 0x11000000u
            && ((op >> 29) & 1u) == 0) {
        unsigned sh = (op >> 22) & 0x3u;
        unsigned imm12 = (op >> 10) & 0xFFFu;
        // sh=00 (LSL #0) and sh=01 (LSL #12) both yield imm=0 when
        // imm12=0. sh in {10, 11} is UNALLOCATED.
        if (imm12 == 0 && sh < 2) {
            unsigned rn = (op >> 5) & 0x1Fu;
            unsigned rd = op & 0x1Fu;
            // ADD/SUB immediate uses SP encoding for Rd=31 and Rn=31:
            // those are the canonical MOV (to/from SP) alias.
            // The Rd == Rn case is suppressed when preceded by an
            // ADR/ADRP with the same Rd: that's the linker-resolved
            // "page address + zero offset" pair, removable only by
            // re-linking, not by an assembler rewrite.
            bool is_adr_pair = state->adr_recent
                && state->adr_recent_rd == rd
                && rd == rn;
            if (rd != 31 && rn != 31 && !is_adr_pair) {
                unsigned sf = (op >> 31) & 1u;
                char w_or_x = sf ? 'x' : 'w';
                bool is_sub = ((op >> 30) & 1u) != 0;
                const char *mnem = is_sub ? "sub" : "add";

                out->name = "ADD/SUB #0 is redundant";
                out->start_offset = offset;
                out->insn_count = 1;
                clear_finding_strings(out);

                if (rd == rn) {
                    snprintf(out->detail, sizeof(out->detail),
                        "%s %c%u, %c%u, #0 is a no-op",
                        mnem, w_or_x, rd, w_or_x, rn);
                } else {
                    snprintf(out->detail, sizeof(out->detail),
                        "%s %c%u, %c%u, #0 -> mov %c%u, %c%u",
                        mnem, w_or_x, rd, w_or_x, rn,
                        w_or_x, rd, w_or_x, rn);
                }
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s %s", insn->mnemonic, insn->op_str);
                produced = true;
            }
        }
    }

    // Update the ADR/ADRP tracking for the NEXT call. ADR and ADRP
    // share bits 28..24 = 10000; bit 31 = 0 for ADR, 1 for ADRP.
    if ((op & 0x1F000000u) == 0x10000000u) {
        state->adr_recent = true;
        state->adr_recent_rd = op & 0x1Fu;
    } else {
        state->adr_recent = false;
    }

    return produced;
}

bool check_mov_reg_self(armlint_state *state, const cs_insn *insn,
                        size_t offset, armlint_finding *out)
{
    (void)state;

    if (insn->size != 4) {
        return false;
    }

    uint32_t op = (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);

    // X-form MOV Xd, Xm = ORR Xd, XZR, Xm with shift=LSL #0. Base
    // 0xAA0003E0 carries sf=1, opc=01 (ORR), class=01010, shift=LSL,
    // N=0, imm6=0, Rn=XZR; free fields are Rm (bits 20..16) and Rd
    // (bits 4..0). We only flag Rm == Rd: that case is the literal
    // no-op. Rd=31 (MOV XZR, XZR) discards the value and is not
    // actionable.
    if ((op & 0xFFE0FFE0u) != 0xAA0003E0u) {
        return false;
    }
    unsigned rm = (op >> 16) & 0x1Fu;
    unsigned rd = op & 0x1Fu;
    if (rm != rd || rd == 31) {
        return false;
    }

    out->name = "redundant MOV to self";
    out->start_offset = offset;
    out->insn_count = 1;
    clear_finding_strings(out);

    snprintf(out->detail, sizeof(out->detail),
        "%s %s is a no-op", insn->mnemonic, insn->op_str);
    snprintf(out->lines[0], sizeof(out->lines[0]),
        "%s %s", insn->mnemonic, insn->op_str);
    return true;
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
            if (armlint_advance_pending_sv(state, insn, &finding)) {
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
            if (check_redundant_sext(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_lsl_lsr_to_ubfx(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_lsr_and_to_ubfx(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_mov_reg_self(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_add_sub_zero(state, insn, offset, &finding)) {
                report_finding(&finding);
                errors++;
            }
            if (check_redundant_cmp_after_s_variant(state, insn, offset,
                                                    &finding)) {
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
