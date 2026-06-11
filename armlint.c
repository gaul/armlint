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

    // Shift-immediate (LSL/LSR/ASR, or ROR via same-register EXTR)
    // pending a shifted-register consumer. shf_type holds the
    // consumer encoding's shift-type field value (0=LSL, 1=LSR,
    // 2=ASR, 3=ROR).
    bool shf_active;
    bool shf_is_64bit;
    unsigned shf_type;
    unsigned shf_rd;
    unsigned shf_rn;
    unsigned shf_shift;
    size_t shf_offset;

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

    // AND-immediate (with a single contiguous run of 1s) pending an LSR
    // consumer for the "mask then shift-right" UBFX idiom -- the mirror
    // of lra_* (which is keyed on an LSR producer). alr_lo/alr_hi bound
    // the mask's run of ones [lo, hi]; alr_rn is the AND's source (the
    // UBFX source) and alr_rd is the AND's destination, which the LSR
    // must read and write.
    bool alr_active;
    bool alr_is_64bit;
    unsigned alr_rd;
    unsigned alr_rn;
    unsigned alr_lo;
    unsigned alr_hi;
    size_t alr_offset;
    char alr_disasm[ARMLINT_FINDING_LINE_LEN];

    // AND-low-mask or LSR pending an LSL consumer (the "shift a field up"
    // idiom). An AND of the low w bits then LSL #n folds to UBFIZ Rd, Rs,
    // #n, #w; an LSR #a then LSL #a (equal shifts) clears the low a bits,
    // i.e. AND Rd, Rs, #~(2^a-1). aul_is_lsr selects which producer;
    // aul_param holds the mask width w (AND) or the shift a (LSR). aul_rd
    // is the producer's destination (the LSL reads and writes it), aul_rn
    // its source (the fold's source).
    bool aul_active;
    bool aul_is_64bit;
    bool aul_is_lsr;
    unsigned aul_rd;
    unsigned aul_rn;
    unsigned aul_param;
    size_t aul_offset;
    char aul_disasm[ARMLINT_FINDING_LINE_LEN];

    // Zero-test of Rn (CMP Rn,#0 / CMP Rn,XZR / TST Rn,Rn) pending a
    // B.EQ/B.NE consumer (any form), a B.HI/B.LS consumer (the SUBS
    // forms only -- cmp_is_subs), or a sign-condition B.cond.
    bool cmp_active;
    bool cmp_is_64bit;
    bool cmp_is_subs;
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
    // True when the producer is a data-relocating shift (ASR) rather
    // than a pure in-place sign-extension (SXTB/SXTH/SXTW, LDRS*). The
    // redundant-SXT path is sound for both (a following SXT re-extends
    // the same field in place), but the dead-sign-extension path treats
    // the producer as removable, which is only valid when the producer
    // leaves the meaningful data in its original low bits. ASR shifts
    // those bits, so it must be excluded from the dead path.
    bool sxt_is_shift;

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

    // BFXIL/BFI synthesis: clear a w-bit field at position lsb, isolate
    // the same field from a source, and OR them together --
    //   AND Rd, Rd, #~(mask<<lsb) ; <isolate Rt> ; ORR Rd, Rd, Rt
    //     -> BFXIL Rd, Rs, #0, #w   (lsb == 0)
    //     -> BFI   Rd, Rs, #lsb, #w (lsb >  0)
    // The isolate is a low-mask AND (lsb == 0) or a UBFIZ (lsb > 0). The
    // clear and isolate can appear in either order; we track them
    // independently. Both flags set means we are waiting for the ORR.
    // Strict adjacency: any unrecognized instruction expires both flags.
    bool bfx_clear_seen;
    bool bfx_isolate_seen;
    bool bfx_is_64bit;
    unsigned bfx_width;
    unsigned bfx_lsb;          // field position; 0 == BFXIL, >0 == BFI
    unsigned bfx_clear_rd;     // Rd from "AND Rd, Rd, #~(mask<<lsb)"
    unsigned bfx_isolate_rt;   // destination of the isolate (AND/UBFIZ)
    unsigned bfx_isolate_rn;   // Rs (the source of the bitfield)
    size_t bfx_first_offset;   // offset of whichever op came first
    char bfx_clear_disasm[ARMLINT_FINDING_LINE_LEN];
    char bfx_isolate_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending MUL Rt, Ra, Rb awaiting an adjacent ADD/SUB consumer
    // whose Rd overwrites Rt and whose accumulator operand is not Rt
    // -- the pair folds to MADD/MSUB. Strict adjacency: any
    // non-matching instruction expires the state.
    bool mul_pending;
    bool mul_pending_is_64bit;
    unsigned mul_pending_rd;
    unsigned mul_pending_rn;
    unsigned mul_pending_rm;
    size_t mul_pending_offset;
    char mul_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending widening multiply SMULL/UMULL Xt, Wa, Wb awaiting an
    // adjacent X-form ADD/SUB consumer whose Rd overwrites Xt and whose
    // accumulator operand is not Xt -- the pair folds to SMADDL/UMADDL
    // (ADD) or SMSUBL/UMSUBL (SUB). The 32x32->64 product is always
    // 64-bit, so the consumer must be X-form. wmul_pending_rn/rm are the
    // W-form multiply operands; the destination and accumulator are
    // X-form. wmul_pending_signed selects the S* vs U* mnemonic family.
    // Strict adjacency: any non-matching instruction expires the state.
    bool wmul_pending;
    bool wmul_pending_signed;
    unsigned wmul_pending_rd;
    unsigned wmul_pending_rn;
    unsigned wmul_pending_rm;
    size_t wmul_pending_offset;
    char wmul_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending NEG Rt, Rs (the SUB Rt, XZR, Rs alias, no shift, non-S)
    // awaiting an adjacent ADD/SUB consumer whose Rd overwrites Rt and
    // whose negated-operand slot is Rt -- the pair folds to a single
    // SUB (for ADD consumer) or ADD (for SUB consumer). Strict
    // adjacency: any non-matching instruction expires the state.
    bool neg_pending;
    bool neg_pending_is_64bit;
    unsigned neg_pending_rd;
    unsigned neg_pending_rs;
    size_t neg_pending_offset;
    char neg_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending MVN Rt, Rs (the ORN Rt, XZR, Rs alias, no shift) awaiting
    // an adjacent AND/ORR/EOR/ANDS (shifted-register, LSL #0, N=0)
    // consumer whose Rd overwrites Rt and one of whose sources is Rt --
    // the pair folds the bitwise-NOT into the consumer's negated-operand
    // form: AND->BIC, ORR->ORN, EOR->EON, ANDS->BICS. The logical ops
    // commute, so Rt may sit in either source slot. Strict adjacency.
    bool mvn_pending;
    bool mvn_pending_is_64bit;
    unsigned mvn_pending_rd;
    unsigned mvn_pending_rs;
    size_t mvn_pending_offset;
    char mvn_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending standalone extend (UXTB/UXTH/SXTB/SXTH/SXTW) Rt, Rs
    // awaiting an adjacent ADD/SUB (shifted-register, LSL #0) consumer
    // whose Rd overwrites Rt and one of whose sources is Rt -- the pair
    // folds into the consumer's extended-register form (the extend, and
    // optional shift, ride on the consumer's Rm). ADD/ADDS commute so Rt
    // may be in either source slot; SUB/SUBS need it in Rm. The producer
    // form (W vs X) must match the consumer's, except that a W-form
    // zero-extend (UXTB/UXTH) also feeds an X-form consumer (the W
    // write zeroed the high half). ext_pending_option is the
    // ADD/SUB extend option (0 UXTB, 1 UXTH, 4 SXTB, 5 SXTH, 6 SXTW).
    bool ext_pending;
    bool ext_pending_is_64bit;
    unsigned ext_pending_rd;
    unsigned ext_pending_rs;
    unsigned ext_pending_option;
    size_t ext_pending_offset;
    char ext_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending SXTW Xt, Ws awaiting an adjacent register-offset LDR whose
    // index register and destination both equal Xt -- the pair folds the
    // sign-extend into the load's addressing mode (option SXTW). The LDR
    // overwrites Xt, so the extended index is dead. sxl_rd is the SXTW's
    // destination (the load's index/Rt), sxl_rs its W source.
    bool sxl_pending;
    unsigned sxl_rd;
    unsigned sxl_rs;
    size_t sxl_offset;
    char sxl_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending unsigned-offset load awaiting an adjacent in-place
    // sign-extend (SXTB/SXTH/SXTW) of the loaded register -- the pair
    // folds to the matching sign-extending load LDRSB/LDRSH/LDRSW.
    // Two producer families: zero-extending loads (LDRB/LDRH/LDR Wt,
    // lsx_signed = false), where the consumer's sign threshold must
    // equal the load's access width; and the W-form sign-extending
    // loads (LDRSB/LDRSH Wt, lsx_signed = true), where any X-form
    // consumer with threshold >= the access width re-extends a sign
    // copy and folds to the X-form load. The consumer overwrites the
    // load's Rt, so the intermediate is dead. lsx_size is the load's
    // size field (0=B, 1=H, 2=W). Strict adjacency: any non-matching
    // instruction expires the state.
    bool lsx_active;
    bool lsx_signed;
    unsigned lsx_size;
    unsigned lsx_rt;
    unsigned lsx_rn;
    unsigned lsx_imm12;
    size_t lsx_offset;
    char lsx_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending X-form ADD (shifted-register, LSL #s, non-S-variant)
    // awaiting an adjacent unsigned-offset LDR consumer whose base
    // register and destination register both equal Rd of the ADD. The
    // pair folds to a single register-offset LDR. Strict adjacency:
    // any non-matching instruction expires the state.
    bool add_pending;
    unsigned add_pending_rd;
    unsigned add_pending_rn;
    unsigned add_pending_rm;
    unsigned add_pending_shift;
    size_t add_pending_offset;
    char add_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending X-form ADD-immediate (non-S-variant) awaiting an adjacent
    // unsigned-offset LDR consumer with imm12 == 0 whose base register
    // and destination register both equal Rd of the ADD. The pair folds
    // to a single immediate-offset LDR, provided the ADD's byte
    // immediate is a multiple of the LDR's access size and the scaled
    // value fits in 12 bits. addi_pending_imm is the actual byte
    // immediate (sh=1 already expanded to imm12 << 12). Strict
    // adjacency: any non-matching instruction expires the state.
    bool addi_pending;
    unsigned addi_pending_rd;
    unsigned addi_pending_rn;
    uint32_t addi_pending_imm;
    size_t addi_pending_offset;
    char addi_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending unsigned-offset LDR/STR with imm12 == 0 awaiting an
    // adjacent X-form ADD-immediate that self-updates the base
    // register (Rd == Rn == LDR/STR's Rn). The pair folds into a
    // single post-indexed LDR/STR with the ADD/SUB's byte immediate in
    // the post-index slot. Post-index uses a 9-bit signed immediate
    // (-256..255): ADD imm in 1..255 folds to a positive writeback,
    // SUB imm in 1..256 to a negative one. SIMD&FP accesses
    // (lspi_pending_is_fp; size is then the log2 transfer bytes,
    // 0..4 for B/H/S/D/Q) fold the same way -- every FP size has a
    // post-indexed form, and the FP Rt can never alias the integer
    // base. Strict adjacency: any non-matching instruction expires
    // the state.
    bool lspi_pending;
    bool lspi_pending_is_load;
    bool lspi_pending_is_fp;
    unsigned lspi_pending_size;
    unsigned lspi_pending_rn;
    unsigned lspi_pending_rt;
    size_t lspi_pending_offset;
    char lspi_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending X-form ADD-immediate self-update (Rd == Rn) awaiting an
    // adjacent unsigned-offset LDR/STR with imm12 == 0 whose base
    // register equals the ADD's Rd. The pair folds into a single
    // pre-indexed LDR/STR. Same 9-bit signed range as post-index: ADD
    // imm in 1..255 (positive writeback) or SUB imm in 1..256 (negative
    // writeback), the sign recorded in lspr_pending_is_sub. Distinct from
    // check_add_ldr_imm_offset, which catches the related pattern
    // where the LDR's Rt also equals the ADD's Rd (folding to the
    // unsigned-offset form with no writeback).
    bool lspr_pending;
    bool lspr_pending_is_sub;     // SUB self-update -> negative writeback
    unsigned lspr_pending_rd;
    uint32_t lspr_pending_imm;    // magnitude; sign carried by is_sub
    size_t lspr_pending_offset;
    char lspr_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending unsigned-offset LDR/STR/LDRSW awaiting an adjacent
    // partner for LDP/STP/LDPSW coalescing. The next instruction of
    // the same kind (sext or zext, integer or SIMD&FP) with the same
    // Rn, same direction (load/load or store/store), same access size,
    // and imm12 = previous + 1 (in scaled units) closes the pair into
    // an LDP/STP/LDPSW. Strict adjacency: any non-matching instruction
    // expires the state. lsp_is_sext flags an LDRSW (always Xt, load,
    // 4-byte transfer); lsp_is_fp a SIMD&FP access (S/D/Q -- the only
    // FP sizes with a pair form -- with lsp_lg2size the log2 transfer
    // bytes, 2/3/4); otherwise lsp_is_64bit selects W/X and
    // lsp_is_load selects load/store.
    bool lsp_active;
    bool lsp_is_load;
    bool lsp_is_64bit;
    bool lsp_is_sext;
    bool lsp_is_fp;
    unsigned lsp_lg2size;
    unsigned lsp_rt;
    unsigned lsp_rn;
    unsigned lsp_imm12;
    size_t lsp_offset;
    char lsp_disasm[ARMLINT_FINDING_LINE_LEN];
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

// Assemble the little-endian 4-byte A64 instruction word. Every check
// decodes from the raw bytes (rather than Capstone's parsed fields) to
// avoid ambiguity from alias selection; this centralizes that assembly.
// Callers guard insn->size == 4 first; the cs_insn byte buffer is always
// large enough to read four bytes regardless.
static uint32_t insn_word(const cs_insn *insn)
{
    return (uint32_t)insn->bytes[0]
        | ((uint32_t)insn->bytes[1] << 8)
        | ((uint32_t)insn->bytes[2] << 16)
        | ((uint32_t)insn->bytes[3] << 24);
}

// Minimal number of move-wide instructions (MOVZ/MOVN + MOVKs) that
// can materialize value at reg_width: a MOVZ-based chain needs one
// instruction per non-zero halfword, a MOVN-based chain one per
// non-0xffff halfword, each with a floor of one (MOVZ #0 / MOVN #0
// for the all-zeros / all-ones values).
static unsigned minimal_mov_wide_count(uint64_t value, unsigned reg_width)
{
    unsigned halfwords = reg_width / 16u;
    unsigned nonzero = 0, nonones = 0;
    for (unsigned i = 0; i < halfwords; i++) {
        unsigned hw = (value >> (i * 16u)) & 0xffffu;
        if (hw != 0) {
            nonzero++;
        }
        if (hw != 0xffffu) {
            nonones++;
        }
    }
    unsigned movz_len = nonzero ? nonzero : 1u;
    unsigned movn_len = nonones ? nonones : 1u;
    return movz_len < movn_len ? movz_len : movn_len;
}

// Render the minimal MOVZ/MOVN + MOVK sequence for value into buf,
// instructions separated by " ; ". Ties between the MOVZ- and
// MOVN-based forms go to MOVZ (the canonical spelling). A flagged
// chain's suggestion is at most one instruction per halfword minus
// one, which fits the detail buffer.
static void render_minimal_mov_wide(char *buf, size_t bufsz,
                                    char w_or_x, unsigned rd,
                                    uint64_t value, unsigned reg_width)
{
    unsigned halfwords = reg_width / 16u;
    unsigned nonzero = 0, nonones = 0;
    for (unsigned i = 0; i < halfwords; i++) {
        unsigned hw = (value >> (i * 16u)) & 0xffffu;
        if (hw != 0) {
            nonzero++;
        }
        if (hw != 0xffffu) {
            nonones++;
        }
    }
    bool use_movn = (nonones ? nonones : 1u) < (nonzero ? nonzero : 1u);
    unsigned skip_hw = use_movn ? 0xffffu : 0u;

    if ((use_movn ? nonones : nonzero) == 0) {
        // All-zeros (MOVZ) or all-ones (MOVN): a single base insn.
        snprintf(buf, bufsz, "%s %c%u, #0x0",
            use_movn ? "movn" : "movz", w_or_x, rd);
        return;
    }

    size_t pos = 0;
    bool first = true;
    for (unsigned i = 0; i < halfwords && pos < bufsz; i++) {
        unsigned hw = (value >> (i * 16u)) & 0xffffu;
        if (hw == skip_hw) {
            continue;
        }
        // MOVN materializes ~(imm16 << shift), so the base instruction
        // carries the complemented halfword; the MOVKs that follow
        // overwrite with the actual halfword values.
        const char *mnem = first ? (use_movn ? "movn" : "movz") : "movk";
        unsigned imm = (first && use_movn) ? (~hw & 0xffffu) : hw;
        unsigned shift = i * 16u;
        int n;
        if (shift == 0) {
            n = snprintf(buf + pos, bufsz - pos, "%s%s %c%u, #0x%x",
                first ? "" : " ; ", mnem, w_or_x, rd, imm);
        } else {
            n = snprintf(buf + pos, bufsz - pos,
                "%s%s %c%u, #0x%x, lsl #%u",
                first ? "" : " ; ", mnem, w_or_x, rd, imm, shift);
        }
        if (n < 0) {
            break;
        }
        pos += (size_t)n;
        first = false;
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
        bool bitmask = is_bitmask_immediate(state->mov_value, reg_width);
        unsigned minimal =
            minimal_mov_wide_count(state->mov_value, reg_width);
        if (bitmask || state->mov_insn_count > minimal) {
            char w_or_x = state->mov_is_64bit ? 'x' : 'w';

            out->name = "suboptimal MOVZ/MOVK sequence";
            out->start_offset = state->mov_start_offset;
            out->insn_count = state->mov_insn_count;
            clear_finding_strings(out);

            if (bitmask) {
                // Encodable as a single bitmask-immediate MOV (ORR).
                snprintf(out->detail, sizeof(out->detail),
                    "%c%u = 0x%" PRIx64,
                    w_or_x, state->mov_rd, state->mov_value);
            } else {
                // Not a bitmask immediate, but a shorter MOVZ/MOVN +
                // MOVK chain reaches the same value.
                char seq[ARMLINT_FINDING_DETAIL_LEN - 4];
                render_minimal_mov_wide(seq, sizeof(seq), w_or_x,
                    state->mov_rd, state->mov_value, reg_width);
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s", seq);
            }

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
    // The shift, CMP, and TST checks never produce a finding from flush
    // alone -- an isolated shift, CMP, or TST is not actionable -- but
    // their state must be cleared so a new region starts fresh. Any
    // pending CMP+B.EQ/NE or TST+B.EQ/NE finding is discarded too:
    // without seeing a safe stopper before end-of-region, we cannot
    // prove the fold is sound.
    state->shf_active = false;
    state->bsx_active = false;
    state->lra_active = false;
    state->alr_active = false;
    state->aul_active = false;
    state->cmp_active = false;
    state->tst_active = false;
    state->wzx_active = false;
    state->sxt_active = false;
    state->sv_active = false;
    state->sv_cmp_active = false;
    state->pending_active = false;
    state->pending_sv_active = false;
    state->adr_recent = false;
    state->bfx_clear_seen = false;
    state->bfx_isolate_seen = false;
    state->lsp_active = false;
    state->mul_pending = false;
    state->wmul_pending = false;
    state->neg_pending = false;
    state->mvn_pending = false;
    state->ext_pending = false;
    state->sxl_pending = false;
    state->lsx_active = false;
    state->add_pending = false;
    state->addi_pending = false;
    state->lspi_pending = false;
    state->lspr_pending = false;
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

    uint32_t op = insn_word(insn);

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

static bool decode_lsr_imm(uint32_t op, unsigned *out_sf,
                           unsigned *out_rd, unsigned *out_rn,
                           unsigned *out_shift);
static bool decode_asr_imm(uint32_t op, unsigned *out_sf,
                           unsigned *out_rd, unsigned *out_rn,
                           unsigned *out_shift);

// Shift-type names indexed by the shifted-register encoding's
// shift-type field (bits 23..22).
static const char *const shift_type_name[4] = {
    "lsl", "lsr", "asr", "ror"
};

// Decode ROR (immediate) -- the EXTR Rd, Rs, Rs, #shift alias (Rn ==
// Rm). EXTR: sf | 00 | 100111 | N(= sf) | 0 | Rm(5) | imms(6) | Rn(5)
// | Rd(5); the W-form requires imms < 32. The shift equals imms;
// imms == 0 is rejected (EXTR #0 is a plain register copy, not a
// rotate).
static bool decode_ror_imm(uint32_t op, unsigned *out_sf,
                           unsigned *out_rd, unsigned *out_rn,
                           unsigned *out_shift)
{
    unsigned sf = (op >> 31) & 1u;
    uint32_t base = sf ? 0x93C00000u : 0x13800000u;
    if ((op & 0xFFE00000u) != base) {
        return false;
    }
    unsigned rm = (op >> 16) & 0x1Fu;
    unsigned rn = (op >> 5) & 0x1Fu;
    if (rm != rn) {
        return false;
    }
    unsigned imms = (op >> 10) & 0x3Fu;
    if (imms == 0) {
        return false;
    }
    if (!sf && imms >= 32) {
        return false;
    }
    *out_sf = sf;
    *out_rd = op & 0x1Fu;
    *out_rn = rn;
    *out_shift = imms;
    return true;
}

// Detect arithmetic-shifted-register (ADD/SUB and S-variants) or
// logical-shifted-register (AND/ORR/EOR + N-variants and S-variants)
// whose immediate shift amount is zero, so a shift can be folded in.
//
// Fills *out_mnem with the canonical underlying mnemonic (without the
// CMP/CMN/TST/MOV/MVN/NEG aliases -- those have Rd==31 or Rn==31 which
// the caller will inspect separately if needed). *out_is_arith
// distinguishes the families: the arithmetic one reserves shift type
// 11 (ROR), so only logical consumers can absorb a rotate.
static bool decode_shifted_register_consumer(
    uint32_t op,
    unsigned *out_sf,
    unsigned *out_rd,
    unsigned *out_rn,
    unsigned *out_rm,
    const char **out_mnem,
    bool *out_commutes,
    bool *out_is_arith)
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
    *out_is_arith = is_arith;

    if (is_arith) {
        unsigned arith_op = (op >> 30) & 0x1u;
        unsigned S = (op >> 29) & 0x1u;
        static const char *names[4] = { "add", "adds", "sub", "subs" };
        *out_mnem = names[(arith_op << 1) | S];
        // ADD/ADDS commute (a+b == b+a, same flags); SUB/SUBS do not.
        *out_commutes = (arith_op == 0u);
    } else {
        unsigned opc = (op >> 29) & 0x3u;
        unsigned N = (op >> 21) & 0x1u;
        static const char *names[8] = {
            "and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"
        };
        *out_mnem = names[(opc << 1) | N];
        // The N=0 members (AND/ORR/EOR/ANDS) commute, as does EON
        // (opc=2, N=1) -- it is bitwise XNOR, so a^~b == b^~a. The other
        // N=1 members BIC (a & ~b), ORN (a | ~b) and BICS do not.
        *out_commutes = (N == 0u) || (opc == 2u);
    }
    return true;
}

bool check_lsl_fold(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->shf_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Try to close: is this instruction a shifted-register consumer
    //     of the pending shift?
    if (state->shf_active) {
        unsigned c_sf, c_rd, c_rn, c_rm;
        const char *c_mnem;
        bool c_commutes, c_is_arith;
        if (decode_shifted_register_consumer(op, &c_sf, &c_rd, &c_rn, &c_rm,
                                             &c_mnem, &c_commutes,
                                             &c_is_arith)
                && c_sf == (state->shf_is_64bit ? 1u : 0u)
                && c_rd == state->shf_rd
                && state->shf_rd != 31
                // Arithmetic shifted-register reserves type 11 (ROR):
                // a rotate can ride only on a logical consumer.
                && !(c_is_arith && state->shf_type == 3u)) {
            // The shifted-register form carries the shift on Rm only, so
            // the shift result must be exactly one source operand and the
            // other -- the "independent" operand that becomes the new Rn
            // -- must NOT also be the shift destination (else the fold,
            // which reads pre-shift register values, would use the wrong
            // value for it). When the shift result is in Rn, only a
            // commutative consumer can move it to Rm by swapping sources.
            unsigned indep;
            bool foldable = false;
            if (c_rm == state->shf_rd && c_rn != state->shf_rd) {
                indep = c_rn;
                foldable = true;
            } else if (c_rn == state->shf_rd && c_rm != state->shf_rd
                       && c_commutes) {
                indep = c_rm;
                foldable = true;
            }

            if (foldable) {
                char w_or_x = state->shf_is_64bit ? 'x' : 'w';
                const char *shift_mnem = shift_type_name[state->shf_type];

                out->name = "shift foldable into shifted-register form";
                out->start_offset = state->shf_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %c%u, %c%u, %c%u, %s #%u",
                    c_mnem,
                    w_or_x, c_rd,
                    w_or_x, indep,
                    w_or_x, state->shf_rn,
                    shift_mnem,
                    state->shf_shift);

                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s %c%u, %c%u, #%u",
                    shift_mnem,
                    w_or_x, state->shf_rd,
                    w_or_x, state->shf_rn,
                    state->shf_shift);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %c%u, %c%u, %c%u",
                    c_mnem,
                    w_or_x, c_rd,
                    w_or_x, c_rn,
                    w_or_x, c_rm);

                produced = true;
            }
        }
        // Strict adjacency: any non-matching instruction expires the
        // pending shift.
        state->shf_active = false;
    }

    // (2) Try to open: is this a shift (immediate)? LSL/LSR/ASR are
    //     UBFM/SBFM aliases; ROR is the same-register EXTR alias.
    unsigned sf, rd, rn, shift;
    unsigned type = 0;
    bool opened = false;
    if (decode_lsl_imm(op, &sf, &rd, &rn, &shift)) {
        type = 0;
        opened = true;
    } else if (decode_lsr_imm(op, &sf, &rd, &rn, &shift)) {
        type = 1;
        opened = true;
    } else if (decode_asr_imm(op, &sf, &rd, &rn, &shift)) {
        type = 2;
        opened = true;
    } else if (decode_ror_imm(op, &sf, &rd, &rn, &shift)) {
        type = 3;
        opened = true;
    }
    // Writing to XZR makes the shift pointless and there is nothing
    // for a consumer to fold against; skip.
    if (opened && rd != 31) {
        state->shf_active = true;
        state->shf_is_64bit = (sf != 0);
        state->shf_type = type;
        state->shf_rd = rd;
        state->shf_rn = rn;
        state->shf_shift = shift;
        state->shf_offset = offset;
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

    uint32_t op = insn_word(insn);

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

    uint32_t op = insn_word(insn);

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

// Reconstruct the concrete value of a logical (bitmask) immediate from
// its (N, immr, imms) fields at the given datasize (32 or 64). This is
// the AArch64 DecodeBitMasks "wmask". Returns false for encodings that
// are not valid bitmask immediates (len < 1, or S == esize-1, the
// all-ones-within-element case). On success *out_value holds the value
// masked to datasize bits.
static bool decode_bitmask_imm_value(unsigned N, unsigned immr,
                                     unsigned imms, unsigned datasize,
                                     uint64_t *out_value)
{
    unsigned bits7 = (N << 6) | ((~imms) & 0x3Fu);   // N : NOT(imms)
    if (bits7 == 0) {
        return false;
    }
    int len = 6;
    while (len >= 0 && ((bits7 >> len) & 1u) == 0) {
        len--;
    }
    if (len < 1) {
        return false;
    }
    unsigned esize = 1u << len;
    unsigned S = imms & (esize - 1u);
    unsigned R = immr & (esize - 1u);
    if (S == esize - 1u) {
        return false;   // all-ones within the element -- not encodable
    }
    uint64_t welem = ((uint64_t)1 << (S + 1u)) - 1u;   // S+1 low ones
    uint64_t elem_mask = (esize == 64u) ? ~(uint64_t)0
                                        : (((uint64_t)1 << esize) - 1u);
    uint64_t rotated = (R == 0)
        ? welem
        : (((welem >> R) | (welem << (esize - R))) & elem_mask);
    uint64_t value = 0;
    for (unsigned pos = 0; pos < datasize; pos += esize) {
        value |= rotated << pos;
    }
    if (datasize == 32u) {
        value &= 0xFFFFFFFFu;
    }
    *out_value = value;
    return true;
}

// Decode an AND (immediate), W- or X-form, returning the concrete mask
// value and registers. Base 0x12000000 (W, N=0) / 0x92400000 (X, N=1),
// mask 0xFFC00000 -- the same family the existing low-/high-mask
// decoders match, but here the full value is reconstructed so the
// caller can inspect arbitrary run shapes. ANDS (flag-setting) has
// different opc bits and is not matched.
static bool decode_and_imm(uint32_t op, unsigned *out_sf, uint64_t *out_mask,
                           unsigned *out_rd, unsigned *out_rn)
{
    unsigned sf = (op >> 31) & 1u;
    uint32_t base = sf ? 0x92400000u : 0x12000000u;
    if ((op & 0xFFC00000u) != base) {
        return false;
    }
    unsigned N = (op >> 22) & 1u;
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;
    uint64_t value;
    if (!decode_bitmask_imm_value(N, immr, imms, sf ? 64u : 32u, &value)) {
        return false;
    }
    *out_sf = sf;
    *out_mask = value;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

bool check_and_lsr_to_ubfx(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->alr_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: LSR Rd, Rd, #n consuming the pending AND? The LSR must
    //     read and write the AND's destination (Rd == Rn == alr_rd).
    if (state->alr_active) {
        unsigned c_sf, c_rd, c_rn, n;
        if (decode_lsr_imm(op, &c_sf, &c_rd, &c_rn, &n)
                && c_sf == (state->alr_is_64bit ? 1u : 0u)
                && c_rd == state->alr_rd
                && c_rn == state->alr_rd) {
            unsigned lo = state->alr_lo;
            unsigned hi = state->alr_hi;
            // (mask & ws) >> n is a bottom-aligned field -- a single
            // UBFX -- iff the run is not shifted past bit 0 (lo <= n,
            // so any mask bits below n are simply dropped) and not
            // shifted out entirely (n <= hi). The surviving bits are
            // ws[hi : n], so width = hi + 1 - n at lsb = n. lo > n would
            // leave the field above bit 0 (no single UBFX); n > hi makes
            // the result 0 (a different, degenerate rewrite).
            if (lo <= n && n <= hi) {
                unsigned width = hi + 1u - n;
                char w_or_x = state->alr_is_64bit ? 'x' : 'w';

                out->name = "AND+LSR foldable into UBFX";
                out->start_offset = state->alr_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                snprintf(out->detail, sizeof(out->detail),
                    "-> ubfx %c%u, %c%u, #%u, #%u",
                    w_or_x, c_rd, w_or_x, state->alr_rn, n, width);

                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->alr_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "lsr %c%u, %c%u, #%u",
                    w_or_x, c_rd, w_or_x, c_rn, n);
                produced = true;
            }
        }
        // Strict adjacency: any non-matching instruction expires.
        state->alr_active = false;
    }

    // (2) Open: is this AND Rd, Rs, #<single contiguous run> (Rd != XZR)?
    unsigned a_sf, a_rd, a_rn;
    uint64_t mask;
    if (decode_and_imm(op, &a_sf, &mask, &a_rd, &a_rn) && a_rd != 31) {
        unsigned datasize = a_sf ? 64u : 32u;
        unsigned lo = 0;
        while (lo < datasize && ((mask >> lo) & 1u) == 0) {
            lo++;
        }
        if (lo < datasize) {
            unsigned hi = datasize - 1u;
            while (hi > lo && ((mask >> hi) & 1u) == 0) {
                hi--;
            }
            unsigned runlen = hi - lo + 1u;
            uint64_t runmask = (runlen >= 64u)
                ? ~(uint64_t)0
                : (((uint64_t)1 << runlen) - 1u) << lo;
            if (datasize == 32u) {
                runmask &= 0xFFFFFFFFu;
            }
            // Single contiguous, non-wrapping run only. Replicated
            // patterns (esize < datasize, e.g. 0x0f0f0f0f) and rotated
            // wrapping runs leave a gap, so mask != runmask and are
            // skipped -- they have no single-UBFX equivalent.
            if (mask == runmask) {
                state->alr_active = true;
                state->alr_is_64bit = (a_sf != 0);
                state->alr_rd = a_rd;
                state->alr_rn = a_rn;
                state->alr_lo = lo;
                state->alr_hi = hi;
                state->alr_offset = offset;
                snprintf(state->alr_disasm, sizeof(state->alr_disasm),
                    "%s %s", insn->mnemonic, insn->op_str);
            }
        }
    }

    return produced;
}

bool check_and_lsr_lsl_fold(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->aul_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: LSL Rd, Rd, #n consuming the pending AND-low-mask / LSR?
    if (state->aul_active) {
        unsigned c_sf, c_rd, c_rn, n;
        if (decode_lsl_imm(op, &c_sf, &c_rd, &c_rn, &n)
                && c_sf == (state->aul_is_64bit ? 1u : 0u)
                && c_rd == state->aul_rd
                && c_rn == state->aul_rd) {
            unsigned datasize = state->aul_is_64bit ? 64u : 32u;
            char w_or_x = state->aul_is_64bit ? 'x' : 'w';

            if (!state->aul_is_lsr) {
                // AND low w bits, then LSL #n:
                //   (ws & ((1<<w)-1)) << n  ==  ubfiz Rd, Rs, #n, #w.
                // Cap the width at the bits that survive the shift, since
                // n + w may exceed datasize.
                unsigned width = state->aul_param;
                if (n + width > datasize) {
                    width = datasize - n;
                }
                out->name = "AND+LSL foldable into UBFIZ";
                out->start_offset = state->aul_offset;
                out->insn_count = 2;
                clear_finding_strings(out);
                snprintf(out->detail, sizeof(out->detail),
                    "-> ubfiz %c%u, %c%u, #%u, #%u",
                    w_or_x, c_rd, w_or_x, state->aul_rn, n, width);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->aul_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);
                produced = true;
            } else if (n == state->aul_param) {
                // LSR #a then LSL #a clears the low a bits:
                //   (ws >> a) << a  ==  ws & ~((1<<a)-1).
                // Unequal shifts have no single-instruction form (the
                // surviving field is neither low- nor zero-aligned), so
                // they are left un-flagged.
                unsigned a = state->aul_param;
                uint64_t mask = ~(((uint64_t)1 << a) - 1u);
                if (datasize == 32u) {
                    mask &= 0xFFFFFFFFu;
                }
                out->name = "LSR+LSL foldable into bit-clearing AND";
                out->start_offset = state->aul_offset;
                out->insn_count = 2;
                clear_finding_strings(out);
                snprintf(out->detail, sizeof(out->detail),
                    "-> and %c%u, %c%u, #0x%" PRIx64,
                    w_or_x, c_rd, w_or_x, state->aul_rn, mask);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->aul_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);
                produced = true;
            }
        }
        // Strict adjacency: any non-matching instruction expires.
        state->aul_active = false;
    }

    // (2) Open: an AND with a low mask, or an LSR (Rd != XZR)?
    unsigned w_width, a_rd, a_rn;
    if (decode_and_imm_lowmask(op, &w_width, &a_rd, &a_rn) && a_rd != 31) {
        state->aul_active = true;
        state->aul_is_64bit = (((op >> 31) & 1u) != 0u);
        state->aul_is_lsr = false;
        state->aul_rd = a_rd;
        state->aul_rn = a_rn;
        state->aul_param = w_width;
        state->aul_offset = offset;
        snprintf(state->aul_disasm, sizeof(state->aul_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    } else {
        unsigned l_sf, l_rd, l_rn, l_shift;
        if (decode_lsr_imm(op, &l_sf, &l_rd, &l_rn, &l_shift)
                && l_rd != 31) {
            state->aul_active = true;
            state->aul_is_64bit = (l_sf != 0);
            state->aul_is_lsr = true;
            state->aul_rd = l_rd;
            state->aul_rn = l_rn;
            state->aul_param = l_shift;
            state->aul_offset = offset;
            snprintf(state->aul_disasm, sizeof(state->aul_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
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
//
// The forms differ in the carry they leave: the SUBS-based CMPs set
// C = 1 (subtracting zero never borrows), which makes the unsigned
// HI/LS conditions reduce to NE/EQ; the ANDS-based TST clears C,
// where HI is never taken and LS always. *out_is_subs reports which
// family matched so the caller can gate the HI/LS fold.
static bool decode_zero_test(uint32_t op, unsigned *out_sf,
                             unsigned *out_rn, bool *out_is_subs)
{
    // CMP Rn, #0 (SUBS-imm with Rd=31, sh=0, imm12=0).
    if ((op & 0x7FFFFC1Fu) == 0x7100001Fu) {
        *out_sf = (op >> 31) & 1u;
        *out_rn = (op >> 5) & 0x1Fu;
        *out_is_subs = true;
        return true;
    }
    // CMP Rn, XZR/WZR (SUBS shifted-reg with Rd=31, Rm=31, shift=LSL,
    // imm6=0).
    if ((op & 0x7FFFFC1Fu) == 0x6B1F001Fu) {
        *out_sf = (op >> 31) & 1u;
        *out_rn = (op >> 5) & 0x1Fu;
        *out_is_subs = true;
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
            *out_is_subs = false;
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

// Detect B.cond with cond in {HI, LS}. After a SUBS-based zero test
// (CMP Rn, #0 / CMP Rn, ZR) the carry is always set -- subtracting
// zero never borrows -- so HI (C && !Z) reduces to NE and LS
// (!C || Z) to EQ, the same CBNZ/CBZ rewrite as the eq/ne forms.
// Callers must confirm the producer really is the SUBS form: the
// ANDS-based TST Rn, Rn clears C, where HI is never taken and LS
// always -- dead-branch territory, not this fold.
static bool decode_b_hi_or_ls(uint32_t op, bool *out_is_ls,
                              int32_t *out_imm19)
{
    if ((op & 0xFF000010u) != 0x54000000u) {
        return false;
    }
    unsigned cond = op & 0xFu;
    if (cond != 8 && cond != 9) {
        return false;
    }
    *out_is_ls = (cond == 9);
    int32_t imm19 = (int32_t)((op >> 5) & 0x7FFFFu);
    imm19 = (imm19 ^ 0x40000) - 0x40000;
    *out_imm19 = imm19;
    return true;
}

// Detect B.cond with cond in {MI, PL, LT, GE} -- branches whose truth
// depends only on the sign bit when V == 0 (which holds after a
// CMP Rn, #0 / CMP Rn, ZR / TST Rn, Rn). MI (N==1) and LT (N!=V with
// V=0 -> N==1) test "sign == 1"; PL (N==0) and GE (N==V with V=0 ->
// N==0) test "sign == 0". Returns is_neg = true for MI/LT, false for
// PL/GE, plus the specific cond (for disassembly).
static bool decode_b_sign_cond(uint32_t op, bool *out_is_neg,
                               unsigned *out_cond, int32_t *out_imm19)
{
    if ((op & 0xFF000010u) != 0x54000000u) {
        return false;
    }
    unsigned cond = op & 0xFu;
    bool is_neg;
    switch (cond) {
    case 4:   // MI
    case 11:  // LT
        is_neg = true;
        break;
    case 5:   // PL
    case 10:  // GE
        is_neg = false;
        break;
    default:
        return false;
    }
    *out_is_neg = is_neg;
    *out_cond = cond;
    int32_t imm19 = (int32_t)((op >> 5) & 0x7FFFFu);
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
    // FCSEL (FP conditional select) reads NZCV: bits 31..24 = 00011110,
    // bit 21 = 1, bits 11..10 = 11 -- the field that distinguishes it
    // from FCMP (bits 11..10 = 00). FCCMP/FCCMPE (FP conditional compare)
    // read NZCV too, with bits 11..10 = 01, before conditionally writing
    // it. A later integer instruction may overwrite the flags, but the FP
    // conditional op has already consumed them, so dropping the CMP/TST is
    // unsound -- classify both as reads.
    if ((op & 0xFF200C00u) == 0x1E200C00u) {
        return LIV_READ;   // FCSEL
    }
    if ((op & 0xFF200C00u) == 0x1E200400u) {
        return LIV_READ;   // FCCMP / FCCMPE
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
    // and register-zero variants. This is a pure NZCV writer; the
    // NZCV-reading FP conditionals FCSEL (bits 11..10 = 11) and
    // FCCMP/FCCMPE (bits 11..10 = 01) are caught as reads above.
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
                             size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        state->pending_active = false;
        return false;
    }
    uint32_t op = insn_word(insn);
    return advance_one_pending(op, &state->pending_active,
                               &state->pending_window,
                               &state->pending_finding, out);
}

bool armlint_advance_pending_sv(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        state->pending_sv_active = false;
        return false;
    }
    uint32_t op = insn_word(insn);
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

    uint32_t op = insn_word(insn);

    // (1) Close: is this a B.EQ/B.NE (CBZ/CBNZ form), a B.HI/B.LS
    //     (the same form, SUBS producers only -- C is known set, so
    //     HI reduces to NE and LS to EQ), or a B.MI/PL/LT/GE
    //     (sign-bit TBZ/TBNZ form) consuming the pending CMP?
    if (state->cmp_active) {
        bool is_eq, is_ls, is_neg;
        unsigned cond;
        int32_t imm19;
        bool to_cbz = false;
        const char *bcond_mnem = NULL;
        if (decode_b_eq_or_ne(op, &is_eq, &imm19)) {
            to_cbz = is_eq;
            bcond_mnem = is_eq ? "b.eq" : "b.ne";
        } else if (state->cmp_is_subs
                   && decode_b_hi_or_ls(op, &is_ls, &imm19)) {
            to_cbz = is_ls;
            bcond_mnem = is_ls ? "b.ls" : "b.hi";
        }
        if (bcond_mnem != NULL) {
            uint64_t target = insn->address
                + (uint64_t)((int64_t)imm19 * 4);
            char w_or_x = state->cmp_is_64bit ? 'x' : 'w';
            const char *cb_mnem = to_cbz ? "cbz" : "cbnz";

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
        } else if (decode_b_sign_cond(op, &is_neg, &cond, &imm19)) {
            // CMP/TST-zero followed by a sign-only B.cond (MI/PL/LT/GE).
            // The TBZ replaces the CMP at the CMP's address (4 bytes
            // before the B.cond), so its required imm14 is imm19 + 1.
            int64_t tbz_disp = (int64_t)imm19 + 1;
            if (tbz_disp >= -8192 && tbz_disp <= 8191) {
                uint64_t target = insn->address
                    + (uint64_t)((int64_t)imm19 * 4);
                char w_or_x = state->cmp_is_64bit ? 'x' : 'w';
                unsigned bit = state->cmp_is_64bit ? 63u : 31u;
                const char *tb_mnem = is_neg ? "tbnz" : "tbz";
                const char *bcond_mnem;
                switch (cond) {
                case 4:  bcond_mnem = "b.mi"; break;
                case 5:  bcond_mnem = "b.pl"; break;
                case 10: bcond_mnem = "b.ge"; break;
                default: bcond_mnem = "b.lt"; break;  // case 11
                }

                armlint_finding *p = &state->pending_finding;
                p->name = "compare-zero signed-branch foldable into TBZ/TBNZ";
                p->start_offset = state->cmp_offset;
                p->insn_count = 2;
                clear_finding_strings(p);

                snprintf(p->detail, sizeof(p->detail),
                    "-> %s %c%u, #%u, 0x%" PRIx64,
                    tb_mnem, w_or_x, state->cmp_rn, bit, target);

                snprintf(p->lines[0], sizeof(p->lines[0]),
                    "%s", state->cmp_disasm);
                snprintf(p->lines[1], sizeof(p->lines[1]),
                    "%s 0x%" PRIx64, bcond_mnem, target);

                state->pending_active = true;
                state->pending_window = LIVENESS_WINDOW;
            }
        }
        // Strict adjacency: any non-matching instruction expires the CMP.
        state->cmp_active = false;
    }

    // (2) Open: is this a zero-test of Rn (Rn != XZR)?
    unsigned sf, rn;
    bool is_subs;
    if (decode_zero_test(op, &sf, &rn, &is_subs) && rn != 31) {
        state->cmp_active = true;
        state->cmp_is_64bit = (sf != 0);
        state->cmp_is_subs = is_subs;
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

    uint32_t op = insn_word(insn);

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
        bool cmp_is_subs;   // unused: only the shared Z bit matters here
        if (decode_zero_test(op, &cmp_sf, &cmp_rn, &cmp_is_subs)
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

    uint32_t op = insn_word(insn);

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

    uint32_t op = insn_word(insn);

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
                                 unsigned *out_w, unsigned *out_rd,
                                 bool *out_is_shift)
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
        *out_is_shift = false;
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
        *out_is_shift = true;
        return true;
    }

    // Sign-extending loads. (size, opc) -> (S, W):
    //   LDRSB Xt: (00, 10) -> (8,  64)
    //   LDRSB Wt: (00, 11) -> (8,  32)
    //   LDRSH Xt: (01, 10) -> (16, 64)
    //   LDRSH Wt: (01, 11) -> (16, 32)
    //   LDRSW Xt: (10, 10) -> (32, 64)
    if ((op & 0xFEC00000u) == 0x38800000u) { *out_s = 8;  *out_w = 64; *out_rd = rd_field; *out_is_shift = false; return true; }
    if ((op & 0xFEC00000u) == 0x38C00000u) { *out_s = 8;  *out_w = 32; *out_rd = rd_field; *out_is_shift = false; return true; }
    if ((op & 0xFEC00000u) == 0x78800000u) { *out_s = 16; *out_w = 64; *out_rd = rd_field; *out_is_shift = false; return true; }
    if ((op & 0xFEC00000u) == 0x78C00000u) { *out_s = 16; *out_w = 32; *out_rd = rd_field; *out_is_shift = false; return true; }
    if ((op & 0xFEC00000u) == 0xB8800000u) { *out_s = 32; *out_w = 64; *out_rd = rd_field; *out_is_shift = false; return true; }

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

    uint32_t op = insn_word(insn);

    // (1) Close: is this a SXT consumer (sign re-extension), or a
    //     zero-extension consumer that masks the sign-extension?
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
        } else {
            // Zero-extension consumer (UBFM-zext / AND-imm low-mask /
            // MOV W self) that masks the sign-extension. The producer
            // wrote bits [S_p, W_p) = sign(bit S_p - 1); the consumer
            // clears bits >= C_c. When C_c <= S_p the consumer covers
            // (and overwrites with zero) every sign-extended bit:
            //   - within the consumer's destination width, by mask.
            //   - above the destination width (X[63:32]), by W-form
            //     auto-zero when the consumer is W-form.
            // No explicit width-matching constraint is needed.
            unsigned z_c, z_rd, z_rn;
            bool is_uxtm = decode_ubfm_zext(op, &z_c, &z_rd, &z_rn);
            bool is_andm = !is_uxtm
                && decode_and_imm_lowmask(op, &z_c, &z_rd, &z_rn);
            bool is_movs = false;
            if (!is_uxtm && !is_andm) {
                is_movs = decode_mov_w_self(op, &z_c, &z_rd);
                if (is_movs) {
                    z_rn = z_rd;
                }
            }
            if ((is_uxtm || is_andm || is_movs)
                    && z_rd == state->sxt_rd
                    && z_rn == state->sxt_rd
                    && z_c <= state->sxt_signed_from
                    && !state->sxt_is_shift) {
                out->name = "dead sign-extension masked by zero-extension";
                out->start_offset = state->sxt_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                snprintf(out->detail, sizeof(out->detail),
                    "%s is dead -- %s %s clears bits >= %u (S = %u)",
                    state->sxt_producer_disasm,
                    insn->mnemonic, insn->op_str,
                    z_c, state->sxt_signed_from);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->sxt_producer_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);
                produced = true;
            }
        }
        // Strict adjacency: any non-matching instruction expires.
        state->sxt_active = false;
    }

    // (2) Open: is this a sign-extending producer?
    unsigned p_s, p_w, p_rd;
    bool p_is_shift;
    if (decode_sext_producer(op, &p_s, &p_w, &p_rd, &p_is_shift)) {
        state->sxt_active = true;
        state->sxt_rd = p_rd;
        state->sxt_signed_from = p_s;
        state->sxt_upper = p_w;
        state->sxt_is_shift = p_is_shift;
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

    uint32_t op = insn_word(insn);

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

// Detect the logical shifted-register self-op:
//   AND/ORR/EOR/BIC/ORN/EON Rd, Rs, Rs (shift = LSL #0)
// with Rn == Rm. ANDS / BICS (opc=11) are skipped: the flag-set is
// intentional.
//
// Mask fixes bits 28..21 (class + LSL + N) and bits 15..10 (imm6=0).
// Bit 21 (N) distinguishes the two halves of the family:
//   N=0 base 0x0A000000: AND (opc=00), ORR (01), EOR (10), ANDS (11)
//   N=1 base 0x0A200000: BIC (opc=00), ORN (01), EON (10), BICS (11)
static bool decode_logical_self_op(uint32_t op, unsigned *out_sf,
                                   unsigned *out_opc, unsigned *out_n,
                                   unsigned *out_rd, unsigned *out_rn)
{
    uint32_t masked = op & 0x1FE0FC00u;
    unsigned n_bit;
    if (masked == 0x0A000000u) {
        n_bit = 0;
    } else if (masked == 0x0A200000u) {
        n_bit = 1;
    } else {
        return false;
    }
    unsigned opc = (op >> 29) & 0x3u;
    if (opc == 3) {
        return false;  // ANDS / BICS: flag-set is intentional
    }
    unsigned rm = (op >> 16) & 0x1Fu;
    unsigned rn = (op >> 5) & 0x1Fu;
    if (rm != rn) {
        return false;
    }
    unsigned rd = op & 0x1Fu;
    if (rd == 31 || rn == 31) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_opc = opc;
    *out_n = n_bit;
    *out_rd = rd;
    *out_rn = rn;
    return true;
}

// Detect SUB Rd, Rs, Rs (arithmetic shifted-register, S = 0, shift =
// LSL #0). The SUBS (S=1) variant is skipped -- the flag-set form is
// the intentional way to test or zero-with-flags.
//
// Mask fixes bits 30..21 (op=1, S=0, class 01011, LSL, fixed-0) and
// bits 15..10 (imm6=0).
static bool decode_sub_self_op(uint32_t op, unsigned *out_sf,
                               unsigned *out_rd, unsigned *out_rn)
{
    if ((op & 0x7FE0FC00u) != 0x4B000000u) {
        return false;
    }
    unsigned rm = (op >> 16) & 0x1Fu;
    unsigned rn = (op >> 5) & 0x1Fu;
    if (rm != rn) {
        return false;
    }
    unsigned rd = op & 0x1Fu;
    if (rd == 31 || rn == 31) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_rd = rd;
    *out_rn = rn;
    return true;
}

bool check_self_op(armlint_state *state, const cs_insn *insn,
                   size_t offset, armlint_finding *out)
{
    (void)state;

    if (insn->size != 4) {
        return false;
    }

    uint32_t op = insn_word(insn);

    unsigned sf, rd, rn;
    const char *mnem;
    // Result of the self-op: identity (= Rs), zero (= 0), or negative
    // one (all-ones, encoded as MOVN Rd, #0).
    enum { RES_IDENTITY, RES_ZERO, RES_NEG_ONE } kind;

    unsigned opc, n_bit;
    if (decode_logical_self_op(op, &sf, &opc, &n_bit, &rd, &rn)) {
        if (n_bit == 0) {
            switch (opc) {
            case 0: mnem = "and"; kind = RES_IDENTITY; break;
            case 1: mnem = "orr"; kind = RES_IDENTITY; break;
            case 2: mnem = "eor"; kind = RES_ZERO;     break;
            default: return false;  // opc=3 (ANDS) rejected by decoder
            }
        } else {
            switch (opc) {
            case 0: mnem = "bic"; kind = RES_ZERO;     break;
            case 1: mnem = "orn"; kind = RES_NEG_ONE;  break;
            case 2: mnem = "eon"; kind = RES_NEG_ONE;  break;
            default: return false;  // opc=3 (BICS) rejected by decoder
            }
        }
    } else if (decode_sub_self_op(op, &sf, &rd, &rn)) {
        mnem = "sub";
        kind = RES_ZERO;
    } else {
        return false;
    }

    char w_or_x = sf ? 'x' : 'w';

    out->name = "self-op identity";
    out->start_offset = offset;
    out->insn_count = 1;
    clear_finding_strings(out);

    switch (kind) {
    case RES_IDENTITY:
        snprintf(out->detail, sizeof(out->detail),
            "%s %c%u, %c%u, %c%u -> mov %c%u, %c%u",
            mnem, w_or_x, rd, w_or_x, rn, w_or_x, rn,
            w_or_x, rd, w_or_x, rn);
        break;
    case RES_ZERO:
        snprintf(out->detail, sizeof(out->detail),
            "%s %c%u, %c%u, %c%u -> mov %c%u, %czr",
            mnem, w_or_x, rd, w_or_x, rn, w_or_x, rn,
            w_or_x, rd, w_or_x);
        break;
    case RES_NEG_ONE:
        snprintf(out->detail, sizeof(out->detail),
            "%s %c%u, %c%u, %c%u -> mov %c%u, #-1 (movn %c%u, #0)",
            mnem, w_or_x, rd, w_or_x, rn, w_or_x, rn,
            w_or_x, rd, w_or_x, rd);
        break;
    }
    snprintf(out->lines[0], sizeof(out->lines[0]),
        "%s %s", insn->mnemonic, insn->op_str);
    return true;
}

bool check_csel_self(armlint_state *state, const cs_insn *insn,
                     size_t offset, armlint_finding *out)
{
    (void)state;

    if (insn->size != 4) {
        return false;
    }

    uint32_t op = insn_word(insn);

    // CSEL: sf | 0 | 0 | 11010100 | Rm | cond | 00 | Rn | Rd. op2
    // (bits 11..10) = 00 distinguishes CSEL from CSINC (01), CSINV
    // (10), CSNEG (11) -- only CSEL is an identity when Rn == Rm; the
    // others have different "else" branches.
    if ((op & 0x7FE00C00u) != 0x1A800000u) {
        return false;
    }

    unsigned rm = (op >> 16) & 0x1Fu;
    unsigned rn = (op >> 5) & 0x1Fu;
    if (rm != rn) {
        return false;
    }
    unsigned rd = op & 0x1Fu;
    if (rd == 31 || rn == 31) {
        return false;
    }

    unsigned sf = (op >> 31) & 1u;
    char w_or_x = sf ? 'x' : 'w';

    out->name = "CSEL same-operand identity";
    out->start_offset = offset;
    out->insn_count = 1;
    clear_finding_strings(out);

    snprintf(out->detail, sizeof(out->detail),
        "%s %s -> mov %c%u, %c%u (cond irrelevant: both branches = %c%u)",
        insn->mnemonic, insn->op_str,
        w_or_x, rd, w_or_x, rn, w_or_x, rn);
    snprintf(out->lines[0], sizeof(out->lines[0]),
        "%s %s", insn->mnemonic, insn->op_str);
    return true;
}

// Decode AND-immediate with a "high-only" mask: ~((1<<w)-1), i.e.,
// the top (datasize - w) bits are 1 and the low w bits are 0. The
// bitmask-immediate encoding for this shape has immr = imms + 1
// (R = datasize - w, S = datasize - w - 1). Returns the width w of
// the zero region in the low bits.
// Decode UBFIZ Rd, Rn, #lsb, #w -- the zero-extending bitfield-insert
// alias of UBFM with imms < immr. The lsb == 0 case (immr == 0) is
// excluded: that is a plain low-mask zero-extend, matched as the
// isolate's AND form instead. The field always fits (lsb + w <=
// datasize) because imms < immr.
static bool decode_ubfiz(uint32_t op, unsigned *out_sf, unsigned *out_lsb,
                         unsigned *out_w, unsigned *out_rd, unsigned *out_rn)
{
    unsigned sf = (op >> 31) & 1u;
    uint32_t base = sf ? 0xD3400000u : 0x53000000u;   // UBFM, N == sf
    if ((op & 0xFFC00000u) != base) {
        return false;
    }
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;
    if (sf == 0 && (immr > 31u || imms > 31u)) {
        return false;       // W-form fields are in [0, 31]
    }
    if (immr == 0 || imms >= immr) {
        return false;       // immr == 0 -> lsb 0 (AND form); imms >= immr -> UBFX
    }
    unsigned datasize = sf ? 64u : 32u;
    *out_sf = sf;
    *out_lsb = datasize - immr;
    *out_w = imms + 1u;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// Decode an AND-immediate that clears a single contiguous run of w bits
// at position lsb (the "clear the destination field" step). The mask is
// reconstructed to its concrete value and accepted only when the cleared
// bits (~mask) form one unbroken, non-wrapping run; rotated/split masks
// have no single BFI/BFXIL field and are rejected. lsb == 0 is the BFXIL
// clear (clears the low w bits); lsb > 0 generalizes to BFI. ANDS is not
// matched by decode_and_imm, so the flag-setting form is excluded.
static bool decode_and_imm_field_clear(uint32_t op, unsigned *out_lsb,
                                       unsigned *out_w, unsigned *out_rd,
                                       unsigned *out_rn)
{
    unsigned sf, rd, rn;
    uint64_t mask;
    if (!decode_and_imm(op, &sf, &mask, &rd, &rn)) {
        return false;
    }
    unsigned datasize = sf ? 64u : 32u;
    uint64_t dmask = (datasize == 64u) ? ~(uint64_t)0
                                       : (((uint64_t)1 << datasize) - 1u);
    uint64_t cleared = (~mask) & dmask;
    if (cleared == 0) {
        return false;               // clears nothing
    }
    // Find the cleared run [lo, hi] and confirm it is contiguous, the
    // same idiom the AND+LSR -> UBFX check uses for the kept run.
    unsigned lo = 0;
    while (lo < datasize && ((cleared >> lo) & 1u) == 0) {
        lo++;
    }
    unsigned hi = datasize - 1u;
    while (hi > lo && ((cleared >> hi) & 1u) == 0) {
        hi--;
    }
    unsigned runlen = hi - lo + 1u;
    uint64_t runmask = (runlen >= 64u)
        ? ~(uint64_t)0
        : (((uint64_t)1 << runlen) - 1u) << lo;
    if (datasize == 32u) {
        runmask &= 0xFFFFFFFFu;
    }
    if (cleared != runmask) {
        return false;               // split or wrapping run -- no single field
    }
    *out_lsb = lo;
    *out_w = runlen;
    *out_rd = rd;
    *out_rn = rn;
    return true;
}

// Decode ORR shifted-register with shift = LSL #0, N = 0 (no negation
// of Rm). Any Rd / Rn / Rm.
static bool decode_orr_reg_shift0(uint32_t op, unsigned *out_sf,
                                  unsigned *out_rd, unsigned *out_rn,
                                  unsigned *out_rm)
{
    if ((op & 0x7FE0FC00u) != 0x2A000000u) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    return true;
}

bool check_bfxil_synth(armlint_state *state, const cs_insn *insn,
                       size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->bfx_clear_seen = false;
        state->bfx_isolate_seen = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // Categorize the current instruction.
    unsigned width = 0, and_rd = 0, and_rn = 0, lsb = 0;
    unsigned orr_sf = 0, orr_rd = 0, orr_rn = 0, orr_rm = 0;
    unsigned c_lsb, c_w, c_rd, c_rn;       // field-clear AND
    unsigned l_w, l_rd, l_rn;              // low-mask isolate AND
    unsigned u_sf, u_lsb, u_w, u_rd, u_rn; // UBFIZ isolate
    unsigned sf = (op >> 31) & 1u;
    bool is_clear = false, is_isolate = false, is_combine = false;

    // An AND-immediate plays one of two roles, distinguished by whether
    // it writes in place. The clear is "AND Rd, Rd, #~(mask<<lsb)"
    // (in-place, Rd == Rn); a low-mask isolate is "AND Rt, Rs, #mask"
    // into a separate temp (Rd != Rn). The split matters because an
    // in-place low-mask AND -- e.g. one whose cleared field reaches the
    // top of the register -- matches both shapes; Rd == Rn fixes the
    // role, since a sound isolate always needs Rt != Rs anyway. Every
    // low-mask AND is also a field-clear shape (its high bits form a
    // contiguous cleared run), so the clear branch is tried first and
    // the non-in-place ones fall through to the isolate branch.
    if (decode_and_imm_field_clear(op, &c_lsb, &c_w, &c_rd, &c_rn)
            && c_rd == c_rn && c_rd != 31) {
        is_clear = true;
        lsb = c_lsb;
        width = c_w;
        and_rd = c_rd;
        and_rn = c_rn;
    } else if (decode_and_imm_lowmask(op, &l_w, &l_rd, &l_rn)
            && l_rd != l_rn && l_rd != 31 && l_rn != 31) {
        // Low-mask isolate keeps bits [0, w), so lsb == 0 (BFXIL).
        is_isolate = true;
        lsb = 0;
        width = l_w;
        and_rd = l_rd;
        and_rn = l_rn;
    } else if (decode_ubfiz(op, &u_sf, &u_lsb, &u_w, &u_rd, &u_rn)
            && u_rd != 31 && u_rn != 31) {
        // UBFIZ isolate positions the field at lsb > 0 (BFI).
        is_isolate = true;
        sf = u_sf;
        width = u_w;
        lsb = u_lsb;
        and_rd = u_rd;
        and_rn = u_rn;
    } else if (decode_orr_reg_shift0(op, &orr_sf, &orr_rd, &orr_rn,
                                     &orr_rm)) {
        is_combine = true;
    }

    bool produced = false;

    if (is_combine) {
        if (state->bfx_clear_seen && state->bfx_isolate_seen
                && state->bfx_is_64bit == (orr_sf != 0)) {
            unsigned cd = state->bfx_clear_rd;
            unsigned tt = state->bfx_isolate_rt;
            unsigned rs = state->bfx_isolate_rn;
            // ORR Rd, Rd, Rt or ORR Rd, Rt, Rd. Rd = clear.Rd.
            bool combo_ok = orr_rd == cd &&
                ((orr_rn == cd && orr_rm == tt) ||
                 (orr_rn == tt && orr_rm == cd));
            // Aliasing constraints for the rewrite to BFXIL Rd, Rs:
            //   isolate.Rt != clear.Rd  (else the isolate clobbers
            //     the cleared Rd in place of writing a separate temp)
            //   isolate.Rt != isolate.Rn (Rt != Rs; the BFXIL rewrite
            //     leaves Rs unmodified, so flagging when Rs is
            //     modified would silently change semantics)
            //   isolate.Rn != clear.Rd  (Rs == Rd is a degenerate
            //     case where the isolate reads the just-cleared Rd
            //     and yields Rt = 0, so the ORR is a no-op and the
            //     net effect is just the clear -- not BFXIL)
            bool alias_ok = tt != cd && tt != rs && rs != cd;
            if (combo_ok && alias_ok) {
                char w_or_x = state->bfx_is_64bit ? 'x' : 'w';
                unsigned lo = state->bfx_lsb;
                out->start_offset = state->bfx_first_offset;
                out->insn_count = 3;
                clear_finding_strings(out);

                if (lo == 0) {
                    out->name = "BFXIL synthesis via AND-AND-ORR";
                    snprintf(out->detail, sizeof(out->detail),
                        "-> bfxil %c%u, %c%u, #0, #%u",
                        w_or_x, cd, w_or_x, rs, state->bfx_width);
                } else {
                    out->name = "BFI synthesis via AND-UBFIZ-ORR";
                    snprintf(out->detail, sizeof(out->detail),
                        "-> bfi %c%u, %c%u, #%u, #%u",
                        w_or_x, cd, w_or_x, rs, lo, state->bfx_width);
                }
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->bfx_clear_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s", state->bfx_isolate_disasm);
                snprintf(out->lines[2], sizeof(out->lines[2]),
                    "%s %s", insn->mnemonic, insn->op_str);
                produced = true;
            }
        }
        state->bfx_clear_seen = false;
        state->bfx_isolate_seen = false;
    } else if (is_clear) {
        // If isolate already pending with matching field (sf, width,
        // lsb), add clear to it. Otherwise reset and open fresh clear.
        if (state->bfx_isolate_seen
                && state->bfx_is_64bit == (sf != 0)
                && state->bfx_width == width
                && state->bfx_lsb == lsb) {
            state->bfx_clear_seen = true;
            state->bfx_clear_rd = and_rd;
            snprintf(state->bfx_clear_disasm,
                sizeof(state->bfx_clear_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        } else {
            state->bfx_isolate_seen = false;
            state->bfx_clear_seen = true;
            state->bfx_is_64bit = (sf != 0);
            state->bfx_width = width;
            state->bfx_lsb = lsb;
            state->bfx_clear_rd = and_rd;
            state->bfx_first_offset = offset;
            snprintf(state->bfx_clear_disasm,
                sizeof(state->bfx_clear_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
    } else if (is_isolate) {
        if (state->bfx_clear_seen
                && state->bfx_is_64bit == (sf != 0)
                && state->bfx_width == width
                && state->bfx_lsb == lsb) {
            state->bfx_isolate_seen = true;
            state->bfx_isolate_rt = and_rd;
            state->bfx_isolate_rn = and_rn;
            snprintf(state->bfx_isolate_disasm,
                sizeof(state->bfx_isolate_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        } else {
            state->bfx_clear_seen = false;
            state->bfx_isolate_seen = true;
            state->bfx_is_64bit = (sf != 0);
            state->bfx_width = width;
            state->bfx_lsb = lsb;
            state->bfx_isolate_rt = and_rd;
            state->bfx_isolate_rn = and_rn;
            state->bfx_first_offset = offset;
            snprintf(state->bfx_isolate_disasm,
                sizeof(state->bfx_isolate_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
    } else {
        // Unrecognized instruction expires the window.
        state->bfx_clear_seen = false;
        state->bfx_isolate_seen = false;
    }

    return produced;
}

// MUL Rd, Rn, Rm is the canonical alias for MADD Rd, Rn, Rm, ZR.
// MADD encoding: sf | 00 | 11011 | 000 | Rm(5) | 0 | Ra(5) | Rn(5) |
// Rd(5). The MUL alias requires Ra == 11111 (XZR/WZR). Bit 15 must be
// 0 to distinguish MADD from MSUB (the MNEG alias counterpart).
static bool decode_mul(uint32_t op,
                       unsigned *out_sf, unsigned *out_rd,
                       unsigned *out_rn, unsigned *out_rm)
{
    if ((op & 0x7FE0FC00u) != 0x1B007C00u) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    return true;
}

bool check_mul_strength_reduce(armlint_state *state, const cs_insn *insn,
                               size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        return false;
    }
    if (!state->mov_active) {
        return false;
    }

    uint32_t op = insn_word(insn);

    unsigned sf, rd, rn, rm;
    if (!decode_mul(op, &sf, &rd, &rn, &rm)) {
        return false;
    }

    bool is_64bit = (sf != 0);
    if (is_64bit != state->mov_is_64bit) {
        return false;
    }

    // Identify which of (Rn, Rm) came from the MOV chain. MUL is
    // commutative.
    unsigned other;
    if (rm == state->mov_rd) {
        other = rn;
    } else if (rn == state->mov_rd) {
        other = rm;
    } else {
        return false;
    }

    // ZR as Rd discards the result; ZR as the "other" operand makes
    // the MUL evaluate to zero (different idiom, not strength
    // reduction).
    if (rd == 31 || other == 31) {
        return false;
    }

    // The surviving operand must not be the MOV destination itself
    // (MUL Rd, Xc, Xc -- squaring the constant): the shift/add
    // rewrite would still read the constant register, so the MOV
    // chain could never be deleted.
    if (other == state->mov_rd) {
        return false;
    }

    uint64_t c = state->mov_value;
    if (c < 2) {
        // C == 0: MUL is zero (rewrite is MOV Rd, ZR).
        // C == 1: MUL is identity (rewrite is MOV Rd, R<other>).
        return false;
    }

    unsigned datasize = is_64bit ? 64u : 32u;
    unsigned n = 0;
    bool is_pow2 = false;
    bool is_p1 = false;

    if ((c & (c - 1u)) == 0) {
        uint64_t t = c;
        while ((t & 1u) == 0) {
            t >>= 1;
            n++;
        }
        if (n >= 1 && n < datasize) {
            is_pow2 = true;
        }
    } else {
        uint64_t cm1 = c - 1u;
        if ((cm1 & (cm1 - 1u)) == 0) {
            uint64_t t = cm1;
            while ((t & 1u) == 0) {
                t >>= 1;
                n++;
            }
            if (n >= 1 && n < datasize) {
                is_p1 = true;
            }
        }
    }

    if (!is_pow2 && !is_p1) {
        return false;
    }

    char w_or_x = is_64bit ? 'x' : 'w';

    out->name = "MUL by constant foldable to shift/add";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    if (is_pow2) {
        snprintf(out->detail, sizeof(out->detail),
            "-> lsl %c%u, %c%u, #%u",
            w_or_x, rd, w_or_x, other, n);
    } else {
        snprintf(out->detail, sizeof(out->detail),
            "-> add %c%u, %c%u, %c%u, lsl #%u",
            w_or_x, rd, w_or_x, other, w_or_x, other, n);
    }

    // Render MOV chain, leaving one line for the MUL itself.
    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mnem = e->opc == 2 ? "movz"
                       : (e->opc == 0 ? "movn" : "movk");
        unsigned shift = (unsigned)e->shift_div_16 * 16u;
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
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "mul %c%u, %c%u, %c%u",
        w_or_x, rd, w_or_x, rn, w_or_x, rm);

    return true;
}

// MNEG Rd, Rn, Rm is the alias for MSUB Rd, Rn, Rm, ZR.
// MSUB encoding: sf | 00 | 11011 | 000 | Rm(5) | 1 | Ra(5) | Rn(5) |
// Rd(5). Same opcode block as MADD but with bit 15 ("o0") = 1. The
// MNEG alias requires Ra == 11111 (XZR/WZR).
static bool decode_mneg(uint32_t op,
                        unsigned *out_sf, unsigned *out_rd,
                        unsigned *out_rn, unsigned *out_rm)
{
    if ((op & 0x7FE0FC00u) != 0x1B00FC00u) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    return true;
}

bool check_mneg_strength_reduce(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        return false;
    }
    if (!state->mov_active) {
        return false;
    }

    uint32_t op = insn_word(insn);

    unsigned sf, rd, rn, rm;
    if (!decode_mneg(op, &sf, &rd, &rn, &rm)) {
        return false;
    }

    bool is_64bit = (sf != 0);
    if (is_64bit != state->mov_is_64bit) {
        return false;
    }

    unsigned other;
    if (rm == state->mov_rd) {
        other = rn;
    } else if (rn == state->mov_rd) {
        other = rm;
    } else {
        return false;
    }

    if (rd == 31 || other == 31) {
        return false;
    }

    // The surviving operand must not be the MOV destination itself
    // (MNEG Rd, Xc, Xc): the rewrite would still read the constant
    // register, so the MOV chain could never be deleted.
    if (other == state->mov_rd) {
        return false;
    }

    uint64_t c = state->mov_value;
    if (c == 0) {
        // MNEG by 0 = 0; rewrite is MOV Rd, ZR. Different idiom.
        return false;
    }

    unsigned datasize = is_64bit ? 64u : 32u;
    unsigned n = 0;
    bool is_one = (c == 1u);
    bool is_pow2 = false;
    bool is_n_minus_1 = false;

    if (!is_one) {
        if ((c & (c - 1u)) == 0) {
            uint64_t t = c;
            while ((t & 1u) == 0) {
                t >>= 1;
                n++;
            }
            if (n >= 1 && n < datasize) {
                is_pow2 = true;
            }
        } else {
            // C + 1 == 2^N : the 2^N - 1 family. cp1 == 0 only when
            // c == all-ones (e.g. MOVN producing -1); that wraps to 0
            // and is correctly rejected below.
            uint64_t cp1 = c + 1u;
            if (cp1 != 0 && (cp1 & (cp1 - 1u)) == 0) {
                uint64_t t = cp1;
                while ((t & 1u) == 0) {
                    t >>= 1;
                    n++;
                }
                // N >= 2 because the c == 1 (N == 1) case is handled
                // above as the simpler NEG-without-shift.
                if (n >= 2 && n < datasize) {
                    is_n_minus_1 = true;
                }
            }
        }
    }

    if (!is_one && !is_pow2 && !is_n_minus_1) {
        return false;
    }

    char w_or_x = is_64bit ? 'x' : 'w';

    out->name = "MNEG by constant foldable to neg/sub";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    if (is_one) {
        snprintf(out->detail, sizeof(out->detail),
            "-> neg %c%u, %c%u",
            w_or_x, rd, w_or_x, other);
    } else if (is_pow2) {
        snprintf(out->detail, sizeof(out->detail),
            "-> neg %c%u, %c%u, lsl #%u",
            w_or_x, rd, w_or_x, other, n);
    } else {
        snprintf(out->detail, sizeof(out->detail),
            "-> sub %c%u, %c%u, %c%u, lsl #%u",
            w_or_x, rd, w_or_x, other, w_or_x, other, n);
    }

    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mnem = e->opc == 2 ? "movz"
                       : (e->opc == 0 ? "movn" : "movk");
        unsigned shift = (unsigned)e->shift_div_16 * 16u;
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
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "mneg %c%u, %c%u, %c%u",
        w_or_x, rd, w_or_x, rn, w_or_x, rm);

    return true;
}

// UDIV encoding (Data-processing 2-source):
// sf | 0 | 0 | 11010110 | Rm(5) | 000010 | Rn(5) | Rd(5). SDIV uses the
// same opcode block with opcode2 = 000011 at bits 15..10; we
// deliberately only match UDIV here -- see check_udiv_strength_reduce.
static bool decode_udiv(uint32_t op,
                        unsigned *out_sf, unsigned *out_rd,
                        unsigned *out_rn, unsigned *out_rm)
{
    if ((op & 0x7FE0FC00u) != 0x1AC00800u) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    return true;
}

bool check_udiv_strength_reduce(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        return false;
    }
    if (!state->mov_active) {
        return false;
    }

    uint32_t op = insn_word(insn);

    unsigned sf, rd, rn, rm;
    if (!decode_udiv(op, &sf, &rd, &rn, &rm)) {
        return false;
    }

    bool is_64bit = (sf != 0);
    if (is_64bit != state->mov_is_64bit) {
        return false;
    }

    // UDIV is NOT commutative: only the divisor (Rm) coming from the
    // MOV chain enables the LSR fold. Rn from MOV would be a
    // reciprocal-multiply problem, not a shift.
    if (rm != state->mov_rd) {
        return false;
    }

    // ZR as Rd discards the result; ZR as Rn (dividend) makes the
    // result always 0 -- a different idiom, not strength reduction.
    if (rd == 31 || rn == 31) {
        return false;
    }

    // The dividend must not be the MOV destination itself
    // (UDIV Rd, Xc, Xc -- the constant divided by itself): the LSR
    // rewrite would still read the constant register, so the MOV
    // chain could never be deleted.
    if (rn == state->mov_rd) {
        return false;
    }

    uint64_t c = state->mov_value;
    if (c < 2) {
        // C == 0: UDIV by zero produces 0 on AArch64 (no trap), but
        // this is a degenerate idiom, not strength reduction.
        // C == 1: UDIV is identity (rewrite is MOV Rd, Rn).
        return false;
    }

    // Only powers of two map cleanly to LSR. Non-pow2 divisors have
    // no single-instruction shift rewrite.
    if ((c & (c - 1u)) != 0) {
        return false;
    }

    unsigned datasize = is_64bit ? 64u : 32u;
    unsigned n = 0;
    uint64_t t = c;
    while ((t & 1u) == 0) {
        t >>= 1;
        n++;
    }
    if (n < 1 || n >= datasize) {
        return false;
    }

    char w_or_x = is_64bit ? 'x' : 'w';

    out->name = "UDIV by constant foldable to shift";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    snprintf(out->detail, sizeof(out->detail),
        "-> lsr %c%u, %c%u, #%u",
        w_or_x, rd, w_or_x, rn, n);

    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mnem = e->opc == 2 ? "movz"
                       : (e->opc == 0 ? "movn" : "movk");
        unsigned shift = (unsigned)e->shift_div_16 * 16u;
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
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "udiv %c%u, %c%u, %c%u",
        w_or_x, rd, w_or_x, rn, w_or_x, rm);

    return true;
}

// ADD/SUB shifted-register (LSL #0, shift_type = LSL): the form that
// reads its Rm directly. Fixed-bit mask 0x1F200000, value 0x0B000000;
// shift_type at bits 23..22 must be 00 (LSL) -- LSR/ASR forms don't
// fold to an immediate; the bit 21 = 0 in the value rejects the
// extending-register form (which has bit 21 = 1). imm6 at bits
// 15..10 must be 0 (no LSL shift on Rm); a nonzero imm6 would change
// the effective constant value, defeating the fold.
static bool decode_add_sub_shifted_lsl0(uint32_t op,
                                        unsigned *out_sf,
                                        bool *out_is_sub,
                                        bool *out_is_s,
                                        unsigned *out_rd,
                                        unsigned *out_rn,
                                        unsigned *out_rm)
{
    if ((op & 0x1F200000u) != 0x0B000000u) {
        return false;
    }
    unsigned shift_type = (op >> 22) & 0x3u;
    if (shift_type != 0) {
        return false;
    }
    unsigned imm6 = (op >> 10) & 0x3Fu;
    if (imm6 != 0) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_is_sub = ((op >> 30) & 1u) != 0;
    *out_is_s = ((op >> 29) & 1u) != 0;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    return true;
}

bool check_mov_add_sub_imm_fold(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        return false;
    }
    if (!state->mov_active) {
        return false;
    }

    uint32_t op = insn_word(insn);

    unsigned sf, rd, rn, rm;
    bool is_sub, is_s;
    if (!decode_add_sub_shifted_lsl0(op, &sf, &is_sub, &is_s,
                                     &rd, &rn, &rm)) {
        return false;
    }

    bool is_64bit = (sf != 0);
    if (is_64bit != state->mov_is_64bit) {
        return false;
    }

    // Non-S-variant writing ZR is dead code -- skip. S-variant with
    // Rd = ZR is the CMP/CMN alias, allowed.
    if (rd == 31 && !is_s) {
        return false;
    }

    // Identify which operand is from the MOV chain. ADD is commutative
    // (either Rn or Rm). SUB is not: only Rm == mov_rd folds to
    // SUB imm; Rn == mov_rd would require a reverse-subtract which
    // AArch64 does not have.
    unsigned other;
    if (is_sub) {
        if (rm != state->mov_rd) {
            return false;
        }
        other = rn;
    } else {
        if (rm == state->mov_rd) {
            other = rn;
        } else if (rn == state->mov_rd) {
            other = rm;
        } else {
            return false;
        }
    }

    // ZR as the other operand makes the ADD/SUB degenerate (it
    // reduces to a MOV/NEG of the constant); not the typical fold.
    if (other == 31) {
        return false;
    }

    // The surviving operand must not be the MOV destination itself
    // (ADD Rd, Xc, Xc; SUB/CMP of Xc against itself): the immediate
    // rewrite would still read the constant register, so the MOV
    // chain could never be deleted. SUB Rd, Xc, Xc is the self-op
    // identity check's territory.
    if (other == state->mov_rd) {
        return false;
    }

    uint64_t c = state->mov_value;
    if (c == 0) {
        // ADD/SUB by 0 is the MOV-or-no-op case; check_add_sub_zero
        // handles the immediate-form analogue, and the MOV here is
        // separately suspect. Skip.
        return false;
    }

    // ADD/SUB imm form: 12-bit unsigned imm with optional LSL #12.
    // C fits iff C is in [0, 0xFFF] (sh=0) or C is a multiple of
    // 0x1000 and (C >> 12) is in [0, 0xFFF] (sh=1).
    bool fits_no_shift = (c <= 0xFFFu);
    bool fits_with_shift = (c >= 0x1000u)
        && ((c & 0xFFFu) == 0)
        && ((c >> 12) <= 0xFFFu);
    if (!fits_no_shift && !fits_with_shift) {
        return false;
    }

    char w_or_x = is_64bit ? 'x' : 'w';
    const char *mnem;
    if (is_sub) {
        mnem = is_s ? "subs" : "sub";
    } else {
        mnem = is_s ? "adds" : "add";
    }
    const char *alias = NULL;
    if (rd == 31 && is_s) {
        alias = is_sub ? "cmp" : "cmn";
    }

    out->name = "MOV + ADD/SUB foldable to immediate form";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    if (alias != NULL) {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, #0x%" PRIx64,
            alias, w_or_x, other, c);
    } else {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, %c%u, #0x%" PRIx64,
            mnem, w_or_x, rd, w_or_x, other, c);
    }

    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mov_mnem = e->opc == 2 ? "movz"
                          : (e->opc == 0 ? "movn" : "movk");
        unsigned shift = (unsigned)e->shift_div_16 * 16u;
        if (shift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, w_or_x, state->mov_rd, e->imm16, shift);
        }
    }
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s %c%u, %c%u, %c%u",
        mnem, w_or_x, rd, w_or_x, rn, w_or_x, rm);

    return true;
}

// Logical shifted-register (AND/BIC/ORR/ORN/EOR/EON/ANDS/BICS) with
// LSL #0. Fixed-bit mask 0x1F000000, value 0x0A000000; shift_type at
// bits 23..22 must be 00 (LSL); imm6 at bits 15..10 must be 0. opc at
// bits 30..29 selects 00=AND, 01=ORR, 10=EOR, 11=ANDS; N at bit 21
// selects the Rm-inverting family (1: BIC/ORN/EON/BICS). Callers that
// only handle the direct forms filter on *out_n == 0.
static bool decode_logic_shifted_lsl0(uint32_t op,
                                      unsigned *out_sf,
                                      unsigned *out_opc,
                                      unsigned *out_n,
                                      unsigned *out_rd,
                                      unsigned *out_rn,
                                      unsigned *out_rm)
{
    if ((op & 0x1F000000u) != 0x0A000000u) {
        return false;
    }
    unsigned shift_type = (op >> 22) & 0x3u;
    if (shift_type != 0) {
        return false;
    }
    unsigned imm6 = (op >> 10) & 0x3Fu;
    if (imm6 != 0) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_opc = (op >> 29) & 0x3u;
    *out_n = (op >> 21) & 0x1u;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    return true;
}

bool check_mov_logic_imm_fold(armlint_state *state, const cs_insn *insn,
                              size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        return false;
    }
    if (!state->mov_active) {
        return false;
    }

    uint32_t op = insn_word(insn);

    unsigned sf, opc, n_bit, rd, rn, rm;
    if (!decode_logic_shifted_lsl0(op, &sf, &opc, &n_bit, &rd, &rn, &rm)) {
        return false;
    }

    bool is_64bit = (sf != 0);
    if (is_64bit != state->mov_is_64bit) {
        return false;
    }

    // ANDS/BICS (opc=3) with Rd=ZR is TST(-of-the-complement) -- a
    // meaningful flag-setting instruction. Other variants writing ZR
    // are dead and skipped.
    bool inverted = (n_bit != 0);
    bool is_ands = (opc == 3);
    if (rd == 31 && !is_ands) {
        return false;
    }

    // Identify the operand from the MOV chain. The direct forms
    // (AND/ORR/EOR/ANDS) are commutative -- either operand may be the
    // MOV destination. The N = 1 forms (BIC/ORN/EON/BICS) invert Rm
    // only: the constant must sit in Rm for the complemented-immediate
    // rewrite; Rn from the MOV (C op ~Rm) has no immediate form.
    unsigned other;
    if (inverted) {
        if (rm != state->mov_rd) {
            return false;
        }
        other = rn;
    } else if (rm == state->mov_rd) {
        other = rn;
    } else if (rn == state->mov_rd) {
        other = rm;
    } else {
        return false;
    }

    // The surviving operand must not itself be the MOV destination
    // (e.g. AND Rd, Xc, Xc): the suggested immediate form would still
    // read the constant register, so the MOV chain it spans could
    // never be deleted and the rewrite saves nothing. Rn == Rm shapes
    // are check_self_op territory anyway.
    if (other == state->mov_rd) {
        return false;
    }

    // ZR as the non-MOV operand makes the op degenerate:
    //   AND/ANDS Rd, ZR, X<C>  = MOV Rd, ZR (always zero)
    //   ORR Rd, ZR, X<C>       = MOV Rd, X<C>  (the canonical MOV)
    //   EOR Rd, ZR, X<C>       = MOV Rd, X<C>
    //   BIC/BICS Rd, ZR, X<C>  = always zero / constant flags
    //   ORN/EON Rd, ZR, X<C>   = MVN X<C> (materializes ~C)
    // None match the typical bitmask-imm fold pattern.
    if (other == 31) {
        return false;
    }

    // The immediate the rewrite needs: C itself for the direct forms;
    // ~C at the operation width for BIC/ORN/EON/BICS, which compute
    // Rn op NOT(Rm), so the NOT folds into the constant. The NZCV
    // behavior of BICS matches ANDS-immediate (N/Z from the result,
    // C = V = 0 -- A64 logical S-ops have no shifter carry-out).
    unsigned reg_width = is_64bit ? 64u : 32u;
    uint64_t c = state->mov_value;
    uint64_t imm = inverted ? (~c & width_mask(reg_width)) : c;
    if (!is_bitmask_immediate(imm, reg_width)) {
        return false;
    }

    char w_or_x = is_64bit ? 'x' : 'w';
    static const char *const logic_mnems[2][4] = {
        { "and", "orr", "eor", "ands" },  // N = 0: direct forms
        { "bic", "orn", "eon", "bics" },  // N = 1: Rm-inverting forms
    };
    const char *cons_mnem = logic_mnems[inverted ? 1 : 0][opc];
    // The suggestion always uses the direct family -- the only one
    // with an immediate form.
    const char *mnem = logic_mnems[0][opc];
    const char *alias = (is_ands && rd == 31) ? "tst" : NULL;

    out->name = inverted
        ? "MOV + BIC/ORN/EON foldable to bitmask immediate"
        : "MOV + AND/ORR/EOR foldable to bitmask immediate";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    if (alias != NULL) {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, #0x%" PRIx64,
            alias, w_or_x, other, imm);
    } else {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, %c%u, #0x%" PRIx64,
            mnem, w_or_x, rd, w_or_x, other, imm);
    }

    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mov_mnem = e->opc == 2 ? "movz"
                          : (e->opc == 0 ? "movn" : "movk");
        unsigned shift = (unsigned)e->shift_div_16 * 16u;
        if (shift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, w_or_x, state->mov_rd, e->imm16, shift);
        }
    }
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s %c%u, %c%u, %c%u",
        cons_mnem, w_or_x, rd, w_or_x, rn, w_or_x, rm);

    return true;
}

bool check_mul_add_sub_fold(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->mul_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: is this an ADD/SUB consuming the pending MUL?
    if (state->mul_pending) {
        unsigned sf, rd, rn, rm;
        bool is_sub, is_s;
        if (decode_add_sub_shifted_lsl0(op, &sf, &is_sub, &is_s,
                                        &rd, &rn, &rm)
                && !is_s
                && ((sf != 0) == state->mul_pending_is_64bit)) {
            unsigned t = state->mul_pending_rd;
            bool valid = false;
            unsigned xc = 0;
            if (rd == t) {
                if (is_sub) {
                    // Only "sub xd, xc, xt" folds (Rm == t, Rn != t).
                    if (rm == t && rn != t) {
                        valid = true;
                        xc = rn;
                    }
                } else {
                    // ADD is commutative -- Rm == t OR Rn == t (but
                    // not both, which is the xc == t aliasing case).
                    if (rm == t && rn != t) {
                        valid = true;
                        xc = rn;
                    } else if (rn == t && rm != t) {
                        valid = true;
                        xc = rm;
                    }
                }
            }

            if (valid) {
                char w_or_x = state->mul_pending_is_64bit ? 'x' : 'w';

                if (is_sub && xc == 31) {
                    // sub xd, xzr, xt is NEG xd, xt, so the fold is the
                    // MSUB-with-ZR alias MNEG -- render it as such.
                    out->name = "MUL + NEG foldable to MNEG";
                    out->start_offset = state->mul_pending_offset;
                    out->insn_count = 2;
                    clear_finding_strings(out);
                    snprintf(out->detail, sizeof(out->detail),
                        "-> mneg %c%u, %c%u, %c%u",
                        w_or_x, rd, w_or_x, state->mul_pending_rn,
                        w_or_x, state->mul_pending_rm);
                    snprintf(out->lines[0], sizeof(out->lines[0]),
                        "%s", state->mul_pending_disasm);
                    snprintf(out->lines[1], sizeof(out->lines[1]),
                        "neg %c%u, %c%u", w_or_x, rd, w_or_x, rm);
                    produced = true;
                } else {
                    const char *fold_mnem = is_sub ? "msub" : "madd";
                    const char *cons_mnem = is_sub ? "sub" : "add";

                    out->name = "MUL + ADD/SUB foldable to MADD/MSUB";
                    out->start_offset = state->mul_pending_offset;
                    out->insn_count = 2;
                    clear_finding_strings(out);

                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %c%u, %c%u, %c%u, %c%u",
                        fold_mnem,
                        w_or_x, rd,
                        w_or_x, state->mul_pending_rn,
                        w_or_x, state->mul_pending_rm,
                        w_or_x, xc);

                    snprintf(out->lines[0], sizeof(out->lines[0]),
                        "%s", state->mul_pending_disasm);
                    snprintf(out->lines[1], sizeof(out->lines[1]),
                        "%s %c%u, %c%u, %c%u",
                        cons_mnem,
                        w_or_x, rd,
                        w_or_x, rn,
                        w_or_x, rm);

                    produced = true;
                }
            }
        }
        // Strict adjacency: clear regardless of match.
        state->mul_pending = false;
    }

    // (2) Try to open: is this a MUL?
    unsigned m_sf, m_rd, m_rn, m_rm;
    if (decode_mul(op, &m_sf, &m_rd, &m_rn, &m_rm)) {
        if (m_rd != 31) {
            state->mul_pending = true;
            state->mul_pending_is_64bit = (m_sf != 0);
            state->mul_pending_rd = m_rd;
            state->mul_pending_rn = m_rn;
            state->mul_pending_rm = m_rm;
            state->mul_pending_offset = offset;
            char w_or_x = (m_sf != 0) ? 'x' : 'w';
            snprintf(state->mul_pending_disasm,
                sizeof(state->mul_pending_disasm),
                "mul %c%u, %c%u, %c%u",
                w_or_x, m_rd, w_or_x, m_rn, w_or_x, m_rm);
        }
    }

    return produced;
}

// Decode the widening multiply aliases SMULL / UMULL Xd, Wn, Wm -- the
// Ra == XZR forms of SMADDL / UMADDL (Data-processing 3-source). Both
// have sf = 1 (X destination), op54 = 00, class 11011, o0 = 0 (the
// MADDL not MSUBL form), and Ra = 11111. op31 (bits 23..21) selects the
// family: 001 = SMADDL, 101 = UMADDL. The mask 0xFFE0FC00 fixes sf, the
// class, op31, o0, and Ra (bits 14..10 = 11111 -> 0x7C00), leaving Rm,
// Rn, Rd free. Returns is_signed = true for SMULL, false for UMULL.
static bool decode_widening_mul(uint32_t op, bool *out_is_signed,
                                unsigned *out_rd, unsigned *out_rn,
                                unsigned *out_rm)
{
    if ((op & 0xFFE0FC00u) == 0x9B207C00u) {
        *out_is_signed = true;
    } else if ((op & 0xFFE0FC00u) == 0x9BA07C00u) {
        *out_is_signed = false;
    } else {
        return false;
    }
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    return true;
}

bool check_widening_mul_add_sub_fold(armlint_state *state,
                                     const cs_insn *insn,
                                     size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->wmul_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: is this an X-form ADD/SUB consuming the pending
    //     widening MUL? The 32x32->64 product is 64-bit, so a W-form
    //     consumer (sf == 0) would operate on only the low half and is
    //     rejected.
    if (state->wmul_pending) {
        unsigned sf, rd, rn, rm;
        bool is_sub, is_s;
        if (decode_add_sub_shifted_lsl0(op, &sf, &is_sub, &is_s,
                                        &rd, &rn, &rm)
                && !is_s
                && sf == 1u) {
            unsigned t = state->wmul_pending_rd;
            bool valid = false;
            unsigned xc = 0;
            if (rd == t) {
                if (is_sub) {
                    // Only "sub xd, xc, xt" folds (Rm == t, Rn != t):
                    // SMSUBL/UMSUBL compute Xa - Wn*Wm.
                    if (rm == t && rn != t) {
                        valid = true;
                        xc = rn;
                    }
                } else {
                    // ADD is commutative -- Rm == t OR Rn == t (but not
                    // both, which is the xc == t aliasing case).
                    if (rm == t && rn != t) {
                        valid = true;
                        xc = rn;
                    } else if (rn == t && rm != t) {
                        valid = true;
                        xc = rm;
                    }
                }
            }

            if (valid) {
                bool sgn = state->wmul_pending_signed;

                if (is_sub && xc == 31) {
                    // sub xd, xzr, xt is NEG xd, xt, so the fold is the
                    // long MSUB-with-ZR alias SMNEGL / UMNEGL.
                    out->name =
                        "SMULL/UMULL + NEG foldable to SMNEGL/UMNEGL";
                    out->start_offset = state->wmul_pending_offset;
                    out->insn_count = 2;
                    clear_finding_strings(out);
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s x%u, w%u, w%u",
                        sgn ? "smnegl" : "umnegl", rd,
                        state->wmul_pending_rn, state->wmul_pending_rm);
                    snprintf(out->lines[0], sizeof(out->lines[0]),
                        "%s", state->wmul_pending_disasm);
                    snprintf(out->lines[1], sizeof(out->lines[1]),
                        "neg x%u, x%u", rd, rm);
                    produced = true;
                } else {
                    const char *fold_mnem = is_sub
                        ? (sgn ? "smsubl" : "umsubl")
                        : (sgn ? "smaddl" : "umaddl");
                    const char *cons_mnem = is_sub ? "sub" : "add";

                    out->name =
                        "SMULL/UMULL + ADD/SUB foldable to SMADDL/UMADDL";
                    out->start_offset = state->wmul_pending_offset;
                    out->insn_count = 2;
                    clear_finding_strings(out);

                    // Destination and accumulator are X-form; the
                    // multiply operands are W-form.
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s x%u, w%u, w%u, x%u",
                        fold_mnem, rd,
                        state->wmul_pending_rn, state->wmul_pending_rm,
                        xc);

                    snprintf(out->lines[0], sizeof(out->lines[0]),
                        "%s", state->wmul_pending_disasm);
                    snprintf(out->lines[1], sizeof(out->lines[1]),
                        "%s x%u, x%u, x%u", cons_mnem, rd, rn, rm);

                    produced = true;
                }
            }
        }
        // Strict adjacency: clear regardless of match.
        state->wmul_pending = false;
    }

    // (2) Try to open: is this an SMULL / UMULL?
    bool m_signed;
    unsigned m_rd, m_rn, m_rm;
    if (decode_widening_mul(op, &m_signed, &m_rd, &m_rn, &m_rm)) {
        // Rd == 31 discards the product; nothing to fold against.
        if (m_rd != 31) {
            state->wmul_pending = true;
            state->wmul_pending_signed = m_signed;
            state->wmul_pending_rd = m_rd;
            state->wmul_pending_rn = m_rn;
            state->wmul_pending_rm = m_rm;
            state->wmul_pending_offset = offset;
            snprintf(state->wmul_pending_disasm,
                sizeof(state->wmul_pending_disasm),
                "%s x%u, w%u, w%u",
                m_signed ? "smull" : "umull", m_rd, m_rn, m_rm);
        }
    }

    return produced;
}

// Decode NEG Rd, Rs (the SUB Rd, XZR, Rs alias) with shift_type = LSL,
// imm6 = 0, S = 0. NEG (shifted-register, no shift) is the most common
// form emitted by compilers; the shifted form (NEG Rd, Rs, LSL #n) is
// not handled. Mask 0x7FE0FFE0 fixes:
//   bits 30..21 = 1001011000 (SUB, non-S, shifted-register, LSL, bit 21=0)
//   bits 15..10 = 0          (imm6 == 0)
//   bits 9..5   = 11111      (Rn = 31 = XZR)
// sf at bit 31 is left free; Rm (bits 20..16) and Rd (bits 4..0) are
// the NEG's operands.
static bool decode_neg(uint32_t op, unsigned *out_sf, unsigned *out_rd,
                       unsigned *out_rs)
{
    if ((op & 0x7FE0FFE0u) != 0x4B0003E0u) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_rd = op & 0x1Fu;
    *out_rs = (op >> 16) & 0x1Fu;
    return true;
}

bool check_neg_add_sub_fold(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->neg_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: is this an ADD/SUB consuming the pending NEG?
    if (state->neg_pending) {
        unsigned sf, rd, rn, rm;
        bool is_sub, is_s;
        if (decode_add_sub_shifted_lsl0(op, &sf, &is_sub, &is_s,
                                        &rd, &rn, &rm)
                && !is_s
                && ((sf != 0) == state->neg_pending_is_64bit)) {
            unsigned t = state->neg_pending_rd;
            bool valid = false;
            unsigned xc = 0;
            if (rd == t) {
                if (is_sub) {
                    // Only "sub xd, xc, xt" folds (Rm == t, Rn != t):
                    // xd = xc - (-xs) = xc + xs -> add xd, xc, xs.
                    if (rm == t && rn != t) {
                        valid = true;
                        xc = rn;
                    }
                } else {
                    // ADD is commutative -- nt may sit in Rn or Rm
                    // (xor): xd = xc + (-xs) = xc - xs -> sub xd, xc, xs.
                    if (rm == t && rn != t) {
                        valid = true;
                        xc = rn;
                    } else if (rn == t && rm != t) {
                        valid = true;
                        xc = rm;
                    }
                }
            }

            if (valid && xc != t) {
                char w_or_x = state->neg_pending_is_64bit ? 'x' : 'w';
                const char *fold_mnem = is_sub ? "add" : "sub";
                const char *cons_mnem = is_sub ? "sub" : "add";

                out->name = "NEG + ADD/SUB foldable to SUB/ADD";
                out->start_offset = state->neg_pending_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %c%u, %c%u, %c%u",
                    fold_mnem,
                    w_or_x, rd,
                    w_or_x, xc,
                    w_or_x, state->neg_pending_rs);

                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->neg_pending_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %c%u, %c%u, %c%u",
                    cons_mnem,
                    w_or_x, rd,
                    w_or_x, rn,
                    w_or_x, rm);

                produced = true;
            }
        }
        // Strict adjacency: clear regardless of match.
        state->neg_pending = false;
    }

    // (2) Try to open: is this a NEG (SUB Rd, XZR, Rs)?
    unsigned n_sf, n_rd, n_rs;
    if (decode_neg(op, &n_sf, &n_rd, &n_rs)) {
        // Rd = 31 makes the NEG dead (writes to XZR); skip. Rs = 31
        // (NEG Rd, XZR) computes 0 and is degenerate; skip.
        if (n_rd != 31 && n_rs != 31) {
            state->neg_pending = true;
            state->neg_pending_is_64bit = (n_sf != 0);
            state->neg_pending_rd = n_rd;
            state->neg_pending_rs = n_rs;
            state->neg_pending_offset = offset;
            char w_or_x = (n_sf != 0) ? 'x' : 'w';
            snprintf(state->neg_pending_disasm,
                sizeof(state->neg_pending_disasm),
                "neg %c%u, %c%u",
                w_or_x, n_rd, w_or_x, n_rs);
        }
    }

    return produced;
}

// Decode MVN Rd, Rm (the ORN Rd, XZR, Rm alias) with shift_type = LSL,
// imm6 = 0. MVN (no shift) is the common compiler form; the shifted
// form (MVN Rd, Rm, LSL #n) is not handled because the consumer's
// negated-operand form would shift the *complemented* value, not the
// original. Mask 0x7FE0FFE0 fixes bits 30..21 (opc=01 ORR-family,
// logical shifted-register class, LSL, N=1), bits 15..10 (imm6=0) and
// bits 9..5 (Rn=11111=XZR); sf is free, Rm and Rd are the operands.
static bool decode_mvn(uint32_t op, unsigned *out_sf, unsigned *out_rd,
                       unsigned *out_rm)
{
    if ((op & 0x7FE0FFE0u) != 0x2A2003E0u) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_rd = op & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    return true;
}

bool check_mvn_logic_fold(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->mvn_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: is this an AND/ORR/EOR/ANDS consuming the MVN?
    // Direct (N = 0) forms only: the N = 1 forms already invert Rm,
    // so folding the MVN in would need the un-inverted op instead.
    if (state->mvn_pending) {
        unsigned sf, opc, n_bit, rd, rn, rm;
        if (decode_logic_shifted_lsl0(op, &sf, &opc, &n_bit, &rd, &rn, &rm)
                && n_bit == 0
                && ((sf != 0) == state->mvn_pending_is_64bit)) {
            unsigned t = state->mvn_pending_rd;
            bool valid = false;
            unsigned indep = 0;
            // AND/ORR/EOR/ANDS all commute, so the MVN result may sit in
            // Rn or Rm (but not both -- that is a self-op, handled by
            // check_self_op). The other source becomes the new Rn and
            // must not also be the MVN destination.
            if (rd == t) {
                if (rm == t && rn != t) {
                    valid = true;
                    indep = rn;
                } else if (rn == t && rm != t) {
                    valid = true;
                    indep = rm;
                }
            }

            if (valid) {
                char w_or_x = state->mvn_pending_is_64bit ? 'x' : 'w';
                // opc: 0=AND, 1=ORR, 2=EOR, 3=ANDS -> the negated forms.
                static const char *cons_names[4] = {
                    "and", "orr", "eor", "ands"
                };
                static const char *fold_names[4] = {
                    "bic", "orn", "eon", "bics"
                };
                const char *cons_mnem = cons_names[opc];
                const char *fold_mnem = fold_names[opc];

                out->name = "MVN + AND/ORR/EOR foldable to BIC/ORN/EON";
                out->start_offset = state->mvn_pending_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %c%u, %c%u, %c%u",
                    fold_mnem,
                    w_or_x, rd,
                    w_or_x, indep,
                    w_or_x, state->mvn_pending_rs);

                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->mvn_pending_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %c%u, %c%u, %c%u",
                    cons_mnem,
                    w_or_x, rd,
                    w_or_x, rn,
                    w_or_x, rm);

                produced = true;
            }
        }
        // Strict adjacency: clear regardless of match.
        state->mvn_pending = false;
    }

    // (2) Try to open: is this an MVN (no shift)?
    unsigned m_sf, m_rd, m_rs;
    if (decode_mvn(op, &m_sf, &m_rd, &m_rs)) {
        // Rd = 31 writes ZR (dead). Rs = 31 is MVN of XZR = all-ones,
        // a constant materialisation (mov Rd, #-1) -- a different idiom.
        if (m_rd != 31 && m_rs != 31) {
            state->mvn_pending = true;
            state->mvn_pending_is_64bit = (m_sf != 0);
            state->mvn_pending_rd = m_rd;
            state->mvn_pending_rs = m_rs;
            state->mvn_pending_offset = offset;
            char w_or_x = (m_sf != 0) ? 'x' : 'w';
            snprintf(state->mvn_pending_disasm,
                sizeof(state->mvn_pending_disasm),
                "mvn %c%u, %c%u",
                w_or_x, m_rd, w_or_x, m_rs);
        }
    }

    return produced;
}

// ADD/SUB extended-register "option" field names, indexed by the 3-bit
// option (bits 15..13). UXTX/SXTX (011/111) are the LSL forms and are
// not produced here.
static const char *const extend_option_name[8] = {
    "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"
};

// Decode a standalone extend that the extended-register ADD/SUB form can
// absorb: SXTB/SXTH (W or X form) and SXTW (X form), or W-form UXTB/UXTH.
// Returns the ADD/SUB extend option, the producer's destination form
// (W=false, X=true; it must match the consumer), and Rd/Rn (Rn is the
// source, always read as a W register by these extends).
//
// A standalone 32->64 zero-extend (UXTW) is normally a W-register MOV,
// not a literal instruction, so the X-form UBFM zero-extend is not
// matched; only the W-form UXTB/UXTH are taken.
static bool decode_extend_producer(uint32_t op, unsigned *out_option,
                                   bool *out_is_64bit, unsigned *out_rd,
                                   unsigned *out_rn)
{
    unsigned s, w, c, rd, rn;
    if (decode_sbfm_sext(op, &s, &w, &rd, &rn)) {
        // SXTB (s=8), SXTH (s=16), SXTW (s=32).
        *out_option = (s == 8u) ? 4u : (s == 16u ? 5u : 6u);
        *out_is_64bit = (w == 64u);
        *out_rd = rd;
        *out_rn = rn;
        return true;
    }
    if (decode_ubfm_zext(op, &c, &rd, &rn) && (c == 8u || c == 16u)
            && ((op >> 31) & 1u) == 0u) {
        // W-form UXTB (c=8) / UXTH (c=16).
        *out_option = (c == 8u) ? 0u : 1u;
        *out_is_64bit = false;
        *out_rd = rd;
        *out_rn = rn;
        return true;
    }
    return false;
}

bool check_extend_add_sub_fold(armlint_state *state, const cs_insn *insn,
                               size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->ext_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: an ADD/SUB (shifted-register, LSL #0) consuming
    //     the pending extend? The extended-register form extends the
    //     consumer's Rm, so the extend result must be Rm (any consumer)
    //     or Rn (commutative ADD/ADDS only, swapped to Rm). The other
    //     source must not also be the extend's Rd (a self-op otherwise).
    if (state->ext_pending) {
        unsigned sf, rd, rn, rm;
        bool is_sub, is_s;
        // The widths must match, with one relaxation: a W-form
        // zero-extend (UXTB/UXTH, option <= 1) also feeds an X-form
        // consumer soundly -- the W write zeroed bits 63..32, so the
        // X read sees exactly the zero-extended value, which is what
        // the X-form extended-register UXTB/UXTH computes. The W-form
        // sign-extends do NOT get this relaxation: they too zero the
        // high half, where the X-form SXT option would replicate the
        // sign.
        if (decode_add_sub_shifted_lsl0(op, &sf, &is_sub, &is_s,
                                        &rd, &rn, &rm)
                && (((sf != 0) == state->ext_pending_is_64bit)
                    || (sf == 1u && !state->ext_pending_is_64bit
                        && state->ext_pending_option <= 1u))) {
            unsigned t = state->ext_pending_rd;
            bool valid = false;
            unsigned indep = 0;
            // The independent operand must not be register 31: the
            // shifted-register consumer read it as ZR, but Rn = 31 in
            // the extended-register rewrite means SP, so the fold
            // would change the operand.
            if (rd == t && t != 31) {
                if (rm == t && rn != t && rn != 31) {
                    valid = true;
                    indep = rn;
                } else if (!is_sub && rn == t && rm != t && rm != 31) {
                    valid = true;
                    indep = rm;
                }
            }

            if (valid) {
                // Render at the consumer's width: it differs from the
                // producer's in the relaxed W-zext-into-X case.
                char w_or_x = sf ? 'x' : 'w';
                const char *mnem = is_sub ? (is_s ? "subs" : "sub")
                                          : (is_s ? "adds" : "add");
                const char *ext =
                    extend_option_name[state->ext_pending_option];

                out->name =
                    "extend + ADD/SUB foldable to extended-register form";
                out->start_offset = state->ext_pending_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                // The extended operand is always a W register (UXTB
                // through SXTW all source 32 bits or fewer).
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %c%u, %c%u, w%u, %s",
                    mnem, w_or_x, rd, w_or_x, indep,
                    state->ext_pending_rs, ext);

                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->ext_pending_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %c%u, %c%u, %c%u",
                    mnem, w_or_x, rd, w_or_x, rn, w_or_x, rm);

                produced = true;
            }
        }
        // Strict adjacency: clear regardless of match.
        state->ext_pending = false;
    }

    // (2) Try to open: is this a standalone extend?
    unsigned e_option, e_rd, e_rn;
    bool e_is_64;
    if (decode_extend_producer(op, &e_option, &e_is_64, &e_rd, &e_rn)) {
        // Rd = 31 writes ZR (dead); Rn = 31 extends ZR (= 0, degenerate).
        if (e_rd != 31 && e_rn != 31) {
            state->ext_pending = true;
            state->ext_pending_is_64bit = e_is_64;
            state->ext_pending_rd = e_rd;
            state->ext_pending_rs = e_rn;
            state->ext_pending_option = e_option;
            state->ext_pending_offset = offset;
            char pw = e_is_64 ? 'x' : 'w';
            snprintf(state->ext_pending_disasm,
                sizeof(state->ext_pending_disasm),
                "%s %c%u, w%u",
                extend_option_name[e_option], pw, e_rd, e_rn);
        }
    }

    return produced;
}

// Decode unsigned-offset STR (any size: B/H/W/X), integer-register
// form only. Mask 0x3FC00000 covers bits 29..22 (the LDR/STR opcode
// block plus V bit and opc bits). Value 0x39000000 fixes V=0,
// opc=00 (STR). Size at bits 31..30 is left free so all four widths
// match; bit 24 = 1 selects the unsigned-offset addressing form.
static bool decode_str_uimm_any_size(uint32_t op,
                                     unsigned *out_size,
                                     unsigned *out_imm12,
                                     unsigned *out_rn,
                                     unsigned *out_rt)
{
    if ((op & 0x3FC00000u) != 0x39000000u) {
        return false;
    }
    *out_size = (op >> 30) & 0x3u;
    *out_imm12 = (op >> 10) & 0xFFFu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rt = op & 0x1Fu;
    return true;
}

// Render the MOV chain into out->lines[0 .. chain_n-1] and the
// consumer disassembly into out->lines[chain_n]. Shared by the three
// branches of check_mov_zero_to_xzr.
static void mov_zero_finding_render_lines(const armlint_state *state,
                                          armlint_finding *out,
                                          const char *consumer_line)
{
    char mov_w_or_x = state->mov_is_64bit ? 'x' : 'w';
    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mov_mnem = e->opc == 2 ? "movz"
                          : (e->opc == 0 ? "movn" : "movk");
        unsigned shift = (unsigned)e->shift_div_16 * 16u;
        if (shift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, mov_w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, mov_w_or_x, state->mov_rd, e->imm16, shift);
        }
    }
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s", consumer_line);
}

// Format a register name as "<wx>NN" or "<wx>zr" (when reg == 31).
static void format_reg(char *buf, size_t bufsz, char w_or_x, unsigned reg)
{
    if (reg == 31) {
        snprintf(buf, bufsz, "%czr", w_or_x);
    } else {
        snprintf(buf, bufsz, "%c%u", w_or_x, reg);
    }
}

bool check_mov_zero_to_xzr(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        return false;
    }
    if (!state->mov_active) {
        return false;
    }
    if (state->mov_value != 0) {
        return false;
    }

    uint32_t op = insn_word(insn);

    // (a) STR (any size, unsigned-offset) with Rt == mov_rd.
    {
        unsigned size, imm12, rn, rt;
        if (decode_str_uimm_any_size(op, &size, &imm12, &rn, &rt)
                && rt == state->mov_rd) {
            const char *str_mnem;
            char rt_wx;
            unsigned scale_shift;
            switch (size) {
                case 0: str_mnem = "strb"; rt_wx = 'w'; scale_shift = 0; break;
                case 1: str_mnem = "strh"; rt_wx = 'w'; scale_shift = 1; break;
                case 2: str_mnem = "str";  rt_wx = 'w'; scale_shift = 2; break;
                case 3: str_mnem = "str";  rt_wx = 'x'; scale_shift = 3; break;
                default: return false;
            }
            unsigned bytes = imm12 << scale_shift;
            char base_buf[8];
            if (rn == 31) {
                snprintf(base_buf, sizeof(base_buf), "sp");
            } else {
                snprintf(base_buf, sizeof(base_buf), "x%u", rn);
            }

            out->name = "MOV #0 + use foldable to ZR";
            out->start_offset = state->mov_start_offset;
            out->insn_count = state->mov_insn_count + 1;
            clear_finding_strings(out);

            char consumer_line[ARMLINT_FINDING_LINE_LEN];
            if (bytes == 0) {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %czr, [%s]", str_mnem, rt_wx, base_buf);
                snprintf(consumer_line, sizeof(consumer_line),
                    "%s %c%u, [%s]", str_mnem, rt_wx, rt, base_buf);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %czr, [%s, #0x%x]",
                    str_mnem, rt_wx, base_buf, bytes);
                snprintf(consumer_line, sizeof(consumer_line),
                    "%s %c%u, [%s, #0x%x]",
                    str_mnem, rt_wx, rt, base_buf, bytes);
            }
            mov_zero_finding_render_lines(state, out, consumer_line);
            return true;
        }
    }

    // (b) ADD/SUB shifted-register-LSL0 with mov_rd as Rn or Rm.
    {
        unsigned sf, rd, rn, rm;
        bool is_sub, is_s;
        if (decode_add_sub_shifted_lsl0(op, &sf, &is_sub, &is_s,
                                        &rd, &rn, &rm)) {
            if (rn == state->mov_rd || rm == state->mov_rd) {
                char wx = (sf != 0) ? 'x' : 'w';
                const char *mnem;
                if (is_sub) {
                    mnem = is_s ? "subs" : "sub";
                } else {
                    mnem = is_s ? "adds" : "add";
                }
                const char *alias = NULL;
                if (rd == 31 && is_s) {
                    alias = is_sub ? "cmp" : "cmn";
                }
                unsigned new_rn = (rn == state->mov_rd) ? 31u : rn;
                unsigned new_rm = (rm == state->mov_rd) ? 31u : rm;

                char rd_buf[8], orig_rn_buf[8], orig_rm_buf[8];
                char new_rn_buf[8], new_rm_buf[8];
                format_reg(rd_buf, sizeof(rd_buf), wx, rd);
                format_reg(orig_rn_buf, sizeof(orig_rn_buf), wx, rn);
                format_reg(orig_rm_buf, sizeof(orig_rm_buf), wx, rm);
                format_reg(new_rn_buf, sizeof(new_rn_buf), wx, new_rn);
                format_reg(new_rm_buf, sizeof(new_rm_buf), wx, new_rm);

                out->name = "MOV #0 + use foldable to ZR";
                out->start_offset = state->mov_start_offset;
                out->insn_count = state->mov_insn_count + 1;
                clear_finding_strings(out);

                char consumer_line[ARMLINT_FINDING_LINE_LEN];
                if (alias != NULL) {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %s, %s", alias, new_rn_buf, new_rm_buf);
                    snprintf(consumer_line, sizeof(consumer_line),
                        "%s %s, %s", alias, orig_rn_buf, orig_rm_buf);
                } else {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %s, %s, %s",
                        mnem, rd_buf, new_rn_buf, new_rm_buf);
                    snprintf(consumer_line, sizeof(consumer_line),
                        "%s %s, %s, %s",
                        mnem, rd_buf, orig_rn_buf, orig_rm_buf);
                }
                mov_zero_finding_render_lines(state, out, consumer_line);
                return true;
            }
        }
    }

    // (c) AND/ORR/EOR/ANDS shifted-register-LSL0 with mov_rd as Rn or
    // Rm. Direct (N = 0) forms only: substituting ZR into the N = 1
    // forms would be valid too but reduces to identities/MVN, a
    // different rewrite shape.
    {
        unsigned sf, opc_l, n_bit, rd, rn, rm;
        if (decode_logic_shifted_lsl0(op, &sf, &opc_l, &n_bit, &rd, &rn, &rm)
                && n_bit == 0) {
            if (rn == state->mov_rd || rm == state->mov_rd) {
                char wx = (sf != 0) ? 'x' : 'w';
                const char *mnem;
                switch (opc_l) {
                    case 0: mnem = "and"; break;
                    case 1: mnem = "orr"; break;
                    case 2: mnem = "eor"; break;
                    case 3: mnem = "ands"; break;
                    default: return false;
                }
                const char *alias = NULL;
                if (opc_l == 3 && rd == 31) {
                    alias = "tst";
                }
                unsigned new_rn = (rn == state->mov_rd) ? 31u : rn;
                unsigned new_rm = (rm == state->mov_rd) ? 31u : rm;

                char rd_buf[8], orig_rn_buf[8], orig_rm_buf[8];
                char new_rn_buf[8], new_rm_buf[8];
                format_reg(rd_buf, sizeof(rd_buf), wx, rd);
                format_reg(orig_rn_buf, sizeof(orig_rn_buf), wx, rn);
                format_reg(orig_rm_buf, sizeof(orig_rm_buf), wx, rm);
                format_reg(new_rn_buf, sizeof(new_rn_buf), wx, new_rn);
                format_reg(new_rm_buf, sizeof(new_rm_buf), wx, new_rm);

                out->name = "MOV #0 + use foldable to ZR";
                out->start_offset = state->mov_start_offset;
                out->insn_count = state->mov_insn_count + 1;
                clear_finding_strings(out);

                char consumer_line[ARMLINT_FINDING_LINE_LEN];
                if (alias != NULL) {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %s, %s", alias, new_rn_buf, new_rm_buf);
                    snprintf(consumer_line, sizeof(consumer_line),
                        "%s %s, %s", alias, orig_rn_buf, orig_rm_buf);
                } else {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %s, %s, %s",
                        mnem, rd_buf, new_rn_buf, new_rm_buf);
                    snprintf(consumer_line, sizeof(consumer_line),
                        "%s %s, %s, %s",
                        mnem, rd_buf, orig_rn_buf, orig_rm_buf);
                }
                mov_zero_finding_render_lines(state, out, consumer_line);
                return true;
            }
        }
    }

    return false;
}

// Decode the unsigned-offset LDR/STR (32-bit or 64-bit, general
// register, non-atomic, non-SIMD). Encoding mask 0xBF800000, value
// 0xB9000000 leaves bit 30 (size[0]: 0=W, 1=X) and bit 22 (opc[0]:
// 0=STR, 1=LDR) free along with imm12, Rn, Rt. Sign-extending loads
// (opc[1]=1) are rejected by the mask (bit 23 = 0). Byte/halfword
// loads (size top bit = 0) are also rejected (bit 31 = 1).
static bool decode_ldr_str_uimm(uint32_t op, bool *out_is_load,
                                bool *out_is_64bit, unsigned *out_imm12,
                                unsigned *out_rn, unsigned *out_rt)
{
    if ((op & 0xBF800000u) != 0xB9000000u) {
        return false;
    }
    *out_is_64bit = ((op >> 30) & 1u) == 1u;
    *out_is_load  = ((op >> 22) & 1u) == 1u;
    *out_imm12 = (op >> 10) & 0xFFFu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rt = op & 0x1Fu;
    return true;
}

// Decode the unsigned-offset LDRSW (X-form, 32-bit load sign-extended
// to 64-bit). Encoding: size=10 (word), V=0, opc=10 (sign-extend to
// X). Mask 0xFFC00000, value 0xB9800000 fully constrains the family;
// imm12 is scaled by 4 like LDR W. The destination is always Xt and
// the operation is always load, so no direction or size fields are
// returned.
static bool decode_ldrsw_uimm(uint32_t op, unsigned *out_imm12,
                              unsigned *out_rn, unsigned *out_rt)
{
    if ((op & 0xFFC00000u) != 0xB9800000u) {
        return false;
    }
    *out_imm12 = (op >> 10) & 0xFFFu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rt = op & 0x1Fu;
    return true;
}

// Decode an unsigned-offset SIMD&FP LDR/STR of any size. V=1
// unsigned-offset form: size(2) 111 1 01 opc(2) imm12 Rn Rt; the
// transfer size is size + 4*opc[1] (B/H/S/D for opc[1]=0, Q for
// size=00 with opc[1]=1; other opc[1]=1 sizes are unallocated) and
// opc[0] selects load. Returns lg2size in 0..4 (B/H/S/D/Q).
static bool decode_fp_ldr_str_uimm(uint32_t op, bool *out_is_load,
                                   unsigned *out_lg2size,
                                   unsigned *out_imm12, unsigned *out_rn,
                                   unsigned *out_rt)
{
    if ((op & 0x3F000000u) != 0x3D000000u) {
        return false;
    }
    unsigned size = (op >> 30) & 0x3u;
    unsigned opc = (op >> 22) & 0x3u;
    unsigned lg2 = size + ((opc & 0x2u) << 1);
    if (lg2 > 4u) {
        return false;   // opc[1] with size != 00 is unallocated
    }
    *out_is_load = (opc & 1u) != 0;
    *out_lg2size = lg2;
    *out_imm12 = (op >> 10) & 0xFFFu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rt = op & 0x1Fu;
    return true;
}

// Register-class letter for a load/store data register: SIMD&FP sizes
// render their own class letter (b/h/s/d/q by log2 transfer size);
// integer sizes render w (B/H/W) or x.
static char ls_rt_letter(bool is_fp, unsigned size)
{
    static const char fp_letter[5] = { 'b', 'h', 's', 'd', 'q' };
    if (is_fp) {
        return fp_letter[size];
    }
    return size == 3u ? 'x' : 'w';
}

// Load/store mnemonic for a single-register access: the integer
// sub-word sizes carry a suffix (ldrb/ldrh, strb/strh); SIMD&FP
// accesses use the plain mnemonic with the class carried by the
// register operand.
static const char *ls_mnemonic(bool is_fp, bool is_load, unsigned size)
{
    static const char *const int_load[4]  = {
        "ldrb", "ldrh", "ldr", "ldr"
    };
    static const char *const int_store[4] = {
        "strb", "strh", "str", "str"
    };
    if (is_fp) {
        return is_load ? "ldr" : "str";
    }
    return is_load ? int_load[size] : int_store[size];
}

// Format a load/store data register. Register 31 is ZR only in the
// integer file; b31/h31/s31/d31/q31 are ordinary SIMD&FP registers.
static void format_ls_rt(char *buf, size_t bufsz, bool is_fp,
                         unsigned size, unsigned rt)
{
    char c = ls_rt_letter(is_fp, size);
    if (!is_fp && rt == 31) {
        snprintf(buf, bufsz, "%czr", c);
    } else {
        snprintf(buf, bufsz, "%c%u", c, rt);
    }
}

bool check_ldp_stp_coalesce(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->lsp_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool is_load = false, is_64bit = false, is_sext = false;
    bool is_fp = false;
    unsigned lg2size = 0;
    unsigned imm12, rn, rt;

    if (decode_ldrsw_uimm(op, &imm12, &rn, &rt)) {
        // LDRSW: always load, always Xt, transfer = 4 bytes.
        is_load = true;
        is_64bit = true;
        is_sext = true;
    } else if (decode_ldr_str_uimm(op, &is_load, &is_64bit, &imm12,
                                   &rn, &rt)) {
        // Integer W/X form.
    } else if (decode_fp_ldr_str_uimm(op, &is_load, &lg2size, &imm12,
                                      &rn, &rt)
               && lg2size >= 2u) {
        // SIMD&FP S/D/Q form. The B and H sizes have no LDP/STP
        // encoding, so they fall to the else and expire the window
        // like any other non-pairable instruction.
        is_fp = true;
    } else {
        // Non-pairable instruction expires the window (strict
        // adjacency).
        state->lsp_active = false;
        return false;
    }

    bool produced = false;

    // Adjacent in either direction: forward (pending at lower offset,
    // current at higher) or reverse (pending at higher offset, current
    // at lower). In the reverse case the LDP's Rt order is swapped so
    // the register at the lower address still appears first.
    bool forward = state->lsp_active
        && imm12 == state->lsp_imm12 + 1;
    bool reverse = state->lsp_active
        && state->lsp_imm12 == imm12 + 1;

    // Try to close: does this instruction partner the pending one?
    //   - same kind (sext/zext, integer/FP) -- LDR cannot pair with
    //     LDRSW, nor an integer access with a SIMD&FP one
    //   - same direction (load/load or store/store)
    //   - same size (W/W, X/X, or equal S/D/Q)
    //   - same base Rn
    //   - consecutive in scaled units (forward or reverse)
    //   - distinct destination registers (LDP/STP requires Rt1 != Rt2)
    //   - pending's Rt != Rn for integer loads (the FIRST load in
    //     source order would clobber the base before the second's
    //     address is computed in the original sequence). The aliasing
    //     concern is about source order, not offset order, so the same
    //     constraint applies to both forward and reverse. It doesn't
    //     apply to stores, nor to SIMD&FP loads: an FP Rt can never
    //     alias the integer base.
    //   - the LOWER of the two imm12s fits LDP/STP imm7 (signed 7-bit,
    //     scaled), i.e., the lower imm12 must be <= 63 (unsigned).
    unsigned low_imm12 = forward ? state->lsp_imm12 : imm12;
    if ((forward || reverse)
            && state->lsp_is_sext == is_sext
            && state->lsp_is_fp == is_fp
            && (!is_fp || state->lsp_lg2size == lg2size)
            && state->lsp_is_load == is_load
            && (is_fp || state->lsp_is_64bit == is_64bit)
            && state->lsp_rn == rn
            && rt != state->lsp_rt
            && low_imm12 <= 63u
            && (!is_load || is_fp || state->lsp_rt != rn)) {
        // LDPSW always loads Xt with 4-byte transfer; SIMD&FP pairs
        // take their class letter and size; otherwise the register
        // width follows is_64bit and the transfer size matches.
        char w_or_x;
        unsigned xfer;
        if (is_fp) {
            w_or_x = ls_rt_letter(true, lg2size);
            xfer = 1u << lg2size;
        } else if (is_sext) {
            w_or_x = 'x';
            xfer = 4u;
        } else {
            w_or_x = is_64bit ? 'x' : 'w';
            xfer = is_64bit ? 8u : 4u;
        }
        const char *pair_mnem;
        if (is_sext) {
            pair_mnem = "ldpsw";
        } else {
            pair_mnem = is_load ? "ldp" : "stp";
        }
        // LDP/STP encodes the register at the lower address first.
        unsigned first_rt  = forward ? state->lsp_rt : rt;
        unsigned second_rt = forward ? rt : state->lsp_rt;
        unsigned byte_off = low_imm12 * xfer;

        if (is_sext) {
            out->name = reverse
                ? "adjacent LDRSWs foldable into LDPSW (reverse order)"
                : "adjacent LDRSWs foldable into LDPSW";
        } else if (is_load) {
            out->name = reverse
                ? "adjacent LDRs foldable into LDP (reverse order)"
                : "adjacent LDRs foldable into LDP";
        } else {
            out->name = reverse
                ? "adjacent STRs foldable into STP (reverse order)"
                : "adjacent STRs foldable into STP";
        }
        out->start_offset = state->lsp_offset;
        out->insn_count = 2;
        clear_finding_strings(out);

        char rn_buf[8];
        if (rn == 31) {
            snprintf(rn_buf, sizeof(rn_buf), "sp");
        } else {
            snprintf(rn_buf, sizeof(rn_buf), "x%u", rn);
        }
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, %c%u, [%s, #%u]",
            pair_mnem, w_or_x, first_rt, w_or_x, second_rt,
            rn_buf, byte_off);
        snprintf(out->lines[0], sizeof(out->lines[0]),
            "%s", state->lsp_disasm);
        snprintf(out->lines[1], sizeof(out->lines[1]),
            "%s %s", insn->mnemonic, insn->op_str);
        produced = true;

        // Reset to avoid overlapping pairs (4 consecutive loads
        // become 2 non-overlapping pairs, not 3 overlapping ones).
        state->lsp_active = false;
    } else {
        // Open new state with the current instruction.
        state->lsp_active = true;
        state->lsp_is_load = is_load;
        state->lsp_is_64bit = is_64bit;
        state->lsp_is_sext = is_sext;
        state->lsp_is_fp = is_fp;
        state->lsp_lg2size = lg2size;
        state->lsp_rt = rt;
        state->lsp_rn = rn;
        state->lsp_imm12 = imm12;
        state->lsp_offset = offset;
        snprintf(state->lsp_disasm, sizeof(state->lsp_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return produced;
}

// Decode X-form ADD (shifted-register, non-S-variant) with any LSL
// amount in [0, 63]. ADD here means "op = 0, S = 0"; SUB and ADDS/SUBS
// are rejected. sf must be 1 (X-form): the consumer LDR's base
// register is always 64-bit. Mask 0xFF200000 fixes sf=1, op=0, S=0,
// the ADD/SUB opcode bits 28..24, and bit 21 (shifted-register form).
// Shift type (bits 23..22) is checked separately for LSL only.
static bool decode_add_x_shifted_lsl(uint32_t op,
                                     unsigned *out_rd,
                                     unsigned *out_rn,
                                     unsigned *out_rm,
                                     unsigned *out_shift)
{
    if ((op & 0xFF200000u) != 0x8B000000u) {
        return false;
    }
    unsigned shift_type = (op >> 22) & 0x3u;
    if (shift_type != 0) {
        return false;
    }
    *out_shift = (op >> 10) & 0x3Fu;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    return true;
}

// Decode unsigned-offset LDR (any size: B/H/W/X), integer-register
// form only. Parallel to decode_str_uimm_any_size but for opc=01
// (LDR) rather than 00 (STR).
static bool decode_ldr_uimm_any_size(uint32_t op,
                                     unsigned *out_size,
                                     unsigned *out_imm12,
                                     unsigned *out_rn,
                                     unsigned *out_rt)
{
    if ((op & 0x3FC00000u) != 0x39400000u) {
        return false;
    }
    *out_size = (op >> 30) & 0x3u;
    *out_imm12 = (op >> 10) & 0xFFFu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rt = op & 0x1Fu;
    return true;
}

// Decode the W-form sign-extending unsigned-offset loads
// (LDRSB/LDRSH Wt: V=0, opc=11, size 00/01; the size 10/11 slots of
// opc=11 are unallocated). The X-form family (opc=10) is deliberately
// not matched where this is used: those already sign-extend through
// bit 63, so a following SXT* is the redundant-sext check's no-op,
// not a fold.
static bool decode_ldrs_w_uimm(uint32_t op,
                               unsigned *out_size,
                               unsigned *out_imm12,
                               unsigned *out_rn,
                               unsigned *out_rt)
{
    if ((op & 0x3FC00000u) != 0x39C00000u) {
        return false;
    }
    unsigned size = (op >> 30) & 0x3u;
    if (size > 1u) {
        return false;
    }
    *out_size = size;
    *out_imm12 = (op >> 10) & 0xFFFu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rt = op & 0x1Fu;
    return true;
}

// Map an integer-load (size, opc) pair to its mnemonic and
// destination-register width, accepting both the zero-extending family
// (opc=01: LDRB/LDRH/LDR W/LDR X) and the sign-extending one (opc=10
// -> Xt for B/H/W; opc=11 -> Wt for B/H). Rejects stores (opc=00),
// PRFM (size=11, opc=10, whose Rt field is a prefetch operation, not a
// destination), and the unallocated size>=10, opc=11 slots. The access
// size in bytes is 1 << size for every accepted pair, and every
// accepted load overwrites the full X register named by Rt (a W-form
// write zeros bits 63..32) -- the property the Rt == base folds rely
// on.
static bool classify_int_load(unsigned size, unsigned opc,
                              const char **out_mnem, char *out_rt_wx)
{
    static const char *const zext_mnem[4] = {
        "ldrb", "ldrh", "ldr", "ldr"
    };
    static const char *const sext_mnem[3] = {
        "ldrsb", "ldrsh", "ldrsw"
    };
    switch (opc) {
    case 1:
        *out_mnem = zext_mnem[size];
        *out_rt_wx = (size == 3u) ? 'x' : 'w';
        return true;
    case 2:
        if (size >= 3u) {
            return false;       // size=11 is PRFM
        }
        *out_mnem = sext_mnem[size];
        *out_rt_wx = 'x';
        return true;
    case 3:
        if (size >= 2u) {
            return false;       // only LDRSB/LDRSH have a Wt form
        }
        *out_mnem = sext_mnem[size];
        *out_rt_wx = 'w';
        return true;
    default:
        return false;           // opc=00: store
    }
}

// Decode an unsigned-offset integer load of any size and extension
// family (see classify_int_load). Mask 0x3F000000 / value 0x39000000
// fixes bits 29..24 (the load/store register class, V=0,
// unsigned-offset form), leaving size and opc free; classification
// filters out the non-load members.
static bool decode_int_load_uimm(uint32_t op, unsigned *out_size,
                                 const char **out_mnem, char *out_rt_wx,
                                 unsigned *out_imm12, unsigned *out_rn,
                                 unsigned *out_rt)
{
    if ((op & 0x3F000000u) != 0x39000000u) {
        return false;
    }
    unsigned size = (op >> 30) & 0x3u;
    unsigned opc = (op >> 22) & 0x3u;
    if (!classify_int_load(size, opc, out_mnem, out_rt_wx)) {
        return false;
    }
    *out_size = size;
    *out_imm12 = (op >> 10) & 0xFFFu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rt = op & 0x1Fu;
    return true;
}

// Decode X-form ADD (immediate), non-S-variant. ADD-imm uses
// sf 0 0 100010 sh imm12 Rn Rd; sf=1, op=0, S=0 -> base 0x91000000,
// mask 0xFF800000 (bits 31..23). sh (bit 22) is a free field: when
// 1, the imm12 is logically left-shifted by 12. The decoder returns
// the *byte* immediate (sh-expanded), so callers compare directly
// against an LDR's byte offset.
static bool decode_add_imm_x(uint32_t op,
                             unsigned *out_rd,
                             unsigned *out_rn,
                             uint32_t *out_imm)
{
    if ((op & 0xFF800000u) != 0x91000000u) {
        return false;
    }
    unsigned sh = (op >> 22) & 1u;
    unsigned imm12 = (op >> 10) & 0xFFFu;
    *out_imm = sh ? ((uint32_t)imm12 << 12) : (uint32_t)imm12;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// Decode X-form SUB (immediate), non-S-variant. Identical field layout
// to decode_add_imm_x but with op (bit 30) = 1: base 0xD1000000, mask
// 0xFF800000 (sf=1, op=1, S=0, 100010). Returns the sh-expanded byte
// immediate. Used only by the pre-/post-index folds, where a SUB
// self-update maps to a *negative* writeback immediate -- the index
// slot is a signed 9-bit field (-256..255), so a SUB by k folds to a
// writeback of -k. (The unsigned-offset fold in check_add_ldr_imm_offset
// must NOT use this: that addressing form has no negative encoding.)
static bool decode_sub_imm_x(uint32_t op,
                             unsigned *out_rd,
                             unsigned *out_rn,
                             uint32_t *out_imm)
{
    if ((op & 0xFF800000u) != 0xD1000000u) {
        return false;
    }
    unsigned sh = (op >> 22) & 1u;
    unsigned imm12 = (op >> 10) & 0xFFFu;
    *out_imm = sh ? ((uint32_t)imm12 << 12) : (uint32_t)imm12;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

bool check_add_ldr_register_offset(armlint_state *state,
                                   const cs_insn *insn,
                                   size_t offset,
                                   armlint_finding *out)
{
    if (insn->size != 4) {
        state->add_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: is this an integer load (zero- or
    //     sign-extending; see classify_int_load) consuming the pending
    //     ADD? A sign-extending consumer folds identically: it too
    //     overwrites the full X register named by Rt, and the
    //     register-offset LDRS* forms exist for every accepted pair.
    if (state->add_pending) {
        unsigned size, imm12, ldr_rn, ldr_rt;
        const char *ldr_mnem;
        char rt_wx;
        if (decode_int_load_uimm(op, &size, &ldr_mnem, &rt_wx,
                                 &imm12, &ldr_rn, &ldr_rt)
                && imm12 == 0
                && ldr_rn == state->add_pending_rd
                && ldr_rt == state->add_pending_rd) {
            // The load's register-offset form accepts only two shift
            // amounts: 0 or log2(access_size). size encodes log2
            // directly: 0=B, 1=H, 2=W, 3=X.
            unsigned s = state->add_pending_shift;
            if (s == 0 || s == size) {
                out->name = "ADD + LDR foldable to register-offset LDR";
                out->start_offset = state->add_pending_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                if (s == 0) {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %c%u, [x%u, x%u]",
                        ldr_mnem, rt_wx, ldr_rt,
                        state->add_pending_rn, state->add_pending_rm);
                } else {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %c%u, [x%u, x%u, lsl #%u]",
                        ldr_mnem, rt_wx, ldr_rt,
                        state->add_pending_rn, state->add_pending_rm,
                        s);
                }
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->add_pending_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %c%u, [x%u]",
                    ldr_mnem, rt_wx, ldr_rt, ldr_rn);
                produced = true;
            }
        }
        // Strict adjacency: clear regardless of match.
        state->add_pending = false;
    }

    // (2) Try to open: is this an X-form ADD shifted-LSL?
    unsigned a_rd, a_rn, a_rm, a_shift;
    if (decode_add_x_shifted_lsl(op, &a_rd, &a_rn, &a_rm, &a_shift)) {
        // Only open if the shift could match some LDR access scale (0,
        // 1, 2, or 3). All-ZR operands give a degenerate ADD; the
        // fold is uninteresting and the Rn=31 case would also change
        // semantics (Rn=31 in LDR means SP, not XZR). Rd=31 makes the
        // ADD dead code -- skip.
        if (a_rd != 31 && a_rn != 31 && a_rm != 31 && a_shift <= 3) {
            state->add_pending = true;
            state->add_pending_rd = a_rd;
            state->add_pending_rn = a_rn;
            state->add_pending_rm = a_rm;
            state->add_pending_shift = a_shift;
            state->add_pending_offset = offset;
            if (a_shift == 0) {
                snprintf(state->add_pending_disasm,
                    sizeof(state->add_pending_disasm),
                    "add x%u, x%u, x%u", a_rd, a_rn, a_rm);
            } else {
                snprintf(state->add_pending_disasm,
                    sizeof(state->add_pending_disasm),
                    "add x%u, x%u, x%u, lsl #%u",
                    a_rd, a_rn, a_rm, a_shift);
            }
        }
    }

    return produced;
}

// Decode an integer register-offset LDR (the "[Rn, Rm{, ext #s}]" form):
//   size 111 0 00 opc 1 Rm option S 10 Rn Rt
// Mask 0x3F200C00 fixes bits 29..24 = 111000, bit 21 = 1, bits 11..10 =
// 10; value 0x38200800. The caller filters to a plain load (opc = 01)
// with the LSL/UXTX index option (011, a full 64-bit register offset).
// option = bits 15..13, S = bit 12 (scale by log2(size) when set).
static bool decode_ldr_reg_offset(uint32_t op, unsigned *out_size,
                                  unsigned *out_opc, unsigned *out_rm,
                                  unsigned *out_option, unsigned *out_s,
                                  unsigned *out_rn, unsigned *out_rt)
{
    if ((op & 0x3F200C00u) != 0x38200800u) {
        return false;
    }
    *out_size = (op >> 30) & 0x3u;
    *out_opc = (op >> 22) & 0x3u;
    *out_rm = (op >> 16) & 0x1Fu;
    *out_option = (op >> 13) & 0x7u;
    *out_s = (op >> 12) & 0x1u;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rt = op & 0x1Fu;
    return true;
}

bool check_sxtw_ldr_fold(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->sxl_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: a register-offset LDR that uses the SXTW result
    //     as a plain X-register index and loads back into it?
    if (state->sxl_pending) {
        unsigned size, opc, rm, option, s, rn, rt;
        const char *ldr_mnem;
        char rt_wx;
        if (decode_ldr_reg_offset(op, &size, &opc, &rm, &option, &s,
                                  &rn, &rt)
                // Any integer load, zero- or sign-extending (not STR,
                // whose Rt is read, nor PRFM, whose Rt is a prefetch
                // op). Every accepted load overwrites the full X
                // register named by Rt, so the index-deadness proof is
                // the same for the LDRS* forms.
                && classify_int_load(size, opc, &ldr_mnem, &rt_wx)
                && option == 3u         // LSL/UXTX: a full 64-bit offset
                && rm == state->sxl_rd  // index is the SXTW result
                && rt == state->sxl_rd  // the load overwrites it (dead)
                && rn != state->sxl_rd) {
            // Rn == index would make the fold read the base's pre-SXTW
            // value (the SXTW is removed), changing the address; excluded
            // above. The scale bit S carries over unchanged: it scales
            // the sign-extended index either way.
            char base_buf[8];
            if (rn == 31) {
                snprintf(base_buf, sizeof(base_buf), "sp");
            } else {
                snprintf(base_buf, sizeof(base_buf), "x%u", rn);
            }

            out->name = "SXTW + register-offset LDR foldable into the load";
            out->start_offset = state->sxl_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            if (s == 0) {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %c%u, [%s, w%u, sxtw]",
                    ldr_mnem, rt_wx, rt, base_buf, state->sxl_rs);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %c%u, [%s, x%u]",
                    ldr_mnem, rt_wx, rt, base_buf, rm);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %c%u, [%s, w%u, sxtw #%u]",
                    ldr_mnem, rt_wx, rt, base_buf, state->sxl_rs, size);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %c%u, [%s, x%u, lsl #%u]",
                    ldr_mnem, rt_wx, rt, base_buf, rm, size);
            }
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->sxl_disasm);
            produced = true;
        }
        // Strict adjacency: clear regardless of match.
        state->sxl_pending = false;
    }

    // (2) Try to open: is this an SXTW Xd, Wn (SBFM with imms=31)?
    unsigned s_s, s_w, s_rd, s_rn;
    if (decode_sbfm_sext(op, &s_s, &s_w, &s_rd, &s_rn)
            && s_s == 32u            // SXTW (sign-extend word -> dword)
            && s_rd != 31 && s_rn != 31) {
        state->sxl_pending = true;
        state->sxl_rd = s_rd;
        state->sxl_rs = s_rn;
        state->sxl_offset = offset;
        snprintf(state->sxl_disasm, sizeof(state->sxl_disasm),
            "sxtw x%u, w%u", s_rd, s_rn);
    }

    return produced;
}

bool check_ldr_sext_fold(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->lsx_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: an in-place SXTB/SXTH/SXTW of the loaded
    //     register? The threshold rule differs by producer family.
    //     Zero-extending loads require the consumer's sign threshold
    //     to EQUAL the load's access width: below it the LDRS rewrite
    //     would shrink the memory access (not architecturally
    //     identical), above it the consumer sign-extends from a bit
    //     the load provably zeroed (a no-op, not this rewrite). The
    //     W-form sign-extending loads accept any threshold AT OR ABOVE
    //     the access width: every bit from the width up is a copy of
    //     the loaded sign, so SXTB/SXTH/SXTW all reproduce exactly
    //     what the X-form load computes -- but only the X-form (c_w ==
    //     64) consumer is a fold; the W-form one changes nothing and
    //     belongs to the redundant-sext check. c_w (32 or 64) picks
    //     the LDRS destination width; SXTW only exists X-form, so a
    //     word load always folds to LDRSW Xt.
    if (state->lsx_active) {
        unsigned c_s, c_w, c_rd, c_rn;
        if (decode_sbfm_sext(op, &c_s, &c_w, &c_rd, &c_rn)
                && c_rd == state->lsx_rt
                && c_rn == state->lsx_rt
                && (state->lsx_signed
                        ? (c_w == 64u && c_s >= (8u << state->lsx_size))
                        : c_s == (8u << state->lsx_size))) {
            static const char *const ldrs_mnem[3] = {
                "ldrsb", "ldrsh", "ldrsw"
            };
            const char *mnem = ldrs_mnem[state->lsx_size];
            char rt_wx = (c_w == 64u) ? 'x' : 'w';
            unsigned bytes = state->lsx_imm12 << state->lsx_size;
            char base_buf[8];
            if (state->lsx_rn == 31) {
                snprintf(base_buf, sizeof(base_buf), "sp");
            } else {
                snprintf(base_buf, sizeof(base_buf), "x%u",
                    state->lsx_rn);
            }

            out->name =
                "load + sign-extend foldable to LDRSB/LDRSH/LDRSW";
            out->start_offset = state->lsx_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            if (bytes == 0) {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %c%u, [%s]",
                    mnem, rt_wx, state->lsx_rt, base_buf);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %c%u, [%s, #0x%x]",
                    mnem, rt_wx, state->lsx_rt, base_buf, bytes);
            }
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->lsx_disasm);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %s", insn->mnemonic, insn->op_str);
            produced = true;
        }
        // Strict adjacency: clear regardless of match.
        state->lsx_active = false;
    }

    // (2) Try to open: a zero-extending unsigned-offset load (B/H/W),
    //     or a W-form sign-extending one (LDRSB/LDRSH Wt)? Size 3
    //     (LDR Xt) is full-width -- no sign-extend consumer can fold
    //     it -- and the X-form sign-extending loads already fill all
    //     64 bits, so their re-extensions are the redundant-sext
    //     check's no-ops. Rt = 31 discards the load; skip.
    unsigned size, imm12, rn, rt;
    bool open_signed = false;
    bool open = false;
    if (decode_ldr_uimm_any_size(op, &size, &imm12, &rn, &rt)
            && size <= 2u) {
        open = true;
    } else if (decode_ldrs_w_uimm(op, &size, &imm12, &rn, &rt)) {
        open = true;
        open_signed = true;
    }
    if (open && rt != 31) {
        state->lsx_active = true;
        state->lsx_signed = open_signed;
        state->lsx_size = size;
        state->lsx_rt = rt;
        state->lsx_rn = rn;
        state->lsx_imm12 = imm12;
        state->lsx_offset = offset;
        snprintf(state->lsx_disasm, sizeof(state->lsx_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return produced;
}

bool check_add_ldr_imm_offset(armlint_state *state,
                              const cs_insn *insn,
                              size_t offset,
                              armlint_finding *out)
{
    if (insn->size != 4) {
        state->addi_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: is this an integer load (zero- or
    //     sign-extending; see classify_int_load) consuming the pending
    //     ADD? Sign-extending consumers overwrite the full X register
    //     named by Rt just like plain LDR, and every accepted pair has
    //     an unsigned-offset LDRS* form, so the fold carries over.
    if (state->addi_pending) {
        unsigned size, imm12, ldr_rn, ldr_rt;
        const char *ldr_mnem;
        char rt_wx;
        if (decode_int_load_uimm(op, &size, &ldr_mnem, &rt_wx,
                                 &imm12, &ldr_rn, &ldr_rt)
                && ldr_rn == state->addi_pending_rd
                && ldr_rt == state->addi_pending_rd) {
            // The LDR's own byte offset is imm12 * access_size, already
            // a multiple of access_size by construction. So the combined
            // offset's alignment depends only on the ADD's imm, and the
            // scaled total must fit in 12 bits. ldr_byte_imm + add_imm
            // cannot overflow uint32_t: add_imm <= 0xFFF000 (24 bits)
            // and ldr_byte_imm <= 4095 * 8 = 0x7FF8 (15 bits).
            unsigned access_size = 1u << size;
            uint32_t add_imm = state->addi_pending_imm;
            uint32_t ldr_byte_imm = (uint32_t)imm12 * access_size;
            uint32_t combined = add_imm + ldr_byte_imm;
            if ((add_imm & (access_size - 1u)) == 0
                    && (combined >> size) <= 0xFFFu) {
                out->name = "ADD + LDR foldable to immediate-offset LDR";
                out->start_offset = state->addi_pending_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                // combined == 0 is reachable only via the MOV-from-SP
                // alias (imm == 0 requires Rn = SP) with a zero-offset
                // load; render the bare [sp] form.
                if (combined == 0) {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %c%u, [sp]",
                        ldr_mnem, rt_wx, ldr_rt);
                } else if (state->addi_pending_rn == 31) {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %c%u, [sp, #0x%x]",
                        ldr_mnem, rt_wx, ldr_rt, combined);
                } else {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %c%u, [x%u, #0x%x]",
                        ldr_mnem, rt_wx, ldr_rt,
                        state->addi_pending_rn, combined);
                }
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->addi_pending_disasm);
                if (ldr_byte_imm == 0) {
                    snprintf(out->lines[1], sizeof(out->lines[1]),
                        "%s %c%u, [x%u]",
                        ldr_mnem, rt_wx, ldr_rt, ldr_rn);
                } else {
                    snprintf(out->lines[1], sizeof(out->lines[1]),
                        "%s %c%u, [x%u, #0x%x]",
                        ldr_mnem, rt_wx, ldr_rt, ldr_rn, ldr_byte_imm);
                }
                produced = true;
            }
        }
        // Strict adjacency: clear regardless of match.
        state->addi_pending = false;
    }

    // (2) Try to open: is this an X-form ADD-immediate?
    unsigned a_rd, a_rn;
    uint32_t a_imm;
    if (decode_add_imm_x(op, &a_rd, &a_rn, &a_imm)) {
        // Rd=31 in ADD-imm means SP, not XZR; folding would write a
        // discarded LDR to XZR while the SP modification is observable
        // -- exclude. imm == 0 with a GPR source is the redundant ADD
        // that check_add_sub_zero owns, not a strength-reduction case;
        // but imm == 0 with Rn = SP is the MOV-from-SP alias
        // (mov xt, sp), whose base copy folds the same way:
        // mov x8, sp ; ldr x8, [x8] -> ldr x8, [sp]. Rn=31 (SP) IS
        // allowed generally: ADD-imm and LDR-uimm both encode 31 as
        // SP, so the fold preserves semantics for the common
        // stack-relative load pattern.
        if (a_rd != 31 && (a_imm != 0 || a_rn == 31)) {
            state->addi_pending = true;
            state->addi_pending_rd = a_rd;
            state->addi_pending_rn = a_rn;
            state->addi_pending_imm = a_imm;
            state->addi_pending_offset = offset;
            if (a_rn == 31 && a_imm == 0) {
                snprintf(state->addi_pending_disasm,
                    sizeof(state->addi_pending_disasm),
                    "mov x%u, sp", a_rd);
            } else if (a_rn == 31) {
                snprintf(state->addi_pending_disasm,
                    sizeof(state->addi_pending_disasm),
                    "add x%u, sp, #0x%x", a_rd, a_imm);
            } else {
                snprintf(state->addi_pending_disasm,
                    sizeof(state->addi_pending_disasm),
                    "add x%u, x%u, #0x%x", a_rd, a_rn, a_imm);
            }
        }
    }

    return produced;
}

bool check_ldr_str_add_post_indexed(armlint_state *state,
                                    const cs_insn *insn,
                                    size_t offset,
                                    armlint_finding *out)
{
    if (insn->size != 4) {
        state->lspi_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: is this an X-form ADD-immediate that
    // self-updates the pending LDR/STR's base?
    if (state->lspi_pending) {
        unsigned a_rd, a_rn;
        uint32_t a_imm;
        // Rt == Rn writeback is UNPREDICTABLE (CONSTRAINED for stores)
        // unless Rn == 31, where 31 means SP for Rn but XZR for Rt --
        // distinct registers, so no conflict. A SIMD&FP Rt lives in a
        // different register file and can never alias the base.
        bool rt_aliases_rn = !state->lspi_pending_is_fp
            && state->lspi_pending_rt == state->lspi_pending_rn
            && state->lspi_pending_rn != 31;
        bool is_add = decode_add_imm_x(op, &a_rd, &a_rn, &a_imm);
        bool is_sub = !is_add && decode_sub_imm_x(op, &a_rd, &a_rn, &a_imm);
        // ADD self-update folds to a positive writeback (imm 1..255);
        // SUB to a negative one (imm 1..256, the signed-9-bit slot
        // reaching -256). The imm range test sits after the
        // (is_add || is_sub) guard so a_imm is only read once a decoder
        // has filled it.
        if (!rt_aliases_rn
                && (is_add || is_sub)
                && a_rd == state->lspi_pending_rn
                && a_rn == state->lspi_pending_rn
                && a_imm >= 1
                && a_imm <= (is_sub ? 256u : 255u)) {
            unsigned size = state->lspi_pending_size;
            bool is_load = state->lspi_pending_is_load;
            bool is_fp = state->lspi_pending_is_fp;
            const char *mnem = ls_mnemonic(is_fp, is_load, size);
            const char *idx_sign = is_sub ? "-" : "";
            const char *upd_mnem = is_sub ? "sub" : "add";

            if (is_load) {
                out->name = is_sub
                    ? "LDR + SUB foldable to post-indexed LDR"
                    : "LDR + ADD foldable to post-indexed LDR";
            } else {
                out->name = is_sub
                    ? "STR + SUB foldable to post-indexed STR"
                    : "STR + ADD foldable to post-indexed STR";
            }
            out->start_offset = state->lspi_pending_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            char rt_buf[8];
            format_ls_rt(rt_buf, sizeof(rt_buf), is_fp, size,
                state->lspi_pending_rt);
            if (state->lspi_pending_rn == 31) {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, [sp], #%s0x%x", mnem, rt_buf, idx_sign, a_imm);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, [x%u], #%s0x%x",
                    mnem, rt_buf, state->lspi_pending_rn, idx_sign, a_imm);
            }
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->lspi_pending_disasm);
            if (a_rn == 31) {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s sp, sp, #0x%x", upd_mnem, a_imm);
            } else {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s x%u, x%u, #0x%x", upd_mnem, a_rd, a_rn, a_imm);
            }
            produced = true;
        }
        // Strict adjacency: clear regardless of match.
        state->lspi_pending = false;
    }

    // (2) Try to open: is this an unsigned-offset LDR or STR (integer
    // or SIMD&FP -- every FP size has a post-indexed form) with
    // imm12 == 0? Only the zero-offset case folds cleanly: a non-zero
    // imm12 plus a post-index update has no single-instruction
    // rewrite (pre-indexed handles a different pattern).
    unsigned size, imm12, rn, rt;
    bool opened = false;
    bool is_load = false;
    bool is_fp = false;
    if (decode_ldr_uimm_any_size(op, &size, &imm12, &rn, &rt)
            && imm12 == 0) {
        opened = true;
        is_load = true;
    } else if (decode_str_uimm_any_size(op, &size, &imm12, &rn, &rt)
            && imm12 == 0) {
        opened = true;
        is_load = false;
    } else if (decode_fp_ldr_str_uimm(op, &is_load, &size, &imm12,
                                      &rn, &rt)
            && imm12 == 0) {
        opened = true;
        is_fp = true;
    }
    if (opened) {
        state->lspi_pending = true;
        state->lspi_pending_is_load = is_load;
        state->lspi_pending_is_fp = is_fp;
        state->lspi_pending_size = size;
        state->lspi_pending_rn = rn;
        state->lspi_pending_rt = rt;
        state->lspi_pending_offset = offset;
        const char *mnem = ls_mnemonic(is_fp, is_load, size);
        char rt_buf[8];
        format_ls_rt(rt_buf, sizeof(rt_buf), is_fp, size, rt);
        if (rn == 31) {
            snprintf(state->lspi_pending_disasm,
                sizeof(state->lspi_pending_disasm),
                "%s %s, [sp]", mnem, rt_buf);
        } else {
            snprintf(state->lspi_pending_disasm,
                sizeof(state->lspi_pending_disasm),
                "%s %s, [x%u]", mnem, rt_buf, rn);
        }
    }

    return produced;
}

bool check_add_ldr_str_pre_indexed(armlint_state *state,
                                   const cs_insn *insn,
                                   size_t offset,
                                   armlint_finding *out)
{
    if (insn->size != 4) {
        state->lspr_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Try to close: is this an unsigned-offset LDR or STR with
    // imm12 == 0 whose base matches the pending ADD self-update?
    if (state->lspr_pending) {
        unsigned size, imm12, rn, rt;
        bool matched = false;
        bool is_load = false;
        bool is_fp = false;
        if (decode_ldr_uimm_any_size(op, &size, &imm12, &rn, &rt)
                && imm12 == 0
                && rn == state->lspr_pending_rd) {
            matched = true;
            is_load = true;
        } else if (decode_str_uimm_any_size(op, &size, &imm12, &rn, &rt)
                && imm12 == 0
                && rn == state->lspr_pending_rd) {
            matched = true;
            is_load = false;
        } else if (decode_fp_ldr_str_uimm(op, &is_load, &size, &imm12,
                                          &rn, &rt)
                && imm12 == 0
                && rn == state->lspr_pending_rd) {
            // SIMD&FP access: every FP size has a pre-indexed form.
            matched = true;
            is_fp = true;
        }
        // Rt == Rn writeback is UNPREDICTABLE for loads and
        // CONSTRAINED UNPREDICTABLE for stores (same rule as
        // post-index). Rn == 31 is the exception: Rn means SP and Rt
        // means XZR, so the two encode distinct registers. A SIMD&FP
        // Rt lives in a different register file and never aliases.
        bool rt_aliases_rn = matched && !is_fp && rt == rn && rn != 31;
        if (matched && !rt_aliases_rn) {
            const char *mnem = ls_mnemonic(is_fp, is_load, size);

            char rt_buf[8];
            format_ls_rt(rt_buf, sizeof(rt_buf), is_fp, size, rt);

            uint32_t imm = state->lspr_pending_imm;
            const char *idx_sign = state->lspr_pending_is_sub ? "-" : "";
            if (is_load) {
                out->name = state->lspr_pending_is_sub
                    ? "SUB + LDR foldable to pre-indexed LDR"
                    : "ADD + LDR foldable to pre-indexed LDR";
            } else {
                out->name = state->lspr_pending_is_sub
                    ? "SUB + STR foldable to pre-indexed STR"
                    : "ADD + STR foldable to pre-indexed STR";
            }
            out->start_offset = state->lspr_pending_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            if (rn == 31) {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, [sp, #%s0x%x]!", mnem, rt_buf, idx_sign, imm);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, [x%u, #%s0x%x]!", mnem, rt_buf, rn, idx_sign, imm);
            }
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->lspr_pending_disasm);
            if (rn == 31) {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s, [sp]", mnem, rt_buf);
            } else {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s, [x%u]", mnem, rt_buf, rn);
            }
            produced = true;
        }
        // Strict adjacency: clear regardless of match.
        state->lspr_pending = false;
    }

    // (2) Try to open: is this an X-form ADD/SUB-immediate self-update
    // (Rd == Rn) with imm in the 9-bit signed range? ADD imm 1..255 is
    // a positive writeback; SUB imm 1..256 is a negative one (-256
    // being the signed-9-bit minimum).
    unsigned a_rd, a_rn;
    uint32_t a_imm;
    bool is_add = decode_add_imm_x(op, &a_rd, &a_rn, &a_imm);
    bool is_sub = !is_add && decode_sub_imm_x(op, &a_rd, &a_rn, &a_imm);
    if ((is_add || is_sub)
            && a_rd == a_rn
            && a_imm >= 1
            && a_imm <= (is_sub ? 256u : 255u)) {
        const char *upd_mnem = is_sub ? "sub" : "add";
        state->lspr_pending = true;
        state->lspr_pending_is_sub = is_sub;
        state->lspr_pending_rd = a_rd;
        state->lspr_pending_imm = a_imm;
        state->lspr_pending_offset = offset;
        if (a_rn == 31) {
            snprintf(state->lspr_pending_disasm,
                sizeof(state->lspr_pending_disasm),
                "%s sp, sp, #0x%x", upd_mnem, a_imm);
        } else {
            snprintf(state->lspr_pending_disasm,
                sizeof(state->lspr_pending_disasm),
                "%s x%u, x%u, #0x%x", upd_mnem, a_rd, a_rn, a_imm);
        }
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

    uint32_t op = insn_word(insn);

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

// Distinct finding names are bounded by the registry's output variants;
// 128 is comfortably above the few dozen that exist.
#define ARMLINT_SUMMARY_MAX 128

struct armlint_summary {
    struct {
        const char *name;
        unsigned count;
    } entries[ARMLINT_SUMMARY_MAX];
    size_t count;
    size_t instructions;   // total decoded instructions across all runs
};

armlint_summary *armlint_summary_create(void)
{
    return calloc(1, sizeof(struct armlint_summary));
}

void armlint_summary_destroy(armlint_summary *summary)
{
    free(summary);
}

size_t armlint_summary_instructions(const armlint_summary *summary)
{
    return summary == NULL ? 0 : summary->instructions;
}

// Tally one finding by its name (a stable string literal owned by the
// check). Linear scan -- the table is tiny. Silently ignores overflow
// (cannot happen with the current check set) and a NULL summary.
static void summary_add(armlint_summary *summary, const char *name)
{
    if (summary == NULL || name == NULL) {
        return;
    }
    for (size_t i = 0; i < summary->count; i++) {
        if (strcmp(summary->entries[i].name, name) == 0) {
            summary->entries[i].count++;
            return;
        }
    }
    if (summary->count < ARMLINT_SUMMARY_MAX) {
        summary->entries[summary->count].name = name;
        summary->entries[summary->count].count = 1;
        summary->count++;
    }
}

void armlint_summary_print(const armlint_summary *summary)
{
    if (summary == NULL || summary->count == 0) {
        return;
    }

    // Order by descending count, ties broken by name for determinism.
    size_t order[ARMLINT_SUMMARY_MAX];
    for (size_t i = 0; i < summary->count; i++) {
        order[i] = i;
    }
    for (size_t i = 0; i < summary->count; i++) {
        size_t best = i;
        for (size_t j = i + 1; j < summary->count; j++) {
            unsigned cj = summary->entries[order[j]].count;
            unsigned cb = summary->entries[order[best]].count;
            if (cj > cb
                || (cj == cb
                    && strcmp(summary->entries[order[j]].name,
                              summary->entries[order[best]].name) < 0)) {
                best = j;
            }
        }
        size_t tmp = order[i];
        order[i] = order[best];
        order[best] = tmp;
    }

    printf("Optimization opportunities by type:\n");
    for (size_t i = 0; i < summary->count; i++) {
        const char *name = summary->entries[order[i]].name;
        unsigned count = summary->entries[order[i]].count;
        printf("  %6u  %s\n", count, name);
    }
    printf("\n");
}

static void report_finding(const armlint_finding *finding, bool verbose)
{
    // The default output is the by-type summary only -- a large binary
    // can have tens of thousands of opportunities, so listing each one
    // is unhelpful. Verbose mode prints every finding: its one-line
    // summary followed by the offending instructions (indented).
    if (!verbose) {
        return;
    }
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

// Single ordered list of every per-instruction action the driver
// runs. The pre-instruction advancers come first (see the comment on
// armlint_advance_pending); the rest are per-instruction checks. The
// test harness's run_check iterates the same list, so adding a check
// or advancer is a single-line edit here.
const armlint_check_fn armlint_check_registry[] = {
    armlint_advance_pending,
    armlint_advance_pending_sv,
    check_mul_strength_reduce,
    check_mneg_strength_reduce,
    check_udiv_strength_reduce,
    check_mov_add_sub_imm_fold,
    check_mov_logic_imm_fold,
    check_mov_zero_to_xzr,
    check_movz_movk_bitmask,
    check_lsl_fold,
    check_cmp_zero_branch,
    check_tst_branch,
    check_redundant_zext,
    check_redundant_sext,
    check_lsl_lsr_to_ubfx,
    check_lsr_and_to_ubfx,
    check_and_lsr_to_ubfx,
    check_and_lsr_lsl_fold,
    check_mov_reg_self,
    check_add_sub_zero,
    check_self_op,
    check_csel_self,
    check_bfxil_synth,
    check_ldp_stp_coalesce,
    check_redundant_cmp_after_s_variant,
    check_mul_add_sub_fold,
    check_widening_mul_add_sub_fold,
    check_neg_add_sub_fold,
    check_mvn_logic_fold,
    check_extend_add_sub_fold,
    check_add_ldr_register_offset,
    check_sxtw_ldr_fold,
    check_ldr_sext_fold,
    check_add_ldr_imm_offset,
    check_ldr_str_add_post_indexed,
    check_add_ldr_str_pre_indexed,
};

const size_t armlint_check_registry_count =
    sizeof(armlint_check_registry) / sizeof(armlint_check_registry[0]);

// Stream the byte buffer one instruction at a time. cs_disasm would
// require allocating a cs_insn for every instruction up front (5+ GB on
// a 100 MB text section) and silently stops at the first undecodable
// 4-byte slot. cs_disasm_iter recycles a single cs_insn and lets us
// skip past data-in-text by hand.
int check_instructions(csh handle, const uint8_t *inst, size_t len,
                       uint64_t base_addr, bool verbose,
                       armlint_summary *summary)
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
            if (summary != NULL) {
                summary->instructions++;
            }
            size_t offset = (size_t)(insn_addr - base_addr);
            for (size_t k = 0; k < armlint_check_registry_count; k++) {
                armlint_finding finding;
                if (armlint_check_registry[k](state, insn, offset,
                                              &finding)) {
                    report_finding(&finding, verbose);
                    summary_add(summary, finding.name);
                    errors++;
                }
            }
        } else {
            // Treat the slot as opaque data and skip a single A64
            // word. Flush first so an in-progress sequence cannot
            // straddle the gap.
            armlint_finding finding;
            if (armlint_flush(state, &finding)) {
                report_finding(&finding, verbose);
                summary_add(summary, finding.name);
                errors++;
            }
            code += 4;
            size -= 4;
            address += 4;
        }
    }

    armlint_finding finding;
    if (armlint_flush(state, &finding)) {
        report_finding(&finding, verbose);
        summary_add(summary, finding.name);
        errors++;
    }

    cs_free(insn, 1);
    armlint_state_destroy(state);
    return errors;
}
