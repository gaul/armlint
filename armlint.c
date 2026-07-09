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

    // Immediate LSL/LSR shift pending a complementary shifted-register
    // ORR/EOR/ADD consumer, together a funnel shift foldable to EXTR (or
    // ROR when both funnel sources are the same register). fnl_is_lsr
    // records the pending shift's direction; the consumer must carry the
    // opposite one with the two amounts summing to the register width.
    // Separate from shf_* because that check wants a zero-shift consumer
    // to absorb the shift, whereas this one wants a non-zero complementary
    // inline shift that completes the funnel.
    bool fnl_active;
    bool fnl_is_64bit;
    bool fnl_is_lsr;
    unsigned fnl_rd;      // shift destination -- the dead intermediate Rt
    unsigned fnl_rn;      // shift source Ra (one funnel operand)
    unsigned fnl_shift;   // shift amount
    size_t fnl_offset;

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

    // AND-low-mask, a zero-extension (UXTB/UXTH/UXTW or a W-form MOV), or
    // LSR pending an LSL consumer (the "shift a field up" idiom). An AND of
    // the low w bits -- or a zero-extension that keeps the low w bits --
    // then LSL #n folds to UBFIZ Rd, Rs, #n, #w; an LSR #a then LSL #a
    // (equal shifts) clears the low a bits, i.e. AND Rd, Rs, #~(2^a-1).
    // aul_is_lsr selects the LSR producer and aul_zext the zero-extension
    // producer (both clear for a plain AND); aul_param holds the mask/field
    // width w (AND, zext) or the shift a (LSR). aul_is_64bit is the width of
    // the consuming LSL and the emitted rewrite. aul_rd is the producer's
    // destination (the LSL reads and writes it), aul_rn its source (the
    // fold's source).
    bool aul_active;
    bool aul_is_64bit;
    bool aul_is_lsr;
    bool aul_zext;
    unsigned aul_rd;
    unsigned aul_rn;
    unsigned aul_param;
    size_t aul_offset;
    char aul_disasm[ARMLINT_FINDING_LINE_LEN];

    // Zero-test of Rn (CMP Rn,#0 / CMP Rn,XZR / CMN Rn,#0 /
    // CMN Rn,XZR / TST Rn,Rn) pending a B.EQ/B.NE consumer (any
    // form), a B.HI/B.LS consumer (the SUBS forms only --
    // cmp_is_subs; the ADDS/ANDS forms clear C), or a sign-condition
    // B.cond.
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

    // Flag-free single-bit producer (AND-imm with a one-bit mask, or a
    // one-bit UBFM/SBFM extract) pending a CBZ/CBNZ consumer for the
    // TBZ/TBNZ fold. tbf_rd is the producer's destination (the branch
    // tests it), tbf_rs its source (the TBZ reads it), tbf_bit the
    // isolated bit.
    bool tbf_active;
    bool tbf_is_64bit;
    unsigned tbf_rd;
    unsigned tbf_rs;
    unsigned tbf_bit;
    size_t tbf_offset;
    char tbf_disasm[ARMLINT_FINDING_LINE_LEN];

    // Deferred single-bit-test TBZ/TBNZ finding awaiting the two-edge
    // register-liveness proof (see armlint_advance_pending_tb): the
    // rewrite deletes the producer, so the masked temp must be dead on
    // the fall-through path (overwritten before any read or control
    // transfer -- the usual forward scan) AND on the taken path, which
    // is covered by containment: emission requires the branch target
    // to lie within [fall-through, kill], the span the scan just
    // proved free of reads and control transfers, so the taken edge
    // enters that clean span and reaches the same kill.
    bool pending_tb_active;
    unsigned pending_tb_window;
    int pending_tb_reg;
    size_t pending_tb_ft;         // fall-through offset (consumer + 4)
    size_t pending_tb_target;     // branch-target offset
    armlint_finding pending_tb_finding;

    // CSET producer (CSINC Rd, ZR, ZR, cond; cond not AL/NV) pending a
    // consumer: CBZ/CBNZ of Rd (fold to B.cond), EOR Rd', Rd, #1 (fold
    // to the inverted CSET) or NEG Rd', Rd (fold to CSETM). cset_cond
    // is the logical CSET condition -- the raw CSINC field inverted.
    bool cset_active;
    unsigned cset_rd;
    unsigned cset_cond;
    size_t cset_offset;
    char cset_disasm[ARMLINT_FINDING_LINE_LEN];

    // Widening-extend producer (SXTW Xd, Wn, or the zero-extending
    // MOV Wd, Wm) pending a 64-bit-source SCVTF/UCVTF consumer for
    // the narrower-conversion fold. xtc_signed distinguishes the
    // sign- from the zero-extension; xtc_rn is the extend's source.
    bool xtc_active;
    bool xtc_signed;
    unsigned xtc_rd;
    unsigned xtc_rn;
    size_t xtc_offset;
    char xtc_disasm[ARMLINT_FINDING_LINE_LEN];

    // Producer of bits-above-N guaranteed zero, pending a redundant
    // zero-extension consumer that re-zeros those bits. wzx_zero_from
    // is the threshold P: the producer guarantees bits >= P are zero.
    //   UBFM (W or X form)     -> P from the field geometry (see
    //                             decode_zeroing_producer); covers
    //                             LSR / UBFX / UXTB / UXTH producers
    //   AND/ANDS imm (W or X)  -> P = top set bit of the mask + 1
    //   MOVZ (W or X)          -> P = bit count of the known value
    //   CSINC Rd, ZR, ZR (CSET)-> P = 1 (result is 0 or 1)
    //   other W-form ALU / LDR Wt / LDRSB/LDRSH Wt -> P=32
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
    // that region (32 for W-form, 64 for X-form). Any SBFM is a
    // producer, with S from the field geometry (see
    // decode_sext_producer); the canonical shapes:
    //   LDRSB Wt / SXTB Wd, Wn         -> (S=8,  W=32)
    //   LDRSH Wt / SXTH Wd, Wn         -> (S=16, W=32)
    //   LDRSB Xt / SXTB Xd, Wn         -> (S=8,  W=64)
    //   LDRSH Xt / SXTH Xd, Wn         -> (S=16, W=64)
    //   LDRSW Xt / SXTW Xd, Wn         -> (S=32, W=64)
    //   ASR Rd, Rn, #k (W/X)           -> (S=datasize-k, W=datasize)
    //   SBFX Rd, Rn, #lsb, #w          -> (S=w, W=datasize)
    //   SBFIZ Rd, Rn, #lsb, #w         -> (S=lsb+w, W=datasize)
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
    // True when the producer can be dropped outright by the
    // dead-sign-extension path: it is an in-place register sign-extend
    // (an SBFM with immr == 0 -- SXTB/SXTH/SXTW or a general low-field
    // SBFX #0 -- and Rn == Rd), whose only effect is to overwrite the
    // high bits that a following zero-extension then clears -- so
    // removing it leaves the meaningful low bits (already sitting in Rd)
    // untouched.
    //
    // False for every producer that instead writes fresh data into those
    // low bits, where deleting it would change the result:
    //   - sign-extending loads (LDRSB/LDRSH/LDRSW): the value comes from
    //     memory, so dropping the load loses it (and the memory access).
    //   - SXT with Rn != Rd: the value comes from Rn, not Rd's own bits.
    //   - ASR, SBFX with lsb > 0, SBFIZ (immr != 0): data-relocating
    //     shapes -- the field the consumer keeps came from elsewhere.
    // The redundant-SXT path (which removes a following SXT rather than
    // the producer) stays sound for all of these and does not read this.
    bool sxt_dead_ok;

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

    // Mirror of sv_* one S bit over: a non-flag-setting ALU whose
    // S-variant twin exists (ADD/SUB/AND/BIC) pending a CMP/TST-zero
    // of its Rd. Converting the ALU to the S-variant reproduces the
    // zero-test's N and Z exactly, making the CMP/TST droppable once
    // the same NZCV scan proves C/V (which the S-variant sets
    // differently) unobserved. zs_sdisasm holds the pre-rendered
    // S-variant spelling (the producer's mnemonic + "s").
    bool zs_active;
    bool zs_is_64bit;
    unsigned zs_rd;
    size_t zs_offset;
    char zs_disasm[ARMLINT_FINDING_LINE_LEN];
    char zs_sdisasm[ARMLINT_FINDING_LINE_LEN];

    // CMP/TST-zero of zs_rd observed adjacent to the ALU, awaiting a
    // B.EQ/B.NE consumer.
    bool zs_cmp_active;
    char zs_cmp_disasm[ARMLINT_FINDING_LINE_LEN];

    // Deferred "ALU + zero-CMP -> S-variant" finding, parallel to
    // pending_sv_*. Advanced by armlint_advance_pending_zs. A
    // dedicated slot so an overlapping sv deferral cannot clobber it.
    bool pending_zs_active;
    unsigned pending_zs_window;
    armlint_finding pending_zs_finding;

    // Enabled ISA-extension features (ARMLINT_FEATURE_*); checks that
    // suggest extension instructions stay silent unless their feature
    // is set.
    unsigned features;

    // Pending plain register CMP (shifted-register, LSL #0, Rd = 31)
    // awaiting an adjacent CSEL of the compared registers -- the
    // CSSC MAX/MIN shape.
    bool cmx_active;
    bool cmx_is_64bit;
    unsigned cmx_rn;
    unsigned cmx_rm;
    size_t cmx_offset;
    char cmx_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending CMP Rn, #0 awaiting an adjacent CNEG of Rn -- the CSSC
    // ABS shape.
    bool cab_active;
    bool cab_is_64bit;
    unsigned cab_rn;
    size_t cab_offset;
    char cab_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending RBIT awaiting an adjacent CLZ of its destination -- the
    // CSSC CTZ shape.
    bool rbc_active;
    bool rbc_is_64bit;
    unsigned rbc_rd;
    unsigned rbc_rs;
    size_t rbc_offset;
    char rbc_disasm[ARMLINT_FINDING_LINE_LEN];

    // Deferred CSSC finding awaiting proof that NZCV is dead: the
    // MAX/MIN and ABS rewrites delete the compare and set no flags at
    // all, so any later flag reader (before an overwrite) discards.
    // A single shared slot; overlapping deferrals drop the earlier
    // finding (false-negative only), like the shared mz slot.
    bool pending_cssc_active;
    unsigned pending_cssc_window;
    armlint_finding pending_cssc_finding;

    // Deferred finding gated on an FP/vector register's death,
    // advanced by armlint_advance_pending_fp -- the FP twin of the
    // pending_mz slot (single slot, same collision semantics).
    bool pending_fp_active;
    unsigned pending_fp_window;
    int pending_fp_reg;
    armlint_finding pending_fp_finding;

    // Pending halves of the SUB + identical-operand CMP pair (either
    // order): a non-S SUB awaiting the CMP, and a CMP awaiting the
    // SUB. CMP Rn, Rm is SUBS ZR, Rn, Rm, so a CMP of the SUB's exact
    // operands is the SUB's own encoding with the S bit set and
    // Rd = 31 -- scp_sub_op / scp_cmp_op hold the raw words for that
    // modulo-Rd/S-bit match, which covers the immediate, shifted-
    // register and extended-register forms (and forces equal widths,
    // shifts and extends) in one comparison. NZCV is a function of
    // the operands only, never Rd, so the folded SUBS's flags are
    // bit-identical to the CMP's: no liveness scan is needed.
    bool scp_sub_active;
    uint32_t scp_sub_op;
    size_t scp_sub_offset;
    char scp_sub_disasm[ARMLINT_FINDING_LINE_LEN];
    char scp_sub_sdisasm[ARMLINT_FINDING_LINE_LEN];
    bool scp_cmp_active;
    uint32_t scp_cmp_op;
    size_t scp_cmp_offset;
    char scp_cmp_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending flag-setting ADD/SUB (ADDS/SUBS/CMP/CMN, any form)
    // awaiting an adjacent compare of its own operands, which
    // recomputes NZCV the producer already set and can simply be
    // dropped.
    bool rcs_active;
    uint32_t rcs_op;
    size_t rcs_offset;
    char rcs_disasm[ARMLINT_FINDING_LINE_LEN];

    // Deferred "MOV #0 + use foldable to ZR" finding awaiting forward
    // register-liveness verification. Dropping the MOV only saves an
    // instruction when the materialized zero register is dead after the
    // consumer; without this scan a live loop counter (mov Rd, #0 feeding the
    // loop-guard CMP and then used as the induction variable) is reported as a
    // false opportunity. Conservative like the NZCV scan: emit only on a proven
    // overwrite of Rd before any read or control transfer.
    bool pending_mz_active;
    unsigned pending_mz_window;
    int pending_mz_reg;
    armlint_finding pending_mz_finding;

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

    // Pending ADD Rt, Rs, #1 (immediate, no shift, non-S) awaiting an
    // adjacent CSEL reading Rt -- CSINC's else-branch is an increment,
    // so the pair folds to a single CSINC.
    bool ao_pending;
    bool ao_is_64bit;
    unsigned ao_rd;
    unsigned ao_rs;
    size_t ao_offset;
    char ao_disasm[ARMLINT_FINDING_LINE_LEN];

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

    // Pending zero-offset load/store -- a single LDR/STR or an
    // LDP/STP/LDPSW pair -- awaiting an adjacent X-form ADD-immediate
    // that self-updates the base register (Rd == Rn == the access's
    // Rn). The two fold into a single post-indexed form with the
    // ADD/SUB's byte immediate in the post-index slot. Singles use
    // the 9-bit signed slot (-256..255): ADD imm in 1..255 folds to a
    // positive writeback, SUB imm in 1..256 to a negative one. Pairs
    // (lspi_pending_is_pair, second data register in
    // lspi_pending_rt2) use the scaled 7-bit slot instead: the byte
    // amount must be a multiple of the per-register transfer size
    // with quotient 1..63 (ADD) or 1..64 (SUB). SIMD&FP accesses
    // (lspi_pending_is_fp; size is then the log2 transfer bytes,
    // 0..4 for B/H/S/D/Q singles, 2..4 for the S/D/Q pair forms) fold
    // the same way -- every such form has a post-indexed counterpart,
    // and an FP Rt can never alias the integer base.
    // lspi_pending_is_sw flags LDPSW (4-byte transfers into Xt
    // destinations). Strict adjacency: any non-matching instruction
    // expires the state.
    bool lspi_pending;
    bool lspi_pending_is_load;
    bool lspi_pending_is_fp;
    bool lspi_pending_is_pair;
    bool lspi_pending_is_sw;
    unsigned lspi_pending_size;
    unsigned lspi_pending_rn;
    unsigned lspi_pending_rt;
    unsigned lspi_pending_rt2;
    size_t lspi_pending_offset;
    char lspi_pending_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending X-form ADD-immediate self-update (Rd == Rn) awaiting an
    // adjacent zero-offset LDR/STR or LDP/STP/LDPSW whose base
    // register equals the ADD's Rd. The two fold into a single
    // pre-indexed form, the sign recorded in lspr_pending_is_sub. The
    // opener admits any imm up to the largest pair writeback (1008
    // for ADD / 1024 for SUB, the Q-pair limits); the close re-checks
    // the consumer's actual slot -- 9-bit signed for singles (ADD
    // 1..255 / SUB 1..256), scaled 7-bit for pairs (a multiple of the
    // transfer size, quotient 1..63 / 1..64). Distinct from
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

    // Pending zeroing MOVI (an all-zero vector in simd_zero_reg) awaiting
    // an adjacent SIMD compare against it. The compare must overwrite the
    // zero register (Vd == simd_zero_reg), proving the zero is dead, so the
    // pair folds to the compare-with-#0 form and the MOVI is dropped.
    bool simd_zero_active;
    unsigned simd_zero_reg;
    size_t simd_zero_offset;
    char simd_zero_disasm[ARMLINT_FINDING_LINE_LEN];

    // Power-of-two remainder pending: a MOV chain materialising 2^N
    // consumed as a UDIV's divisor, awaiting the adjacent MSUB that
    // computes dividend - quotient*2^N -- the unsigned remainder,
    // which a single AND with 2^N - 1 produces. rem_finding carries
    // the chain and UDIV lines pre-rendered (the chain state is gone
    // by the time the MSUB arrives); rem_lines is the next free line.
    bool rem_active;
    bool rem_is_64bit;
    unsigned rem_xq;        // quotient register
    unsigned rem_x8;        // constant (divisor) register
    unsigned rem_xn;        // dividend register
    unsigned rem_n;         // log2 of the divisor
    unsigned rem_lines;
    armlint_finding rem_finding;

    // The full scanned buffer, for binary-aware checks that read data
    // out of it (literal-pool chasing). Set by the driver via
    // armlint_state_set_buffer; NULL when unavailable, which disables
    // those checks.
    const uint8_t *buf;
    size_t buf_len;

    // Pending ADR awaiting an adjacent single use of the materialised
    // address: a zero-offset load through it (foldable to LDR
    // (literal)) or a BR of it (foldable to a direct B). adf_target
    // is the ADR's byte target relative to the scan base; it may lie
    // outside the buffer -- the fold never reads the pointed-to data.
    bool adf_active;
    unsigned adf_rd;
    int64_t adf_target;
    size_t adf_offset;
    char adf_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending scalar FMUL (S or D) awaiting an adjacent in-place FNEG
    // of its destination -- the pair is FNMUL, whose pseudocode
    // applies FPNeg to the already-rounded FPMul product, exactly
    // what the two-instruction spelling computes. fmn_type is the
    // ftype field (0 = S, 1 = D).
    bool fmn_active;
    unsigned fmn_type;
    unsigned fmn_rd;
    unsigned fmn_rn;
    unsigned fmn_rm;
    size_t fmn_offset;
    char fmn_disasm[ARMLINT_FINDING_LINE_LEN];

    // Pending unsigned-offset LDR W/X awaiting an adjacent
    // width-matched SCVTF/UCVTF of the loaded register: the pair
    // routes an int-to-FP conversion through a GPR when loading into
    // the FP register and converting in-SIMD performs the identical
    // conversion without the cross-register-file transfer.
    bool lcv_active;
    bool lcv_is_64bit;
    unsigned lcv_rt;
    unsigned lcv_rn;
    unsigned lcv_imm12;
    size_t lcv_offset;
    char lcv_disasm[ARMLINT_FINDING_LINE_LEN];
};

#define LIVENESS_WINDOW 16

armlint_state *armlint_state_create(void)
{
    armlint_state *s = calloc(1, sizeof(*s));
    return s;
}

void armlint_state_set_buffer(armlint_state *state, const uint8_t *buf,
                              size_t len)
{
    state->buf = buf;
    state->buf_len = len;
}

void armlint_state_set_features(armlint_state *state, unsigned features)
{
    state->features = features;
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
    state->tbf_active = false;
    state->pending_tb_active = false;
    state->cset_active = false;
    state->xtc_active = false;
    state->wzx_active = false;
    state->sxt_active = false;
    state->sv_active = false;
    state->sv_cmp_active = false;
    state->zs_active = false;
    state->zs_cmp_active = false;
    state->scp_sub_active = false;
    state->scp_cmp_active = false;
    state->rcs_active = false;
    state->pending_active = false;
    state->pending_sv_active = false;
    state->pending_zs_active = false;
    state->pending_mz_active = false;
    state->adr_recent = false;
    state->bfx_clear_seen = false;
    state->bfx_isolate_seen = false;
    state->lsp_active = false;
    state->mul_pending = false;
    state->wmul_pending = false;
    state->neg_pending = false;
    state->mvn_pending = false;
    state->ao_pending = false;
    state->ext_pending = false;
    state->sxl_pending = false;
    state->lsx_active = false;
    state->add_pending = false;
    state->addi_pending = false;
    state->lspi_pending = false;
    state->lspr_pending = false;
    state->simd_zero_active = false;
    state->rem_active = false;
    state->fmn_active = false;
    state->lcv_active = false;
    state->adf_active = false;
    state->cmx_active = false;
    state->cab_active = false;
    state->rbc_active = false;
    state->pending_cssc_active = false;
    state->pending_fp_active = false;
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
static bool defer_dead_mov(armlint_state *state, const armlint_finding *out,
                           unsigned reg);
static void format_reg(char *buf, size_t bufsz, char w_or_x, unsigned reg);
static bool decode_cvtf_from_gpr(uint32_t op, bool *out_src_64,
                                 bool *out_is_double,
                                 bool *out_is_unsigned,
                                 unsigned *out_rn, unsigned *out_rd);
static bool decode_ldr_uimm_any_size(uint32_t op, unsigned *out_size,
                                     unsigned *out_imm12,
                                     unsigned *out_rn, unsigned *out_rt);
static bool fp8_encodable(uint64_t bits, bool is_double);
static void format_fp8(char *buf, size_t bufsz, double v);
static bool decode_ldrsw_uimm(uint32_t op, unsigned *out_imm12,
                              unsigned *out_rn, unsigned *out_rt);
static bool decode_fp_ldr_str_uimm(uint32_t op, bool *out_is_load,
                                   unsigned *out_lg2size,
                                   unsigned *out_imm12,
                                   unsigned *out_rn, unsigned *out_rt);

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
    //     of the pending shift? The rewrite deletes the shift, so its
    //     destination must be dead afterward: a consumer that
    //     overwrites it proves that on the spot, and one writing a
    //     fresh register defers through the forward register-liveness
    //     scan. Rd = 31 consumers are excluded -- the non-S forms are
    //     dead writes, and the S forms are the CMP/CMN/TST aliases,
    //     whose rendering is a separate concern.
    if (state->shf_active) {
        unsigned c_sf, c_rd, c_rn, c_rm;
        const char *c_mnem;
        bool c_commutes, c_is_arith;
        if (decode_shifted_register_consumer(op, &c_sf, &c_rd, &c_rn, &c_rm,
                                             &c_mnem, &c_commutes,
                                             &c_is_arith)
                && c_sf == (state->shf_is_64bit ? 1u : 0u)
                && c_rd != 31
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
            // An XZR surviving operand is a degenerate consumer -- a
            // register copy (ORR from ZR is the MOV alias) or a
            // constant shape, not an op the shift rides into -- and
            // the rewrite would render register 31 as an operand.
            if (foldable && indep == 31) {
                foldable = false;
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

                if (c_rd == state->shf_rd) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, state->shf_rd);
                }
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

// Decode the funnel-shift consumer for check_funnel_to_extr: a
// shifted-register ADD, ORR or EOR (non-flag-setting) whose Rm carries a
// non-zero LSL or LSR. Only these three ops qualify -- in a funnel the two
// shifted fields are bit-disjoint, so ADD, ORR and EOR all agree with EXTR
// -- and only LSL/LSR shift types (ASR would sign-fill into the other
// field; ROR is not a funnel). SUB and the flag-setting / other logical
// forms are rejected. Fills the operand fields and the canonical mnemonic.
static bool decode_funnel_consumer(uint32_t op, unsigned *out_sf,
                                   unsigned *out_rd, unsigned *out_rn,
                                   unsigned *out_rm, unsigned *out_shift_type,
                                   unsigned *out_shift_amt,
                                   const char **out_mnem)
{
    bool is_arith = (op & 0x1f200000u) == 0x0b000000u;
    bool is_logic = (op & 0x1f000000u) == 0x0a000000u;
    if (!is_arith && !is_logic) {
        return false;
    }

    // Only LSL (0) and LSR (1) reconstruct a funnel.
    unsigned shift_type = (op >> 22) & 0x3u;
    if (shift_type != 0u && shift_type != 1u) {
        return false;
    }
    // A funnel consumer must carry a real inline shift.
    unsigned imm6 = (op >> 10) & 0x3fu;
    if (imm6 == 0u) {
        return false;
    }
    unsigned sf = (op >> 31) & 0x1u;
    if (!sf && imm6 >= 32u) {
        return false;
    }

    const char *mnem;
    if (is_arith) {
        // Require plain ADD: bits 30..29 (op|S) == 00. Reject SUB/ADDS/SUBS.
        if (((op >> 29) & 0x3u) != 0u) {
            return false;
        }
        mnem = "add";
    } else {
        // Logical: require N == 0 and opc ORR (01) or EOR (10). Reject
        // AND/ANDS and the N=1 inverted forms BIC/ORN/EON/BICS.
        if (((op >> 21) & 0x1u) != 0u) {
            return false;
        }
        unsigned opc = (op >> 29) & 0x3u;
        if (opc == 1u) {
            mnem = "orr";
        } else if (opc == 2u) {
            mnem = "eor";
        } else {
            return false;
        }
    }

    *out_sf = sf;
    *out_rd = op & 0x1fu;
    *out_rn = (op >> 5) & 0x1fu;
    *out_rm = (op >> 16) & 0x1fu;
    *out_shift_type = shift_type;
    *out_shift_amt = imm6;
    *out_mnem = mnem;
    return true;
}

bool check_funnel_to_extr(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->fnl_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: is this a complementary shifted-register funnel consumer
    //     of the pending shift? The rewrite deletes the shift, so its
    //     destination must be dead afterward: a consumer that
    //     overwrites it proves that on the spot, and one writing a
    //     fresh register defers through the forward register-liveness
    //     scan (Rd = 31 is a dead write and excluded).
    if (state->fnl_active) {
        unsigned c_sf, c_rd, c_rn, c_rm, c_stype, c_samt;
        const char *c_mnem;
        unsigned datasize = state->fnl_is_64bit ? 64u : 32u;
        if (decode_funnel_consumer(op, &c_sf, &c_rd, &c_rn, &c_rm, &c_stype,
                                   &c_samt, &c_mnem)
                && c_sf == (state->fnl_is_64bit ? 1u : 0u)
                // Rn is the shift result (the plain funnel operand).
                && c_rn == state->fnl_rd
                && c_rd != 31u
                // The inline-shifted source must be a different register --
                // the shift wrote fnl_rd, so if Rm were fnl_rd the funnel
                // would read the shifted value instead of the original.
                && c_rm != state->fnl_rd
                && c_rm != 31u
                // Opposite shift directions (one LSL, one LSR)...
                && (state->fnl_is_lsr ? (c_stype == 0u) : (c_stype == 1u))
                // ...with amounts summing to the register width.
                && state->fnl_shift + c_samt == datasize) {
            // The right-shifted (LSR) source is the funnel's low half, the
            // left-shifted (LSL) source its high half; EXTR's lsb is the
            // right-shift amount. Whichever operand the pending shift holds
            // is decided by its direction.
            unsigned left_reg, right_reg, lsb;
            if (state->fnl_is_lsr) {
                right_reg = state->fnl_rn;   // pending LSR: Ra is the low half
                left_reg = c_rm;
                lsb = state->fnl_shift;
            } else {
                left_reg = state->fnl_rn;    // pending LSL: Ra is the high half
                right_reg = c_rm;
                lsb = c_samt;
            }
            // Same source in both halves is a rotate -> ROR.
            bool is_ror = (left_reg == right_reg);
            char wx = state->fnl_is_64bit ? 'x' : 'w';
            const char *sh0 = state->fnl_is_lsr ? "lsr" : "lsl";
            const char *sh1 = shift_type_name[c_stype];

            out->name = is_ror
                ? "shift + shifted OR/EOR/ADD foldable into ROR"
                : "shift + shifted OR/EOR/ADD foldable into EXTR";
            out->start_offset = state->fnl_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            if (is_ror) {
                snprintf(out->detail, sizeof(out->detail),
                    "-> ror %c%u, %c%u, #%u",
                    wx, c_rd, wx, left_reg, lsb);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> extr %c%u, %c%u, %c%u, #%u",
                    wx, c_rd, wx, left_reg, wx, right_reg, lsb);
            }
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s %c%u, %c%u, #%u",
                sh0, wx, state->fnl_rd, wx, state->fnl_rn, state->fnl_shift);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %c%u, %c%u, %c%u, %s #%u",
                c_mnem, wx, c_rd, wx, c_rn, wx, c_rm, sh1, c_samt);

            if (c_rd == state->fnl_rd) {
                produced = true;
            } else {
                defer_dead_mov(state, out, state->fnl_rd);
            }
        }
        // Strict adjacency: the pending shift expires after one instruction.
        state->fnl_active = false;
    }

    // (2) Open: is this a plain immediate LSL or LSR into a real register?
    unsigned sf, rd, rn, shift;
    bool is_lsr = false;
    bool opened = false;
    if (decode_lsl_imm(op, &sf, &rd, &rn, &shift)) {
        is_lsr = false;
        opened = true;
    } else if (decode_lsr_imm(op, &sf, &rd, &rn, &shift)) {
        is_lsr = true;
        opened = true;
    }
    // Skip degenerate shifts: writing XZR is pointless, and shifting XZR
    // (Ra == 31) yields a zero field, not a meaningful funnel operand.
    if (opened && rd != 31u && rn != 31u) {
        state->fnl_active = true;
        state->fnl_is_64bit = (sf != 0u);
        state->fnl_is_lsr = is_lsr;
        state->fnl_rd = rd;
        state->fnl_rn = rn;
        state->fnl_shift = shift;
        state->fnl_offset = offset;
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

// Decode a zero-extension that keeps a low field of `width` bits, the
// producer side of the UXT*/MOV + LSL => UBFIZ fold. Four spellings
// qualify, each equivalent to placing "Rn & ((1 << width) - 1)" in the
// destination with the bits above cleared:
//
//   UXTB Wd, Wn  = UBFM Wd, Wn, #0, #7    width 8,  32-bit result
//   UXTH Wd, Wn  = UBFM Wd, Wn, #0, #15   width 16, 32-bit result
//   UXTW Xd, Wn  = UBFM Xd, Xn, #0, #31   width 32, 64-bit result
//   MOV  Wd, Wn  = ORR  Wd, WZR, Wn       width 32, 64-bit result
//
// Writing any W register zeros bits 63..32, so the MOV form zero-extends
// the low 32 bits exactly like UXTW; the UBFIZ it feeds therefore works in
// the 64-bit (X) domain, hence *out_is_64bit is true for both. *out_is_64bit
// is the width of the consuming LSL and the emitted UBFIZ (which equals the
// producer's result width). The source is Rn (bits 9..5) for the UBFM forms
// but Rm (bits 20..16) for the MOV form, whose Rn is fixed to WZR. Rd=31 is
// rejected for every form; the MOV form also rejects a WZR source (MOV Wd,
// WZR is a zeroing idiom, not a zero-extension).
static bool decode_zext_field_producer(uint32_t op, unsigned *out_width,
                                       bool *out_is_64bit, unsigned *out_rd,
                                       unsigned *out_rn)
{
    unsigned rd = op & 0x1Fu;
    if (rd == 31) {
        return false;
    }
    unsigned src;
    switch (op & 0xFFFFFC00u) {
    case 0x53001C00u:                       // UXTB Wd, Wn
        *out_width = 8;  *out_is_64bit = false;
        src = (op >> 5) & 0x1Fu;
        break;
    case 0x53003C00u:                       // UXTH Wd, Wn
        *out_width = 16; *out_is_64bit = false;
        src = (op >> 5) & 0x1Fu;
        break;
    case 0xD3407C00u:                       // UXTW Xd, Wn
        *out_width = 32; *out_is_64bit = true;
        src = (op >> 5) & 0x1Fu;
        break;
    default:
        // MOV Wd, Wn = ORR Wd, WZR, Wn, LSL #0 (Rn = WZR fixed by the
        // match value); the source register is Rm.
        if ((op & 0xFFE0FFE0u) != 0x2A0003E0u) {
            return false;
        }
        src = (op >> 16) & 0x1Fu;
        if (src == 31) {
            return false;
        }
        *out_width = 32; *out_is_64bit = true;
        break;
    }
    *out_rd = rd;
    *out_rn = src;
    return true;
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
                out->name = state->aul_zext
                    ? "zero-extend + LSL foldable into UBFIZ"
                    : "AND+LSL foldable into UBFIZ";
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

    // (2) Open: an AND with a low mask, a zero-extension (UXT*/MOV), or an
    //     LSR (Rd != XZR)?
    unsigned w_width, a_rd, a_rn;
    bool zext_is_64bit;
    if (decode_and_imm_lowmask(op, &w_width, &a_rd, &a_rn) && a_rd != 31) {
        state->aul_active = true;
        state->aul_is_64bit = (((op >> 31) & 1u) != 0u);
        state->aul_is_lsr = false;
        state->aul_zext = false;
        state->aul_rd = a_rd;
        state->aul_rn = a_rn;
        state->aul_param = w_width;
        state->aul_offset = offset;
        snprintf(state->aul_disasm, sizeof(state->aul_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    } else if (decode_zext_field_producer(op, &w_width, &zext_is_64bit,
                                          &a_rd, &a_rn)) {
        // A UXTB/UXTH/UXTW or W-form MOV keeps the low w bits with the rest
        // zeroed -- the same field-then-shift shape as AND #(2^w-1), so it
        // folds to UBFIZ identically. The field width is fixed by the
        // extension; the rewrite's width follows the closing LSL.
        state->aul_active = true;
        state->aul_is_64bit = zext_is_64bit;
        state->aul_is_lsr = false;
        state->aul_zext = true;
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
            state->aul_zext = false;
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
// usable only for an equality-with-zero branch. Five encodings count:
//
//   CMP Rn, #0     = SUBS X/WZR, Rn, #0       (immediate; sh=0, imm12=0)
//   CMP Rn, X/WZR  = SUBS X/WZR, Rn, X/WZR    (shifted-reg; Rm=31,
//                                              shift=LSL, imm6=0)
//   CMN Rn, #0     = ADDS X/WZR, Rn, #0       (immediate; sh=0, imm12=0)
//   CMN Rn, X/WZR  = ADDS X/WZR, Rn, X/WZR    (shifted-reg; Rm=31,
//                                              shift=LSL, imm6=0)
//   TST Rn, Rn     = ANDS X/WZR, Rn, Rn       (logical shifted-reg;
//                                              Rm=Rn, shift=LSL, N=0,
//                                              imm6=0)
//
// All five have Rd=31 and leave Z = (Rn == 0), N = sign(Rn), V = 0
// (adding or subtracting zero never overflows). Bit 31 (sf) is left
// free so either operand width matches; for the TST form Rm and Rn
// must agree, which is verified after the mask check.
//
// The forms differ in the carry they leave: the SUBS-based CMPs set
// C = 1 (subtracting zero never borrows), which makes the unsigned
// HI/LS conditions reduce to NE/EQ; the ANDS-based TST and the
// ADDS-based CMNs clear C (adding zero never carries), where HI is
// never taken and LS always. *out_is_subs reports which family
// matched so the caller can gate the HI/LS fold.
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
    // CMN Rn, #0 (ADDS-imm with Rd=31, sh=0, imm12=0).
    if ((op & 0x7FFFFC1Fu) == 0x3100001Fu) {
        *out_sf = (op >> 31) & 1u;
        *out_rn = (op >> 5) & 0x1Fu;
        *out_is_subs = false;
        return true;
    }
    // CMN Rn, XZR/WZR (ADDS shifted-reg with Rd=31, Rm=31, shift=LSL,
    // imm6=0).
    if ((op & 0x7FFFFC1Fu) == 0x2B1F001Fu) {
        *out_sf = (op >> 31) & 1u;
        *out_rn = (op >> 5) & 0x1Fu;
        *out_is_subs = false;
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

// Classify `op` for the NZCV liveness scan (liveness_t is declared in
// armlint.h). Conservative on both ends: instructions we don't recognize
// are LIV_UNKNOWN (keep scanning until the window expires), and ambiguous
// reads/writes are erred toward LIV_READ. See the header note on why this
// is hand-rolled rather than taken from Capstone's register-access model.
liveness_t classify_liveness(uint32_t op)
{
    // B.cond reads NZCV (which flags depend on cond). BC.cond (the
    // Armv8.8 consistent conditional branch) shares the encoding with
    // bit 4 = 1 and also reads NZCV, so match bits 31..24 = 0x54 with
    // bit 4 free to catch both.
    if ((op & 0xFF000000u) == 0x54000000u) {
        return LIV_READ;
    }
    // CFINV (Armv8.4) inverts C; XAFLAG/AXFLAG (Armv8.5) rewrite NZCV
    // from the prior flags. All three read the condition flags and share
    // the flag-manipulation MSR-immediate encoding (CRm = 0, Rt = 31),
    // differing only in op2 (bits 7..5); the mask leaves op2 free so all
    // are caught (unallocated op2 values conservatively too). DAIFSet/
    // DAIFClr/SPSel have a different CRm and are excluded.
    if ((op & 0xFFFFFF1Fu) == 0xD500401Fu) {
        return LIV_READ;
    }
    // MRS Xt, NZCV reads the condition flags into a GPR (system register
    // S3_3_C4_C2_0; the mask fixes everything but Rt). Without this a
    // CMP+B.cond -> CBZ fold could drop flags that a later MRS observes.
    if ((op & 0xFFFFFFE0u) == 0xD53B4200u) {
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
    // CBZ/CBNZ and TBZ/TBNZ: conditional branches that do not touch NZCV
    // themselves, but whose taken edge leaves this straight-line run for a
    // target the scan does not follow. The flags may still be live there
    // (the branch does not overwrite them), so treat them as unsafe
    // terminators rather than LIV_UNKNOWN -- otherwise a later overwrite on
    // the fall-through could wrongly prove the flags dead while the taken
    // target still observes them. (classify_reg_liveness stops here too.)
    if ((op & 0x7E000000u) == 0x34000000u) {   // CBZ / CBNZ
        return LIV_TERM_UNSAFE;
    }
    if ((op & 0x7E000000u) == 0x36000000u) {   // TBZ / TBNZ
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

// Map a Capstone AArch64 register operand to its 0..30 GPR encoding number,
// or -1 for the zero register, SP, and non-GPRs (which carry no tracked
// value). W0..W30 and X0..X28 are contiguous in the Capstone enum; X29/X30 are
// the FP/LR aliases.
static int arm64_gpr_num(unsigned reg)
{
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
        return (int)(reg - ARM64_REG_W0);
    }
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        return (int)(reg - ARM64_REG_X0);
    }
    if (reg == ARM64_REG_FP) {
        return 29;
    }
    if (reg == ARM64_REG_LR) {
        return 30;
    }
    return -1;
}

// True for the A64 GPR-writing instructions that also READ their
// destination: MOVK (opc 11 of the move-wide class, inserting into the
// untouched halfwords) and BFM proper (opc 01 of the bitfield class --
// the BFI/BFXIL aliases, preserving bits of Rd). Every other member of
// both classes (MOVZ/MOVN; SBFM/UBFM and all their shift, extract and
// extend aliases) fully overwrites Rd. Capstone's operand access flags
// cannot make this distinction -- it marks whole classes read+write --
// so the raw encoding is the arbiter.
static bool insn_reads_gpr_dest(uint32_t op)
{
    if ((op & 0x1F800000u) == 0x12800000u) {
        return ((op >> 29) & 0x3u) == 3u;       // MOVK
    }
    if ((op & 0x1F800000u) == 0x13000000u) {
        return ((op >> 29) & 0x3u) == 1u;       // BFM (BFI/BFXIL)
    }
    return false;
}

// Determine whether `insn` reads and/or writes GPR `reg` (a 0..30 encoding
// number), from the Capstone detail: explicit operand access flags, memory
// base/index registers (always reads), and the implicit register lists. With
// no detail available, conservatively assume the register is read.
static void insn_reg_access(const cs_insn *insn, int reg,
                            bool *reads, bool *writes)
{
    *reads = false;
    *writes = false;
    uint32_t op = insn->size == 4 ? insn_word(insn) : 0;
    const cs_detail *detail = insn->detail;
    if (detail == NULL) {
        *reads = true;
        return;
    }
    const cs_arm64 *a = &detail->arm64;
    for (int i = 0; i < a->op_count; i++) {
        const cs_arm64_op *o = &a->operands[i];
        if (o->type == ARM64_OP_REG) {
            if (arm64_gpr_num(o->reg) == reg) {
                // Capstone marks entire encoding classes' destinations
                // read+write: the genuine read-modify-writes (MOVK, BFM)
                // but also the pure overwrites sharing their class (the
                // UBFM/SBFM shift and extract aliases fully replace Rd).
                // Honor the read flag on a written operand only when the
                // raw encoding says the instruction really reads its
                // destination, so an RMW keeps the register live -- a
                // deleted producer would change its result -- while real
                // kills stay kills.
                if (o->access & CS_AC_WRITE) {
                    *writes = true;
                    if (insn_reads_gpr_dest(op)) {
                        *reads = true;
                    }
                } else if (o->access & CS_AC_READ) {
                    *reads = true;
                }
            }
        } else if (o->type == ARM64_OP_MEM) {
            if (arm64_gpr_num(o->mem.base) == reg
                    || arm64_gpr_num(o->mem.index) == reg) {
                *reads = true;
            }
        }
    }
    for (uint8_t i = 0; i < detail->regs_read_count; i++) {
        if (arm64_gpr_num(detail->regs_read[i]) == reg) {
            *reads = true;
        }
    }
    for (uint8_t i = 0; i < detail->regs_write_count; i++) {
        if (arm64_gpr_num(detail->regs_write[i]) == reg) {
            *writes = true;
        }
    }

    // Capstone reports NO access flags on the register operands of the
    // atomic read-modify-write memory instructions, leaving them
    // invisible to the loops above -- but an atomic touching the
    // watched register must stop a liveness scan. Recover the
    // registers from the raw encoding and claim conservative reads:
    // Rs is genuinely read; Rt receives the loaded value, and claiming
    // a read for it too merely stops the scan (it is never treated as
    // a kill). ZR fields (the ST<op> aliases' Rt) never match a
    // watched register, which is always 0..30.
    if ((op & 0x3F200C00u) == 0x38200000u) {
        // Atomic memory operations: LDADD..LDUMIN, SWP, LDAPR
        //   size 111000 A R 1 Rs o3 opc 00 Rn Rt
        if ((int)((op >> 16) & 0x1Fu) == reg
                || (int)(op & 0x1Fu) == reg) {
            *reads = true;
        }
    } else if ((op & 0x3FA07C00u) == 0x08A07C00u) {
        // CAS[A][L][B/H]: size 001000 1 L 1 Rs o0 11111 Rn Rt.
        if ((int)((op >> 16) & 0x1Fu) == reg
                || (int)(op & 0x1Fu) == reg) {
            *reads = true;
        }
    } else if ((op & 0xBFA07C00u) == 0x08207C00u) {
        // CASP[A][L]: Rs and Rt each name an even/odd register pair.
        unsigned rs = (op >> 16) & 0x1Fu;
        unsigned rt = op & 0x1Fu;
        if ((int)rs == reg || (int)(rs + 1u) == reg
                || (int)rt == reg || (int)(rt + 1u) == reg) {
            *reads = true;
        }
    }
}

// Register-liveness classification for the MOV #0 forward scan, parallel to
// classify_liveness for NZCV. A read of the zero register means it is live, so
// dropping the MOV would change behavior (LIV_READ). A write with no prior
// read means it is dead from here (LIV_OVERWRITE). Any branch, call, or return
// leaves straight-line code -- the register may be live at the target or be a
// return value -- so stop conservatively (LIV_TERM_UNSAFE).
static liveness_t classify_reg_liveness(const cs_insn *insn, int reg)
{
    uint32_t op = insn_word(insn);
    // Control transfers: B.cond, B/BL, CBZ/CBNZ, TBZ/TBNZ, BR/BLR/RET.
    if ((op & 0xFF000010u) == 0x54000000u
            || (op & 0x7C000000u) == 0x14000000u
            || (op & 0x7E000000u) == 0x34000000u
            || (op & 0x7E000000u) == 0x36000000u
            || (op & 0xFE000000u) == 0xD6000000u) {
        return LIV_TERM_UNSAFE;
    }
    bool reads, writes;
    insn_reg_access(insn, reg, &reads, &writes);
    if (reads) {
        return LIV_READ;
    }
    if (writes) {
        return LIV_OVERWRITE;
    }
    return LIV_UNKNOWN;
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

bool armlint_advance_pending_zs(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        state->pending_zs_active = false;
        return false;
    }
    uint32_t op = insn_word(insn);
    return advance_one_pending(op, &state->pending_zs_active,
                               &state->pending_zs_window,
                               &state->pending_zs_finding, out);
}

bool armlint_advance_pending_cssc(armlint_state *state,
                                  const cs_insn *insn,
                                  size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        state->pending_cssc_active = false;
        return false;
    }
    uint32_t op = insn_word(insn);
    return advance_one_pending(op, &state->pending_cssc_active,
                               &state->pending_cssc_window,
                               &state->pending_cssc_finding, out);
}

// Stash a CSSC finding whose rewrite deletes the compare, pending
// proof that NZCV is dead afterward (armlint_advance_pending_cssc).
// classify_liveness is exactly right here: the rewrite sets no flags
// at all, so ANY later flag reader -- even B.EQ -- must discard.
static bool defer_dead_nzcv_cssc(armlint_state *state,
                                 const armlint_finding *out)
{
    state->pending_cssc_finding = *out;
    state->pending_cssc_active = true;
    state->pending_cssc_window = LIVENESS_WINDOW;
    return false;
}

// Forward register-liveness scan for a deferred MOV #0 + use finding. Emits the
// stashed finding only once a later instruction provably overwrites the zero
// register before any read or control transfer; a read or branch/call/return
// (or window expiry) discards it -- the MOV is needed and dropping it would
// save nothing.
bool armlint_advance_pending_mz(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out)
{
    (void)offset;
    if (!state->pending_mz_active) {
        return false;
    }
    if (insn->size != 4) {
        state->pending_mz_active = false;
        return false;
    }
    switch (classify_reg_liveness(insn, state->pending_mz_reg)) {
    case LIV_OVERWRITE:
        *out = state->pending_mz_finding;
        state->pending_mz_active = false;
        return true;
    case LIV_READ:
    case LIV_TERM_SAFE:
    case LIV_TERM_UNSAFE:
        state->pending_mz_active = false;
        return false;
    case LIV_UNKNOWN:
        if (state->pending_mz_window == 0 || --state->pending_mz_window == 0) {
            state->pending_mz_active = false;
        }
        return false;
    }
    return false;
}

// Stash *out as a deferred finding whose emission is gated on `reg` --
// a register produced by an instruction the finding proposes to delete
// -- being dead afterward. Such a fold only saves an instruction once a
// later instruction overwrites `reg` before any read or control
// transfer; armlint_advance_pending_mz runs that forward scan and emits
// the stashed finding then. Returns false so the caller records nothing
// now. Shared by every fold that deletes the producer of `reg`: the
// MOV-chain folds (strength reductions, immediate/offset/FMOV folds,
// MOV #0 -> ZR), the BFXIL/BFI synthesis (which drops the isolate's
// temp register), the CSET inversion folds (EOR #1 / NEG), the
// ADD/SXTW address folds' store and fresh-destination load consumers
// (which drop the address computation), and the producer folds'
// (shift, funnel, extend, MUL/SMULL, NEG, MVN) fresh-destination
// consumers. One slot: a second deferral arriving while one is
// pending replaces it, silently dropping the earlier finding -- a
// sound (false-negative-only) simplification.
static bool defer_dead_mov(armlint_state *state, const armlint_finding *out,
                           unsigned reg)
{
    state->pending_mz_finding = *out;
    state->pending_mz_active = true;
    state->pending_mz_window = LIVENESS_WINDOW;
    state->pending_mz_reg = (int)reg;
    return false;
}

// Map a Capstone AArch64 register operand to its 0..31 vector register
// number, or -1 for non-vector registers. All six views of the same
// architectural register -- B, H, S, D, Q and the V vector spelling --
// map to one number: a read or write through any view touches the one
// register. Each bank is contiguous in the Capstone enum.
static int arm64_vreg_num(unsigned reg)
{
    if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        return (int)(reg - ARM64_REG_B0);
    }
    if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        return (int)(reg - ARM64_REG_H0);
    }
    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        return (int)(reg - ARM64_REG_S0);
    }
    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        return (int)(reg - ARM64_REG_D0);
    }
    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        return (int)(reg - ARM64_REG_Q0);
    }
    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        return (int)(reg - ARM64_REG_V0);
    }
    return -1;
}

// True for instruction classes whose vector-register DESTINATION is a
// full pure overwrite. The FP world inverts the GPR arbiter's default:
// where GPR read-modify-writers are two enumerable encodings (MOVK,
// BFM), vector RMW writers are everywhere -- accumulators (FMLA, MLA,
// SDOT), lane inserts (INS), bitwise selects (BSL/BIT/BIF), shift
// inserts (SLI/SRI), the vector ORR/BIC immediates sharing MOVI's
// class, the *2 narrowing-high forms -- so a written vector operand is
// treated as ALSO READ unless its class is on this whitelist. Sound in
// the false-negative direction only: an unlisted pure overwrite merely
// fails to commit a deferred finding.
//
//   - FP data processing, scalar (0x1E class, bit 21 set): 1-source
//     (FMOV/FABS/FNEG/FSQRT/FCVT), 2-source (FADD..FDIV, FNMUL),
//     conditional select, immediate, and the GPR<->FP conversions.
//     All write the full vector register, zeroing above the lane.
//   - FP data processing, 3-source (0x1F class): FMADD..FNMSUB. The
//     accumulator is a separate source operand (Ra), not the
//     destination, so Rd is a pure write (Rd == Ra aliasing arrives
//     as a read of Ra and stops the scan anyway).
//   - SIMD&FP loads: unsigned-offset, the other addressing modes,
//     the literal form, and LDP. Loads replace the register.
static bool insn_overwrites_vreg_dest(uint32_t op)
{
    if ((op & 0x5F200000u) == 0x1E200000u) {
        return true;    // FP scalar data processing + conversions
    }
    if ((op & 0x5F000000u) == 0x1F000000u) {
        return true;    // FP scalar 3-source
    }
    if ((op & 0x3F000000u) == 0x3D000000u) {
        return true;    // SIMD&FP LDR/STR, unsigned offset
    }
    if ((op & 0x3F200000u) == 0x3C000000u) {
        return true;    // SIMD&FP LDUR/LDR pre/post/register-offset
    }
    if ((op & 0x3B000000u) == 0x18000000u && (op & (1u << 26)) != 0) {
        return true;    // SIMD&FP LDR (literal)
    }
    if ((op & 0x3A000000u) == 0x28000000u && (op & (1u << 26)) != 0) {
        return true;    // SIMD&FP LDP/STP (all addressing modes)
    }
    return false;
}

// Determine whether `insn` reads and/or writes vector register `reg`
// (0..31), from the Capstone detail. Parallel to insn_reg_access with
// the written-operand default inverted: see insn_overwrites_vreg_dest.
// With no detail available, conservatively assume a read.
static void insn_vreg_access(const cs_insn *insn, int reg,
                             bool *reads, bool *writes)
{
    *reads = false;
    *writes = false;
    uint32_t op = insn->size == 4 ? insn_word(insn) : 0;
    const cs_detail *detail = insn->detail;
    if (detail == NULL) {
        *reads = true;
        return;
    }
    const cs_arm64 *a = &detail->arm64;
    for (int i = 0; i < a->op_count; i++) {
        const cs_arm64_op *o = &a->operands[i];
        if (o->type != ARM64_OP_REG) {
            continue;
        }
        if (arm64_vreg_num(o->reg) != reg) {
            continue;
        }
        if (o->access & CS_AC_WRITE) {
            *writes = true;
            if (!insn_overwrites_vreg_dest(op)) {
                *reads = true;
            }
        }
        if (o->access & CS_AC_READ) {
            *reads = true;
        }
    }
    for (uint8_t i = 0; i < detail->regs_read_count; i++) {
        if (arm64_vreg_num(detail->regs_read[i]) == reg) {
            *reads = true;
        }
    }
    for (uint8_t i = 0; i < detail->regs_write_count; i++) {
        if (arm64_vreg_num(detail->regs_write[i]) == reg) {
            *writes = true;
            if (!insn_overwrites_vreg_dest(op)) {
                *reads = true;
            }
        }
    }
}

// Vector-register liveness classification, parallel to
// classify_reg_liveness. Any control transfer stops the scan
// conservatively; a read keeps the register live; a whitelisted full
// overwrite kills it.
static liveness_t classify_fpreg_liveness(const cs_insn *insn, int reg)
{
    uint32_t op = insn_word(insn);
    if ((op & 0xFF000010u) == 0x54000000u
            || (op & 0x7C000000u) == 0x14000000u
            || (op & 0x7E000000u) == 0x34000000u
            || (op & 0x7E000000u) == 0x36000000u
            || (op & 0xFE000000u) == 0xD6000000u) {
        return LIV_TERM_UNSAFE;
    }
    bool reads, writes;
    insn_vreg_access(insn, reg, &reads, &writes);
    if (reads) {
        return LIV_READ;
    }
    if (writes) {
        return LIV_OVERWRITE;
    }
    return LIV_UNKNOWN;
}

// Forward vector-register liveness scan for a deferred finding whose
// rewrite deletes the producer of an FP/vector temporary, parallel to
// armlint_advance_pending_mz.
bool armlint_advance_pending_fp(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out)
{
    (void)offset;
    if (!state->pending_fp_active) {
        return false;
    }
    if (insn->size != 4) {
        state->pending_fp_active = false;
        return false;
    }
    switch (classify_fpreg_liveness(insn, state->pending_fp_reg)) {
    case LIV_OVERWRITE:
        *out = state->pending_fp_finding;
        state->pending_fp_active = false;
        return true;
    case LIV_READ:
    case LIV_TERM_SAFE:
    case LIV_TERM_UNSAFE:
        state->pending_fp_active = false;
        return false;
    case LIV_UNKNOWN:
        if (state->pending_fp_window == 0 || --state->pending_fp_window == 0) {
            state->pending_fp_active = false;
        }
        return false;
    }
    return false;
}

// Stash *out as a deferred finding gated on vector register `reg`
// being dead afterward -- the FP twin of defer_dead_mov, with the same
// single-slot semantics.
static bool defer_dead_fpreg(armlint_state *state,
                             const armlint_finding *out, unsigned reg)
{
    state->pending_fp_finding = *out;
    state->pending_fp_active = true;
    state->pending_fp_window = LIVENESS_WINDOW;
    state->pending_fp_reg = (int)reg;
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

// Mirror of decode_s_variant_alu one S bit over: the non-flag-setting
// ALU forms whose S-variant twin exists -- ADD/SUB (immediate,
// shifted-register, extended-register) and AND/BIC (immediate for
// AND, shifted-register for both). Rd = 31 is rejected: it means SP
// for the immediate and extended forms (an observable write the
// S-variant would redirect to ZR) and ZR for the shifted forms (a
// dead write). ADD/SUB immediate with imm == 0 is rejected -- that is
// check_add_sub_zero's redundant-ADD shape, and its MOV-from-SP alias
// spelling must not gain an "s" suffix. ADC/SBC also have S twins but
// read the carry the surrounding code is testing; they are left out
// of this fold's v1.
static bool decode_non_s_alu(uint32_t op, unsigned *out_sf,
                             unsigned *out_rd)
{
    unsigned rd = op & 0x1Fu;
    if (rd == 31) {
        return false;
    }

    // ADD/SUB immediate: bit 29 = S = 0, bits 28..23 = 100010.
    if ((op & 0x3F800000u) == 0x11000000u) {
        if (((op >> 10) & 0xFFFu) == 0) {
            return false;
        }
        *out_sf = (op >> 31) & 1u;
        *out_rd = rd;
        return true;
    }
    // ADD/SUB shifted-register and extended-register: bit 29 = 0,
    // bits 28..24 = 01011.
    if ((op & 0x3F000000u) == 0x0B000000u) {
        *out_sf = (op >> 31) & 1u;
        *out_rd = rd;
        return true;
    }
    // AND immediate: bits 30..29 = opc = 00, bits 28..23 = 100100.
    if ((op & 0x7F800000u) == 0x12000000u) {
        *out_sf = (op >> 31) & 1u;
        *out_rd = rd;
        return true;
    }
    // AND (N=0) / BIC (N=1) shifted-register: bits 30..29 = opc = 00,
    // bits 28..24 = 01010.
    if ((op & 0x7F000000u) == 0x0A000000u) {
        *out_sf = (op >> 31) & 1u;
        *out_rd = rd;
        return true;
    }

    return false;
}

bool check_zero_cmp_to_s_variant(armlint_state *state,
                                 const cs_insn *insn,
                                 size_t offset,
                                 armlint_finding *out)
{
    (void)out;  // emission goes through armlint_advance_pending_zs

    if (insn->size != 4) {
        state->zs_active = false;
        state->zs_cmp_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Stage 3: B.EQ/B.NE consuming the alu+cmp chain? The branch
    //     reads only Z, which the S-variant sets identically to the
    //     zero-test (Z = Rd == 0); N agrees too (the sign of Rd under
    //     every zero-test spelling). C and V differ -- CMP pins C = 1,
    //     V = 0 and CMN/TST pin C = 0, V = 0, while the arithmetic
    //     S-variants compute real carry/overflow -- so emission defers
    //     through the same NZCV scan as the sibling check until they
    //     are provably unobserved. (The logical S-forms pin C = V = 0,
    //     making ANDS/BICS after TST exact; the scan is a uniform
    //     conservative superset.)
    if (state->zs_cmp_active) {
        bool is_eq;
        int32_t imm19;
        if (decode_b_eq_or_ne(op, &is_eq, &imm19)) {
            uint64_t target = insn->address
                + (uint64_t)((int64_t)imm19 * 4);
            const char *bcond_mnem = is_eq ? "b.eq" : "b.ne";

            armlint_finding *p = &state->pending_zs_finding;
            p->name = "ADD/SUB/AND/BIC + zero-CMP foldable to S-variant";
            p->start_offset = state->zs_offset;
            p->insn_count = 3;
            clear_finding_strings(p);

            snprintf(p->detail, sizeof(p->detail),
                "-> %s (drop %s)",
                state->zs_sdisasm, state->zs_cmp_disasm);
            snprintf(p->lines[0], sizeof(p->lines[0]),
                "%s", state->zs_disasm);
            snprintf(p->lines[1], sizeof(p->lines[1]),
                "%s", state->zs_cmp_disasm);
            snprintf(p->lines[2], sizeof(p->lines[2]),
                "%s 0x%" PRIx64, bcond_mnem, target);

            state->pending_zs_active = true;
            state->pending_zs_window = LIVENESS_WINDOW;
        }
        state->zs_cmp_active = false;
    }

    // (2) Stage 2: CMP/TST-zero of zs_rd consuming zs_active?
    if (state->zs_active) {
        unsigned cmp_sf, cmp_rn;
        bool cmp_is_subs;   // unused: only the shared N/Z matter here
        if (decode_zero_test(op, &cmp_sf, &cmp_rn, &cmp_is_subs)
                && cmp_rn == state->zs_rd
                && cmp_sf == (state->zs_is_64bit ? 1u : 0u)) {
            state->zs_cmp_active = true;
            snprintf(state->zs_cmp_disasm,
                sizeof(state->zs_cmp_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
        state->zs_active = false;
    }

    // (3) Stage 1: open non-S ALU pending state. The S-variant
    //     spelling is the mnemonic plus "s" for every member --
    //     add/sub/and/bic and the NEG alias (SUB from ZR), whose
    //     flag-setting twin is spelled NEGS -- so it is pre-rendered
    //     here from Capstone's disassembly.
    unsigned sf, rd;
    if (decode_non_s_alu(op, &sf, &rd)) {
        state->zs_active = true;
        state->zs_is_64bit = (sf != 0);
        state->zs_rd = rd;
        state->zs_offset = offset;
        snprintf(state->zs_disasm, sizeof(state->zs_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
        snprintf(state->zs_sdisasm, sizeof(state->zs_sdisasm),
            "%ss %s", insn->mnemonic, insn->op_str);
    }

    return false;
}

// Classify a non-S ADD or SUB in any of the three forms that CMN/CMP
// share -- immediate, shifted-register, extended-register -- writing
// a real register. Rd = 31 is rejected: it means SP for the
// immediate and extended forms (the S-variant's Rd = 31 is ZR, so
// the fold would drop an observable SP update) and a dead ZR write
// for the shifted form. An immediate of 0 is rejected too: the pair
// is degenerate (check_add_sub_zero's redundant-op shapes), and the
// ADD side's MOV-from-SP alias spelling must not gain an "s".
// out_has_rm distinguishes the register forms (whose Rm field is a
// read) from the immediate form (whose bits 20..16 are immediate
// payload), for the ALU-first order's aliasing check; out_is_sub
// selects the SUB/CMP vs ADD/CMN family for reporting.
static bool decode_add_sub_non_s_any(uint32_t op, unsigned *out_rd,
                                     unsigned *out_rn, unsigned *out_rm,
                                     bool *out_has_rm, bool *out_is_sub)
{
    unsigned rd = op & 0x1Fu;
    if (rd == 31) {
        return false;
    }

    // ADD/SUB immediate: bit 29 = S = 0, bits 28..23 = 100010
    // (bit 30 selects ADD/SUB and stays free).
    if ((op & 0x3F800000u) == 0x11000000u) {
        if (((op >> 10) & 0xFFFu) == 0) {
            return false;
        }
        *out_has_rm = false;
    // ADD/SUB shifted-register: bit 29 = 0, bits 28..24 = 01011,
    // bit 21 = 0.
    } else if ((op & 0x3F200000u) == 0x0B000000u) {
        *out_has_rm = true;
    // ADD/SUB extended-register: same class with bit 21 = 1.
    } else if ((op & 0x3F200000u) == 0x0B200000u) {
        *out_has_rm = true;
    } else {
        return false;
    }
    *out_rd = rd;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rm = (op >> 16) & 0x1Fu;
    *out_is_sub = ((op >> 30) & 1u) != 0;
    return true;
}

// The compare spelling of an ADD/SUB's exact computation -- CMN for
// ADD, CMP for SUB -- is the same word with the S bit (29) set and
// Rd = 31.
static uint32_t alu_to_cmp_word(uint32_t alu_op)
{
    return (alu_op & ~0x1Fu) | 0x20000000u | 0x1Fu;
}

// True for a CMP or CMN in any of the three forms (SUBS/ADDS with
// Rd = 31; bit 30 stays free).
static bool is_cmp_cmn_any_form(uint32_t op)
{
    if ((op & 0x1Fu) != 0x1Fu) {
        return false;
    }
    return (op & 0x3F800000u) == 0x31000000u        // immediate
        || (op & 0x3F200000u) == 0x2B000000u        // shifted
        || (op & 0x3F200000u) == 0x2B200000u;       // extended
}

// ADD and CMN are commutative in value: with plain register operands
// the compare may name them in either order and the 65-bit sum --
// hence all four NZCV bits -- is unchanged. Only the unshifted
// shifted-register form (LSL #0) swaps: a nonzero shift amount breaks
// the symmetry (Rn + (Rm << s) != Rm + (Rn << s)), the immediate form
// has no second register, the extended form applies its extension to
// Rm only, and subtraction does not commute at all. True when cmp_op
// is exactly the swapped-operand CMN of the given plain ADD.
static bool cmn_swapped_match(uint32_t alu_op, uint32_t cmp_op)
{
    // ADD (shifted register), non-S, LSL #0:
    //   sf 0 0 01011 00 0 Rm 000000 Rn Rd.
    if ((alu_op & 0x7FE0FC00u) != 0x0B000000u) {
        return false;
    }
    unsigned rn = (alu_op >> 5) & 0x1Fu;
    unsigned rm = (alu_op >> 16) & 0x1Fu;
    return cmp_op == (0x2B00001Fu
        | (alu_op & 0x80000000u)
        | (rn << 16)
        | (rm << 5));
}

bool check_sub_cmp_fold(armlint_state *state, const cs_insn *insn,
                        size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->scp_sub_active = false;
        state->scp_cmp_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Close, ALU-first order: is this the compare of the pending
    //     ADD/SUB's exact operands (CMN for ADD, CMP for SUB) -- or,
    //     for a plain unshifted ADD, the swapped-operand CMN, which
    //     sums the same values? The compare runs after the ALU wrote
    //     Rd, so Rd must not be one of the compared registers -- the
    //     compare read the result there, not the original operand,
    //     and the folded S-variant would use pre-ALU values. (Rn = 31
    //     is SP/ZR depending on form and never collides: Rd != 31 by
    //     construction.)
    if (state->scp_sub_active) {
        unsigned s_rd, s_rn, s_rm;
        bool s_has_rm, s_is_sub;
        if ((op == alu_to_cmp_word(state->scp_sub_op)
                    || cmn_swapped_match(state->scp_sub_op, op))
                && decode_add_sub_non_s_any(state->scp_sub_op, &s_rd,
                                            &s_rn, &s_rm, &s_has_rm,
                                            &s_is_sub)
                && s_rd != s_rn
                && (!s_has_rm || s_rd != s_rm)) {
            out->name = s_is_sub
                ? "SUB + CMP of identical operands foldable to SUBS"
                : "ADD + CMN of identical operands foldable to ADDS";
            out->start_offset = state->scp_sub_offset;
            out->insn_count = 2;
            clear_finding_strings(out);
            snprintf(out->detail, sizeof(out->detail),
                "-> %s (drop %s %s)",
                state->scp_sub_sdisasm, insn->mnemonic, insn->op_str);
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->scp_sub_disasm);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %s", insn->mnemonic, insn->op_str);
            produced = true;
        }
        state->scp_sub_active = false;
    }

    // (2) Close, compare-first order: is this a non-S ADD/SUB of the
    //     pending compare's exact operands (or a plain unshifted ADD
    //     of the pending CMN's swapped ones)? The compare wrote
    //     nothing, so the ALU reads the same values regardless of Rd
    //     -- no aliasing restriction beyond Rd != 31 (in the
    //     decoder). The word match pairs families automatically: an
    //     ADD's compare spelling is CMN, a SUB's is CMP.
    if (state->scp_cmp_active) {
        unsigned s_rd, s_rn, s_rm;
        bool s_has_rm, s_is_sub;
        if (decode_add_sub_non_s_any(op, &s_rd, &s_rn, &s_rm,
                                     &s_has_rm, &s_is_sub)
                && (alu_to_cmp_word(op) == state->scp_cmp_op
                    || cmn_swapped_match(op, state->scp_cmp_op))) {
            out->name = s_is_sub
                ? "SUB + CMP of identical operands foldable to SUBS"
                : "ADD + CMN of identical operands foldable to ADDS";
            out->start_offset = state->scp_cmp_offset;
            out->insn_count = 2;
            clear_finding_strings(out);
            snprintf(out->detail, sizeof(out->detail),
                "-> %ss %s (drop %s)",
                insn->mnemonic, insn->op_str, state->scp_cmp_disasm);
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->scp_cmp_disasm);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %s", insn->mnemonic, insn->op_str);
            produced = true;
        }
        state->scp_cmp_active = false;
    }

    // (3) Open. A compare that just closed the ALU-first order still
    //     opens, so compare-sharing chains (sub ; cmp ; sub) report
    //     both folds. The S-variant spelling is the ALU's mnemonic
    //     plus "s", NEGS for the NEG alias -- same rendering rule as
    //     check_zero_cmp_to_s_variant.
    unsigned o_rd, o_rn, o_rm;
    bool o_has_rm, o_is_sub;
    if (decode_add_sub_non_s_any(op, &o_rd, &o_rn, &o_rm, &o_has_rm,
                                 &o_is_sub)) {
        state->scp_sub_active = true;
        state->scp_sub_op = op;
        state->scp_sub_offset = offset;
        snprintf(state->scp_sub_disasm, sizeof(state->scp_sub_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
        snprintf(state->scp_sub_sdisasm, sizeof(state->scp_sub_sdisasm),
            "%ss %s", insn->mnemonic, insn->op_str);
    } else if (is_cmp_cmn_any_form(op)) {
        state->scp_cmp_active = true;
        state->scp_cmp_op = op;
        state->scp_cmp_offset = offset;
        snprintf(state->scp_cmp_disasm, sizeof(state->scp_cmp_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return produced;
}

bool check_subs_cmp_redundant(armlint_state *state, const cs_insn *insn,
                              size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->rcs_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Close: is this the compare of the pending flag-setting
    //     ADD/SUB's own operands (CMP for SUBS, CMN for ADDS; the
    //     swapped-operand CMN also matches for the plain unshifted
    //     ADDS -- probing with the S bit cleared reuses the non-S
    //     ADD matcher)? The producer already computed exactly these
    //     flags, so the compare recomputes the same NZCV and is
    //     simply dropped -- nothing else is rewritten, so even the
    //     imm = 0 spellings need no exclusion here. The compare must
    //     not read the producer's destination (Rd not among its
    //     operands), where it would see the result rather than the
    //     original value. A producer with Rd = 31 is itself a
    //     compare, making the pair an adjacent duplicate compare,
    //     equally droppable.
    if (state->rcs_active) {
        if (op == alu_to_cmp_word(state->rcs_op)
                || cmn_swapped_match(state->rcs_op & ~0x20000000u, op)) {
            unsigned p_rd = state->rcs_op & 0x1Fu;
            unsigned p_rn = (state->rcs_op >> 5) & 0x1Fu;
            unsigned p_rm = (state->rcs_op >> 16) & 0x1Fu;
            bool p_imm = ((state->rcs_op >> 24) & 0x1Fu) == 0x11u;
            if (p_rd != p_rn && (p_imm || p_rd != p_rm)) {
                bool p_is_sub = ((state->rcs_op >> 30) & 1u) != 0;
                out->name = p_is_sub
                    ? "SUBS + CMP of identical operands: redundant compare"
                    : "ADDS + CMN of identical operands: redundant compare";
                out->start_offset = state->rcs_offset;
                out->insn_count = 2;
                clear_finding_strings(out);
                snprintf(out->detail, sizeof(out->detail),
                    "-> drop %s %s (NZCV already set by %s)",
                    insn->mnemonic, insn->op_str, state->rcs_disasm);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->rcs_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);
                produced = true;
            }
        }
        // Strict adjacency: clear regardless of match.
        state->rcs_active = false;
    }

    // (2) Open: any flag-setting ADD/SUB -- the three CMP/CMN forms
    //     without the Rd = 31 requirement. A compare that just closed
    //     a pair opens the next, so chained duplicates each report.
    if ((op & 0x3F800000u) == 0x31000000u
            || (op & 0x3F200000u) == 0x2B000000u
            || (op & 0x3F200000u) == 0x2B200000u) {
        state->rcs_active = true;
        state->rcs_op = op;
        state->rcs_offset = offset;
        snprintf(state->rcs_disasm, sizeof(state->rcs_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return produced;
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

// AND (immediate, non-flag-setting) whose mask is a single bit:
//   sf | 00 | 100100 | N | immr(6) | imms(6) | Rn | Rd
// imms = 0 (a run of one '1') with N == sf; bit = (datasize - immr)
// mod datasize. Same field logic as decode_tst_single_bit, but for
// the plain AND with a real destination. ANDS is deliberately not
// matched: deleting it would lose the NZCV write (its Rd = ZR form is
// the TST alias that check_tst_branch owns).
static bool decode_and_single_bit(uint32_t op, unsigned *out_sf,
                                  unsigned *out_rd, unsigned *out_rn,
                                  unsigned *out_bit)
{
    if ((op & 0x7F800000u) != 0x12000000u) {
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
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// UBFM or SBFM extracting a single bit: imms == immr == k places bit
// k of the source in Rd[0], zero- or sign-extended, so Rd == 0 iff
// Rs[k] == 0. Covers `ubfx/sbfx Rd, Rs, #k, #1` and the k =
// datasize-1 aliases `lsr/asr Rd, Rs, #(datasize-1)`. BFM (opc = 01)
// merges into Rd's old value and is not a pure bit test.
static bool decode_bfm_single_bit(uint32_t op, unsigned *out_sf,
                                  unsigned *out_rd, unsigned *out_rn,
                                  unsigned *out_bit)
{
    unsigned sf = (op >> 31) & 1u;
    uint32_t cls = op & 0xFFC00000u;
    uint32_t ubfm = sf ? 0xD3400000u : 0x53000000u;
    uint32_t sbfm = sf ? 0x93400000u : 0x13000000u;
    if (cls != ubfm && cls != sbfm) {
        return false;
    }
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;
    if (imms != immr) {
        return false;
    }
    if (!sf && imms >= 32u) {
        return false;       // UNDEFINED encoding
    }
    *out_sf = sf;
    *out_bit = immr;
    *out_rd = op & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
}

// CBZ (op = 0) / CBNZ (op = 1): sf 011010 op imm19 Rt.
static bool decode_cbz_cbnz(uint32_t op, unsigned *out_sf,
                            bool *out_is_cbnz, int32_t *out_imm19,
                            unsigned *out_rt)
{
    if ((op & 0x7E000000u) != 0x34000000u) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_is_cbnz = ((op >> 24) & 1u) != 0;
    int32_t imm19 = (int32_t)((op >> 5) & 0x7FFFFu);
    if (imm19 & 0x40000) {
        imm19 -= 0x80000;   // sign-extend 19 bits
    }
    *out_imm19 = imm19;
    *out_rt = op & 0x1Fu;
    return true;
}

bool armlint_advance_pending_tb(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out)
{
    if (!state->pending_tb_active) {
        return false;
    }
    if (insn->size != 4) {
        state->pending_tb_active = false;
        return false;
    }
    switch (classify_reg_liveness(insn, state->pending_tb_reg)) {
    case LIV_OVERWRITE:
        state->pending_tb_active = false;
        // Fall-through path proven: [ft, here) held no read or
        // control transfer and this instruction kills the register.
        // The taken path shares the proof only when the branch target
        // lies inside that clean span (inclusive of the kill itself):
        // execution entering anywhere in it runs straight to the same
        // kill. A target before the fall-through (backward) or beyond
        // the kill leaves the taken path unproven -- discard.
        if (state->pending_tb_target >= state->pending_tb_ft
                && state->pending_tb_target <= offset) {
            *out = state->pending_tb_finding;
            return true;
        }
        return false;
    case LIV_READ:
    case LIV_TERM_SAFE:
    case LIV_TERM_UNSAFE:
        state->pending_tb_active = false;
        return false;
    case LIV_UNKNOWN:
        if (state->pending_tb_window == 0
                || --state->pending_tb_window == 0) {
            state->pending_tb_active = false;
        }
        return false;
    }
    return false;
}

bool check_single_bit_cbz(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out)
{
    (void)out;  // emission goes through armlint_advance_pending_tb

    if (insn->size != 4) {
        state->tbf_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: a CBZ/CBNZ testing the producer's destination?
    if (state->tbf_active) {
        unsigned c_sf, rt;
        bool is_cbnz;
        int32_t imm19;
        if (decode_cbz_cbnz(op, &c_sf, &is_cbnz, &imm19, &rt)
                && rt == state->tbf_rd
                // A W-form branch cannot observe a bit isolated at or
                // above bit 32: the zero-extended field sits wholly in
                // the discarded high half, making the branch constant
                // -- degenerate, not this fold. (An SBFM producer's
                // sign replication would make it visible, but that
                // exotic shape is conservatively skipped too.)
                && !(c_sf == 0 && state->tbf_bit >= 32u)) {
            // Range: the TBZ replaces the producer, 4 bytes before the
            // CBZ, so its displacement is imm19 + 1 instruction units,
            // within TBZ's signed 14 bits. (The containment gate in
            // the pending scan restricts the target far more tightly;
            // this keeps the encoding constraint visible.) The target
            // must also lie at or after the fall-through: a backward
            // target can never satisfy the containment proof, so it is
            // dropped now rather than deferred.
            int64_t tbz_disp = (int64_t)imm19 + 1;
            int64_t t_off = (int64_t)offset + (int64_t)imm19 * 4;
            if (tbz_disp >= -8192 && tbz_disp <= 8191
                    && t_off >= (int64_t)(offset + 4u)) {
                uint64_t target = insn->address
                    + (uint64_t)((int64_t)imm19 * 4);
                // TBZ names a W source for bits 0..31 and an X source
                // for bits 32..63, independent of the CBZ's width.
                char s_wx = state->tbf_bit < 32u ? 'w' : 'x';
                char c_wx = c_sf ? 'x' : 'w';
                const char *tb_mnem = is_cbnz ? "tbnz" : "tbz";
                const char *cb_mnem = is_cbnz ? "cbnz" : "cbz";

                armlint_finding *p = &state->pending_tb_finding;
                p->name =
                    "single-bit test + CBZ/CBNZ foldable into TBZ/TBNZ";
                p->start_offset = state->tbf_offset;
                p->insn_count = 2;
                clear_finding_strings(p);

                snprintf(p->detail, sizeof(p->detail),
                    "-> %s %c%u, #%u, 0x%" PRIx64,
                    tb_mnem, s_wx, state->tbf_rs, state->tbf_bit,
                    target);
                snprintf(p->lines[0], sizeof(p->lines[0]),
                    "%s", state->tbf_disasm);
                snprintf(p->lines[1], sizeof(p->lines[1]),
                    "%s %c%u, 0x%" PRIx64,
                    cb_mnem, c_wx, rt, target);

                state->pending_tb_active = true;
                state->pending_tb_window = LIVENESS_WINDOW;
                state->pending_tb_reg = (int)state->tbf_rd;
                state->pending_tb_ft = offset + 4u;
                state->pending_tb_target = (size_t)t_off;
            }
        }
        // Strict adjacency: any non-matching instruction expires.
        state->tbf_active = false;
    }

    // (2) Open: a single-bit producer? The source must be a real
    // register (ZR gives a constant zero -- a degenerate always/never
    // branch) and the destination must not be discarded.
    unsigned p_sf, p_rd, p_rs, p_bit;
    if ((decode_and_single_bit(op, &p_sf, &p_rd, &p_rs, &p_bit)
            || decode_bfm_single_bit(op, &p_sf, &p_rd, &p_rs, &p_bit))
            && p_rd != 31 && p_rs != 31) {
        state->tbf_active = true;
        state->tbf_is_64bit = (p_sf != 0);
        state->tbf_rd = p_rd;
        state->tbf_rs = p_rs;
        state->tbf_bit = p_bit;
        state->tbf_offset = offset;
        snprintf(state->tbf_disasm, sizeof(state->tbf_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return false;
}

// CSET Rd, cond -- the alias of CSINC Rd, ZR, ZR, invert(cond):
//   sf 0 0 11010100 Rm(11111) cond 0 1 Rn(11111) Rd
// Rd = 1 exactly when the *inverted* raw field's condition holds, so
// the returned cond is field^1 (the spelling the alias renders). Raw
// fields AL/NV are excluded: ConditionHolds treats both as always-
// true, making the "cset" a constant 0 -- not a conditional at all.
// Rd == ZR (a discarded result) is excluded too.
static bool decode_cset(uint32_t op, unsigned *out_rd, unsigned *out_cond)
{
    if ((op & 0x7FE00C00u) != 0x1A800400u
            || ((op >> 16) & 0x1Fu) != 31u
            || ((op >> 5) & 0x1Fu) != 31u) {
        return false;
    }
    unsigned field = (op >> 12) & 0xFu;
    if (field >= 14u) {
        return false;
    }
    unsigned rd = op & 0x1Fu;
    if (rd == 31u) {
        return false;
    }
    *out_rd = rd;
    *out_cond = field ^ 1u;
    return true;
}

// CSETM Rd, cond -- the alias of CSINV Rd, ZR, ZR, invert(cond):
//   sf 1 0 11010100 Rm(11111) cond 0 0 Rn(11111) Rd
// The CSINV twin of decode_cset (bit 30 set, o2 = 0), producing 0 or
// all-ones instead of 0 or 1, with the same AL/NV constant-result and
// ZR-destination exclusions.
static bool decode_csetm(uint32_t op, unsigned *out_rd,
                         unsigned *out_cond)
{
    if ((op & 0x7FE00C00u) != 0x5A800000u
            || ((op >> 16) & 0x1Fu) != 31u
            || ((op >> 5) & 0x1Fu) != 31u) {
        return false;
    }
    unsigned field = (op >> 12) & 0xFu;
    if (field >= 14u) {
        return false;
    }
    unsigned rd = op & 0x1Fu;
    if (rd == 31u) {
        return false;
    }
    *out_rd = rd;
    *out_cond = field ^ 1u;
    return true;
}

// EOR (immediate) with value 1: sf 10 100100 N immr imms Rn Rd. The
// mask leaves sf and the bitmask fields free; the caller-visible
// constant is reconstructed and must equal 1. Rd = 31 here means SP
// (logical immediates can target SP) and is rejected -- the CSET
// rewrite has no SP destination.
static bool decode_eor_imm_1(uint32_t op, unsigned *out_sf,
                             unsigned *out_rd, unsigned *out_rn)
{
    if ((op & 0x7F800000u) != 0x52000000u) {
        return false;
    }
    unsigned sf = (op >> 31) & 1u;
    unsigned N = (op >> 22) & 1u;
    if (!sf && N) {
        return false;       // UNDEFINED encoding
    }
    unsigned immr = (op >> 16) & 0x3Fu;
    unsigned imms = (op >> 10) & 0x3Fu;
    uint64_t value;
    if (!decode_bitmask_imm_value(N, immr, imms, sf ? 64u : 32u, &value)
            || value != 1u) {
        return false;
    }
    unsigned rd = op & 0x1Fu;
    if (rd == 31u) {
        return false;
    }
    *out_sf = sf;
    *out_rd = rd;
    *out_rn = (op >> 5) & 0x1Fu;
    return true;
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

// A64 condition-code names, indexed by the 4-bit cond field. Capstone's
// spellings (hs/lo rather than cs/cc).
static const char *const a64_cond_names[16] = {
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
};

bool check_cset_fold(armlint_state *state, const cs_insn *insn,
                     size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->cset_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: a consumer of the pending CSET? The producer's value
    // is 0 or 1 zero-extended to the full X register, so a consumer of
    // either width observes the same truth value -- no width gate is
    // needed on any of the three shapes.
    if (state->cset_active) {
        state->cset_active = false;     // strict adjacency
        unsigned p_rd = state->cset_rd;
        unsigned p_cond = state->cset_cond;

        // (a) CBZ/CBNZ of the temp: CBNZ branches exactly when the
        // condition held, CBZ when it did not -- B.cond with the same
        // target, deleting the CSET. The temp must then be dead on
        // BOTH edges; defer through the two-edge scan exactly as the
        // single-bit fold does (fall-through proven by forward scan,
        // taken edge by containment in [fall-through, kill]). Backward
        // targets can never satisfy containment, so they drop now.
        unsigned c_sf, rt;
        bool is_cbnz;
        int32_t imm19;
        if (decode_cbz_cbnz(op, &c_sf, &is_cbnz, &imm19, &rt)
                && rt == p_rd) {
            // The B.cond replaces the producer, 4 bytes before the
            // CBZ, so its displacement is imm19 + 1 units -- still a
            // signed 19-bit quantity except at imm19's positive limit.
            int64_t t_off = (int64_t)offset + (int64_t)imm19 * 4;
            if (t_off >= (int64_t)(offset + 4u)
                    && (int64_t)imm19 + 1 <= 262143) {
                unsigned bcond = is_cbnz ? p_cond : (p_cond ^ 1u);
                uint64_t target = insn->address
                    + (uint64_t)((int64_t)imm19 * 4);
                char c_wx = c_sf ? 'x' : 'w';
                const char *cb_mnem = is_cbnz ? "cbnz" : "cbz";

                armlint_finding *p = &state->pending_tb_finding;
                p->name = "CSET + CBZ/CBNZ foldable into B.cond";
                p->start_offset = state->cset_offset;
                p->insn_count = 2;
                clear_finding_strings(p);

                snprintf(p->detail, sizeof(p->detail),
                    "-> b.%s 0x%" PRIx64,
                    a64_cond_names[bcond], target);
                snprintf(p->lines[0], sizeof(p->lines[0]),
                    "%s", state->cset_disasm);
                snprintf(p->lines[1], sizeof(p->lines[1]),
                    "%s %c%u, 0x%" PRIx64,
                    cb_mnem, c_wx, rt, target);

                state->pending_tb_active = true;
                state->pending_tb_window = LIVENESS_WINDOW;
                state->pending_tb_reg = (int)p_rd;
                state->pending_tb_ft = offset + 4u;
                state->pending_tb_target = (size_t)t_off;
            }
            return false;
        }

        // (b) EOR #1 of the temp inverts the boolean: the pair is the
        // inverted CSET, at the consumer's width. (c) NEG of the temp
        // maps 1 to all-ones: CSETM, condition unchanged. Either way
        // the rewrite deletes the CSET, so the temp must die: a
        // consumer overwriting the temp itself kills it on the spot
        // (emit now); otherwise defer through the forward scan.
        // (decode_eor_imm_1 already rejected Rd = 31 as SP; NEG's
        // Rd = 31 is ZR, a discarded result not worth rewriting.)
        unsigned e_sf, e_rd, e_rn;
        bool is_eor = decode_eor_imm_1(op, &e_sf, &e_rd, &e_rn);
        bool is_neg = !is_eor && decode_neg(op, &e_sf, &e_rd, &e_rn);
        if ((is_eor || is_neg) && e_rn == p_rd && e_rd != 31u) {
            const char *new_mnem = is_eor ? "cset" : "csetm";
            unsigned new_cond = is_eor ? (p_cond ^ 1u) : p_cond;
            char e_wx = e_sf ? 'x' : 'w';

            out->name = is_eor
                ? "CSET + EOR #1 foldable to inverted CSET"
                : "CSET + NEG foldable to CSETM";
            out->start_offset = state->cset_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            snprintf(out->detail, sizeof(out->detail),
                "-> %s %c%u, %s",
                new_mnem, e_wx, e_rd, a64_cond_names[new_cond]);
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->cset_disasm);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %s", insn->mnemonic, insn->op_str);

            if (e_rd == p_rd) {
                return true;
            }
            return defer_dead_mov(state, out, p_rd);
        }
    }

    // (2) Open: a CSET?
    unsigned p_rd, p_cond;
    if (decode_cset(op, &p_rd, &p_cond)) {
        state->cset_active = true;
        state->cset_rd = p_rd;
        state->cset_cond = p_cond;
        state->cset_offset = offset;
        snprintf(state->cset_disasm, sizeof(state->cset_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return false;
}

bool check_tst_cset(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out)
{
    (void)out;      // emission goes through armlint_advance_pending
    (void)offset;

    if (insn->size != 4) {
        return false;   // tst_active is check_tst_branch's to clear
    }
    if (!state->tst_active) {
        return false;
    }

    uint32_t op = insn_word(insn);

    // Consumer: CSET (-> UBFX, 0 or 1) or CSETM (-> SBFX, 0 or
    // all-ones) of the pending single-bit TST. The pair state belongs
    // to check_tst_branch, which runs after this check and expires it
    // on any non-branch; it is only read here.
    unsigned rd, cond;
    bool is_csetm = false;
    if (decode_cset(op, &rd, &cond)) {
        // 0/1 form
    } else if (decode_csetm(op, &rd, &cond)) {
        is_csetm = true;
    } else {
        return false;
    }
    unsigned c_sf = (op >> 31) & 1u;

    unsigned bit = state->tst_bit;
    unsigned p_datasize = state->tst_is_64bit ? 64u : 32u;

    // Condition: NE (Z clear <=> the masked bit is set) folds
    // directly, and MI is its synonym when the isolated bit is the
    // producer's sign bit (N is that bit; any lower bit makes MI
    // constant-false). EQ/PL would need an inverted extract, which
    // has no single-instruction form, and every other condition is
    // constant after TST (C = V = 0).
    if (!(cond == 1u || (cond == 4u && bit == p_datasize - 1u))) {
        return false;
    }

    // The rewrite's width. CSET's 0/1 zero-extends identically at
    // either width, so the consumer's width serves, bumped to X when
    // the bit lives in the high half (only reachable from an X-form
    // TST). CSETM's all-ones must replicate at the CSETM's own width,
    // and a W-form extract cannot reach bits 32..63 -- that shape has
    // no single-instruction form and is skipped. Cross-width register
    // reads are exact: bit k < 32 of Xn and Wn are the same bit.
    unsigned r_sf;
    if (is_csetm) {
        if (c_sf == 0 && bit >= 32u) {
            return false;
        }
        r_sf = c_sf;
    } else {
        r_sf = bit >= 32u ? 1u : c_sf;
    }

    char r_wx = r_sf ? 'x' : 'w';
    char p_wx = state->tst_is_64bit ? 'x' : 'w';
    const char *new_mnem = is_csetm ? "sbfx" : "ubfx";

    armlint_finding *p = &state->pending_finding;
    p->name = is_csetm
        ? "TST single-bit + CSETM foldable into SBFX"
        : "TST single-bit + CSET foldable into UBFX";
    p->start_offset = state->tst_offset;
    p->insn_count = 2;
    clear_finding_strings(p);

    snprintf(p->detail, sizeof(p->detail),
        "-> %s %c%u, %c%u, #%u, #1",
        new_mnem, r_wx, rd, r_wx, state->tst_rn, bit);

    if (bit < 32) {
        snprintf(p->lines[0], sizeof(p->lines[0]),
            "tst %c%u, #0x%x", p_wx, state->tst_rn, 1u << bit);
    } else {
        snprintf(p->lines[0], sizeof(p->lines[0]),
            "tst %c%u, #0x%" PRIx64,
            p_wx, state->tst_rn, (uint64_t)1 << bit);
    }
    snprintf(p->lines[1], sizeof(p->lines[1]),
        "%s %s", insn->mnemonic, insn->op_str);

    // The rewrite deletes the TST, and neither UBFX nor SBFX writes
    // flags: all four flags the TST set disappear, so emission defers
    // until the forward scan proves NZCV dead (overwritten or a safe
    // terminator before any reader) -- the same deferral as the
    // TBZ/CBZ folds, whose rewrites also leave NZCV unwritten.
    state->pending_active = true;
    state->pending_window = LIVENESS_WINDOW;
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
    // With immr = 0, UBFM keeps bits imms..0 in place and clears
    // everything above: a zero-extension of width C = imms + 1. The
    // canonical spellings are UXTB (C=8), UXTH (C=16), the X-form
    // UBFX #0, #32 "UXTW" (C=32), and the general in-place
    // UBFX Rd, Rn, #0, #C. The full-width copies (sf=0 imms=31 is
    // "MOV Wd, Wn"; sf=1 imms=63 a literal no-op) clear nothing and
    // are rejected, as are the UNDEFINED sf=0 encodings with
    // imms >= 32.
    unsigned datasize = sf ? 64u : 32u;
    if (imms >= datasize - 1u) {
        return false;
    }
    *out_c = imms + 1u;
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

// Number of significant bits in v: the index of the highest set bit
// plus one, i.e. the smallest P with v < 2^P. Returns 0 for v == 0.
static unsigned bits_used64(uint64_t v)
{
    unsigned n = 0;
    while (v != 0) {
        n++;
        v >>= 1;
    }
    return n;
}

// True if `op` is an instruction whose Rd/Rt is at bits 4..0 and which
// leaves bits 63..P of the corresponding X register zeroed for the
// returned P. Any W-form write gives P <= 32 for free; several
// producers pin P tighter, or extend the guarantee to X-form ops whose
// result is provably bounded:
//
//   UBFM (W or X)         P from the field geometry: an extraction
//                         (imms >= immr -- the UBFX/LSR/UXTB/UXTH
//                         shapes) leaves a field of imms-immr+1 low
//                         bits; an insertion (imms < immr -- the
//                         UBFIZ/LSL shapes) tops out at bit
//                         datasize-immr+imms, so P is one above that.
//   AND/ANDS imm (W or X) the result is a subset of the mask:
//                         P = top set bit of the mask + 1. ORR/EOR
//                         propagate Rn's high bits and get no sharp
//                         threshold.
//   MOVZ (W or X)         the value is fully known: P = its bit count
//                         (0 for MOVZ #0).
//   CSINC Rd, ZR, ZR      the CSET family: the result is 0 or 1
//                         regardless of cond, so P = 1.
//   other W-form DP       P = 32 (the W write zeros X[63:32]).
//   W-form integer loads  P = 8 (LDRB) / 16 (LDRH) / 32 (LDR /
//                         LDRSB / LDRSH Wt).
//
// An X-form producer whose computed P is 64 guarantees nothing and is
// not matched.
static bool decode_zeroing_producer(uint32_t op, unsigned *out_rd,
                                    unsigned *out_zero_from)
{
    unsigned rd = op & 0x1Fu;
    if (rd == 31) {
        return false;
    }

    unsigned sf = (op >> 31) & 1u;
    unsigned datasize = sf ? 64u : 32u;

    // UBFM: sf 10 100110 N(=sf) immr imms Rn Rd.
    if ((op & 0xFFC00000u) == (sf ? 0xD3400000u : 0x53000000u)) {
        unsigned immr = (op >> 16) & 0x3Fu;
        unsigned imms = (op >> 10) & 0x3Fu;
        if (!sf && (immr >= 32u || imms >= 32u)) {
            return false;   // UNDEFINED encoding
        }
        unsigned p = (imms >= immr) ? (imms - immr + 1u)
                                    : (datasize - immr + imms + 1u);
        if (sf && p == 64u) {
            return false;   // full-width result: nothing known zero
        }
        *out_rd = rd;
        *out_zero_from = p;
        return true;
    }

    // AND (opc=00) / ANDS (opc=11) immediate: decode the mask to its
    // concrete value; the result can set no bit the mask does not.
    if ((op & 0x1F800000u) == 0x12000000u) {
        unsigned opc = (op >> 29) & 0x3u;
        if (opc == 0u || opc == 3u) {
            unsigned n_bit = (op >> 22) & 1u;
            unsigned immr = (op >> 16) & 0x3Fu;
            unsigned imms = (op >> 10) & 0x3Fu;
            uint64_t mask;
            if (!(!sf && n_bit)   // sf=0 with N=1 is UNDEFINED
                    && decode_bitmask_imm_value(n_bit, immr, imms,
                                                datasize, &mask)) {
                unsigned p = bits_used64(mask);
                if (!(sf && p == 64u)) {
                    *out_rd = rd;
                    *out_zero_from = p;
                    return true;
                }
            }
        }
        // ORR/EOR (and undecodable masks) fall through: the W forms
        // still qualify via the generic W-form table below.
    }

    // MOVZ: sf 10 100101 hw imm16 Rd.
    if ((op & 0x7F800000u) == 0x52800000u) {
        unsigned hw = (op >> 21) & 0x3u;
        if (!sf && hw >= 2u) {
            return false;   // UNDEFINED encoding
        }
        uint64_t value = (uint64_t)((op >> 5) & 0xFFFFu) << (16u * hw);
        unsigned p = bits_used64(value);
        if (sf && p == 64u) {
            return false;
        }
        *out_rd = rd;
        *out_zero_from = p;
        return true;
    }

    // CSINC Rd, ZR, ZR, cond -- CSET and its inverted spellings.
    if ((op & 0x7FE00C00u) == 0x1A800400u
            && ((op >> 16) & 0x1Fu) == 31u
            && ((op >> 5) & 0x1Fu) == 31u) {
        *out_rd = rd;
        *out_zero_from = 1u;
        return true;
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
            out->name = "redundant zero-extension after zeroing op";
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
    if (decode_zeroing_producer(op, &p_rd, &p_zero_from)) {
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

// Detect a sign-extending producer for check_redundant_sext: any SBFM
// (which subsumes the SXT* aliases, ASR immediate, and the general
// SBFX/SBFIZ shapes), and the sign-extending integer loads
// LDRSB/LDRSH/LDRSW in any addressing mode (the load mask leaves bit
// 24 free so unsigned-immediate, unscaled, pre-/post-/register-offset
// forms all match). Producers with Rd=31 are skipped (write goes to
// ZR).
//
// *out_dead_ok reports whether the dead-sign-extension path may drop
// this producer outright: true only for an in-place low-field SBFM
// (immr == 0 and Rn == Rd -- the SXT* aliases and SBFX #0 shapes),
// false for loads (data from memory), Rn != Rd extends (data from
// Rn), and the data-relocating shapes (ASR, SBFX with lsb > 0,
// SBFIZ). See the sxt_dead_ok state comment.
static bool decode_sext_producer(uint32_t op, unsigned *out_s,
                                 unsigned *out_w, unsigned *out_rd,
                                 bool *out_dead_ok)
{
    unsigned rd_field = op & 0x1Fu;
    if (rd_field == 31) {
        return false;
    }

    // SBFM: sf 00 100110 N(=sf) immr imms Rn Rd. An extraction shape
    // (imms >= immr -- SXTB/SXTH/SXTW at immr=0, ASR at
    // imms=datasize-1, general SBFX) leaves a field of imms-immr+1
    // low bits and replicates its sign upward, so S is that width; an
    // insertion (imms < immr -- SBFIZ) places the field with its top
    // at bit datasize-immr+imms and replicates from there, so S is
    // one above that. W = datasize (a W-form producer additionally
    // zeros X[63:32], but that is the zext check's concern). S ==
    // datasize -- the full-width copy, or an SBFIZ whose field
    // reaches the top bit -- leaves no sign-replicated region and is
    // not a producer.
    unsigned sf = (op >> 31) & 1u;
    if ((op & 0xFFC00000u) == (sf ? 0x93400000u : 0x13000000u)) {
        unsigned immr = (op >> 16) & 0x3Fu;
        unsigned imms = (op >> 10) & 0x3Fu;
        unsigned datasize = sf ? 64u : 32u;
        if (!sf && (immr >= 32u || imms >= 32u)) {
            return false;   // UNDEFINED encoding
        }
        unsigned s = (imms >= immr) ? (imms - immr + 1u)
                                    : (datasize - immr + imms + 1u);
        if (s == datasize) {
            return false;
        }
        *out_s = s;
        *out_w = datasize;
        *out_rd = rd_field;
        // Dead-removable only when the data stays in place (immr == 0,
        // so the consumer's kept low bits are the extend's own field)
        // and it is Rd's own value being extended (Rn == Rd). A
        // relocating shape or an Rn != Rd extend writes fresh data
        // into the bits the consumer keeps.
        *out_dead_ok = (immr == 0u
                        && rd_field == ((op >> 5) & 0x1Fu));
        return true;
    }

    // Sign-extending loads. (size, opc) -> (S, W). A load brings its
    // value in from memory, so it is never dead-removable (dropping it
    // would discard the load); *out_dead_ok stays false.
    //   LDRSB Xt: (00, 10) -> (8,  64)
    //   LDRSB Wt: (00, 11) -> (8,  32)
    //   LDRSH Xt: (01, 10) -> (16, 64)
    //   LDRSH Wt: (01, 11) -> (16, 32)
    //   LDRSW Xt: (10, 10) -> (32, 64)
    if ((op & 0xFEC00000u) == 0x38800000u) { *out_s = 8;  *out_w = 64; *out_rd = rd_field; *out_dead_ok = false; return true; }
    if ((op & 0xFEC00000u) == 0x38C00000u) { *out_s = 8;  *out_w = 32; *out_rd = rd_field; *out_dead_ok = false; return true; }
    if ((op & 0xFEC00000u) == 0x78800000u) { *out_s = 16; *out_w = 64; *out_rd = rd_field; *out_dead_ok = false; return true; }
    if ((op & 0xFEC00000u) == 0x78C00000u) { *out_s = 16; *out_w = 32; *out_rd = rd_field; *out_dead_ok = false; return true; }
    if ((op & 0xFEC00000u) == 0xB8800000u) { *out_s = 32; *out_w = 64; *out_rd = rd_field; *out_dead_ok = false; return true; }

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
                    // Only when the producer is removable in place: an
                    // in-place SXT (Rn == Rd). A load or an Rn != Rd SXT
                    // put fresh data into the low bits the consumer keeps,
                    // so dropping the producer would change the result.
                    && state->sxt_dead_ok) {
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
    bool p_dead_ok;
    if (decode_sext_producer(op, &p_s, &p_w, &p_rd, &p_dead_ok)) {
        state->sxt_active = true;
        state->sxt_rd = p_rd;
        state->sxt_signed_from = p_s;
        state->sxt_upper = p_w;
        state->sxt_dead_ok = p_dead_ok;
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

bool check_fcsel_self(armlint_state *state, const cs_insn *insn,
                      size_t offset, armlint_finding *out)
{
    (void)state;

    if (insn->size != 4) {
        return false;
    }

    uint32_t op = insn_word(insn);

    // FCSEL: 0001 1110 0 type 1 Rm cond 11 Rn Rd. A pure bit-pattern
    // select -- no arithmetic, no NaN processing -- so Rn == Rm makes
    // the condition irrelevant and the instruction a register copy:
    // FMOV (register), which like FCSEL zeroes the vector register
    // above the written lane, so the rewrite is exact for the full
    // 128 bits. The pointless NZCV read disappears too. Single and
    // double precision only; half precision (FEAT_FP16, type 11) is
    // not matched, consistent with the other FP checks. FP registers
    // have no ZR/SP encoding, so no operand exclusions are needed.
    if ((op & 0xFF200C00u) != 0x1E200C00u) {
        return false;
    }
    unsigned type = (op >> 22) & 0x3u;
    if (type > 1u) {
        return false;
    }
    unsigned rm = (op >> 16) & 0x1Fu;
    unsigned rn = (op >> 5) & 0x1Fu;
    unsigned rd = op & 0x1Fu;
    if (rn != rm) {
        return false;
    }

    char sd = type ? 'd' : 's';

    out->name = "FCSEL same-operand identity";
    out->start_offset = offset;
    out->insn_count = 1;
    clear_finding_strings(out);

    snprintf(out->detail, sizeof(out->detail),
        "%s %s -> fmov %c%u, %c%u (cond irrelevant: both branches = %c%u)",
        insn->mnemonic, insn->op_str,
        sd, rd, sd, rn, sd, rn);
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
                // The rewrite (BFXIL/BFI Rd, Rs) drops the isolate's temp
                // register tt without writing it, so defer until tt is
                // proven dead after the ORR -- a later read of the temp
                // would otherwise make the rewrite unsound. (The ORR
                // writes Rd, never tt, so tt is never self-overwritten
                // here.)
                produced = defer_dead_mov(state, out, tt);
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

    // The rewrite deletes the MOV. If the MUL writes the constant
    // register itself (Rd == mov_rd), that write already kills the
    // constant, so emit now; otherwise defer until a later instruction
    // proves mov_rd dead before any read.
    if (rd == state->mov_rd) {
        return true;
    }
    return defer_dead_mov(state, out, state->mov_rd);
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

    // The rewrite deletes the MOV. If the MNEG writes the constant
    // register itself (Rd == mov_rd), that write already kills the
    // constant, so emit now; otherwise defer until a later instruction
    // proves mov_rd dead before any read.
    if (rd == state->mov_rd) {
        return true;
    }
    return defer_dead_mov(state, out, state->mov_rd);
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

    // The rewrite deletes the MOV. If the UDIV writes the constant
    // register itself (Rd == mov_rd), that write already kills the
    // constant, so emit now; otherwise defer until a later instruction
    // proves mov_rd dead before any read.
    if (rd == state->mov_rd) {
        return true;
    }
    return defer_dead_mov(state, out, state->mov_rd);
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
    // 0x1000 and (C >> 12) is in [0, 0xFFF] (sh=1). A value that
    // does not fit directly may still fold sign-crossed: a NEGATIVE
    // value whose magnitude encodes folds into the opposite-sign
    // consumer (add <-> sub, adds <-> subs, cmp <-> cmn). The
    // crossing is exact for every flag: SUBS Rn, Rm with Rm = -C
    // computes Rn + NOT(-C) + 1 = Rn + C, the identical 65-bit sum
    // as ADDS Rn, #C, so N, Z, C and V all agree bit-for-bit (and
    // symmetrically for ADDS of a negative).
    uint64_t imm = c;
    bool crossed = false;
    bool fits_no_shift = (imm <= 0xFFFu);
    bool fits_with_shift = (imm >= 0x1000u)
        && ((imm & 0xFFFu) == 0)
        && ((imm >> 12) <= 0xFFFu);
    if (!fits_no_shift && !fits_with_shift) {
        uint64_t sign_bit = is_64bit ? (1ull << 63) : (1ull << 31);
        uint64_t mask = is_64bit ? ~0ull : 0xFFFFFFFFull;
        if ((c & sign_bit) == 0) {
            return false;
        }
        uint64_t mag = (~c + 1u) & mask;
        fits_no_shift = (mag <= 0xFFFu);
        fits_with_shift = (mag >= 0x1000u)
            && ((mag & 0xFFFu) == 0)
            && ((mag >> 12) <= 0xFFFu);
        if (!fits_no_shift && !fits_with_shift) {
            return false;
        }
        crossed = true;
        imm = mag;
    }

    char w_or_x = is_64bit ? 'x' : 'w';
    // The fold's sign flips when the constant crossed.
    bool fold_sub = is_sub != crossed;
    const char *fold_mnem;
    if (fold_sub) {
        fold_mnem = is_s ? "subs" : "sub";
    } else {
        fold_mnem = is_s ? "adds" : "add";
    }
    const char *fold_alias = NULL;
    if (rd == 31 && is_s) {
        fold_alias = fold_sub ? "cmp" : "cmn";
    }

    out->name = crossed
        ? "MOV + ADD/SUB foldable to sign-crossed immediate form"
        : "MOV + ADD/SUB foldable to immediate form";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    if (fold_alias != NULL) {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, #0x%" PRIx64,
            fold_alias, w_or_x, other, imm);
    } else {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, %c%u, #0x%" PRIx64,
            fold_mnem, w_or_x, rd, w_or_x, other, imm);
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
    // Capstone's own text renders the CMP/CMN aliases correctly
    // (the manual spelling would print the Rd = 31 slot as "x31").
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s %s", insn->mnemonic, insn->op_str);

    // The rewrite deletes the MOV. If the ADD/SUB writes the constant
    // register itself (Rd == mov_rd), that write already kills the
    // constant, so emit now; otherwise defer until a later instruction
    // proves mov_rd dead before any read. (The CMP/CMN alias has Rd = 31,
    // never mov_rd, so it always defers.)
    if (rd == state->mov_rd) {
        return true;
    }
    return defer_dead_mov(state, out, state->mov_rd);
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
    // Capstone's own text renders the TST alias (and a Rd = 31 BICS)
    // correctly (the manual spelling would print that slot as "x31").
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s %s", insn->mnemonic, insn->op_str);

    // The rewrite deletes the MOV. If the logical op writes the constant
    // register itself (Rd == mov_rd), that write already kills the
    // constant, so emit now; otherwise defer until a later instruction
    // proves mov_rd dead before any read. (The TST alias has Rd = 31,
    // never mov_rd, so it always defers.)
    if (rd == state->mov_rd) {
        return true;
    }
    return defer_dead_mov(state, out, state->mov_rd);
}

// Conditional compare, register form: CCMN (op = 0) / CCMP (op = 1),
//   sf op 1 11010010 Rm cond 0 0 Rn 0 nzcv
// Mask 0x3FE00C10 fixes S (bit 29), the class bits 28..21, the
// register-form selector (bit 11 = 0), o2 (bit 10) and o3 (bit 4),
// leaving sf and op free. The immediate form differs only in
// bit 11 = 1 and is deliberately not matched -- it is the rewrite.
static bool decode_ccmp_ccmn_reg(uint32_t op, unsigned *out_sf,
                                 bool *out_is_ccmp, unsigned *out_rn,
                                 unsigned *out_rm, unsigned *out_nzcv,
                                 unsigned *out_cond)
{
    if ((op & 0x3FE00C10u) != 0x3A400000u) {
        return false;
    }
    *out_sf = (op >> 31) & 1u;
    *out_is_ccmp = ((op >> 30) & 1u) != 0;
    *out_rm = (op >> 16) & 0x1Fu;
    *out_cond = (op >> 12) & 0xFu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_nzcv = op & 0xFu;
    return true;
}

bool check_mov_ccmp_imm_fold(armlint_state *state, const cs_insn *insn,
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

    unsigned sf, rn, rm, nzcv, cond;
    bool is_ccmp;
    if (!decode_ccmp_ccmn_reg(op, &sf, &is_ccmp, &rn, &rm, &nzcv,
                              &cond)) {
        return false;
    }

    bool is_64bit = (sf != 0);
    if (is_64bit != state->mov_is_64bit) {
        return false;
    }

    // The conditional compare is not commutative: only Rm (the
    // subtrahend/addend) has an immediate slot. Rn from the chain
    // would need a reversed compare, which the immediate form cannot
    // express.
    if (rm != state->mov_rd) {
        return false;
    }

    // The surviving operand must not be the constant register (the
    // rewrite would still read it, so the MOV could never be deleted)
    // nor ZR (a degenerate compare-against-zero idiom, consistent with
    // the other MOV-chain folds' exclusion of ZR operands).
    if (rn == state->mov_rd || rn == 31) {
        return false;
    }

    // The immediate form's imm5 is a 5-bit unsigned value. A larger
    // constant may still fold sign-crossed: a NEGATIVE value whose
    // magnitude fits imm5 folds into the opposite compare
    // (ccmp <-> ccmn), whose NZCV agree exactly -- when the condition
    // holds, CCMP of -C and CCMN of #C perform the identical 65-bit
    // sum (Rn + NOT(-C) + 1 = Rn + C), and when it fails both set the
    // carried-over #nzcv literal.
    uint64_t c = state->mov_value;
    uint64_t imm = c;
    bool crossed = false;
    if (c > 31) {
        uint64_t sign_bit = is_64bit ? (1ull << 63) : (1ull << 31);
        uint64_t mask = is_64bit ? ~0ull : 0xFFFFFFFFull;
        uint64_t mag = (~c + 1u) & mask;
        if ((c & sign_bit) == 0 || mag > 31) {
            return false;
        }
        crossed = true;
        imm = mag;
    }

    char w_or_x = is_64bit ? 'x' : 'w';
    const char *mnem = is_ccmp ? "ccmp" : "ccmn";
    const char *fold_mnem = (is_ccmp != crossed) ? "ccmp" : "ccmn";

    out->name = crossed
        ? "MOV + CCMP/CCMN foldable to sign-crossed immediate form"
        : "MOV + CCMP/CCMN foldable to immediate form";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    snprintf(out->detail, sizeof(out->detail),
        "-> %s %c%u, #0x%" PRIx64 ", #0x%x, %s",
        fold_mnem, w_or_x, rn, imm, nzcv, a64_cond_names[cond]);

    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mov_mnem = e->opc == 2 ? "movz"
                          : (e->opc == 0 ? "movn" : "movk");
        unsigned mshift = (unsigned)e->shift_div_16 * 16u;
        if (mshift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, w_or_x, state->mov_rd, e->imm16, mshift);
        }
    }
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s %c%u, %c%u, #0x%x, %s",
        mnem, w_or_x, rn, w_or_x, rm, nzcv, a64_cond_names[cond]);

    // The rewrite deletes the MOV, and a conditional compare writes
    // only NZCV -- it can never kill the constant register itself --
    // so the finding always defers until mov_rd is provably dead.
    return defer_dead_mov(state, out, state->mov_rd);
}

bool check_mov_csel_fold(armlint_state *state, const cs_insn *insn,
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

    // CSEL proper only (op2 = 00): CSINC/CSINV/CSNEG have different
    // else-branches.
    if ((op & 0x7FE00C00u) != 0x1A800000u) {
        return false;
    }
    unsigned sf = (op >> 31) & 1u;
    unsigned rd = op & 0x1Fu;
    unsigned rn = (op >> 5) & 0x1Fu;
    unsigned rm = (op >> 16) & 0x1Fu;
    unsigned cond = (op >> 12) & 0xFu;

    if ((sf != 0) != state->mov_is_64bit) {
        return false;
    }
    // Only a materialised 1 or all-ones folds: CSINC's else-branch
    // is Rm + 1, reproducing the 1 by incrementing ZR, and CSINV's
    // is ~Rm, reproducing all-ones by complementing it. All-ones is
    // width-dependent (0xFFFFFFFF for a W chain), unlike the zero
    // fold's width-agnostic value; the width gate above already
    // matched chain and consumer.
    uint64_t all_ones = state->mov_is_64bit ? ~0ull : 0xFFFFFFFFull;
    bool ones = state->mov_value == all_ones;
    if (state->mov_value != 1 && !ones) {
        return false;
    }
    // AL/NV are excluded: ConditionHolds treats both as always-true,
    // so the select is a plain MOV (of the constant or of the other
    // operand) and the then-slot inversion (AL <-> NV) would still be
    // always-taken. Rd = 31 discards the select.
    if (cond >= 14u || rd == 31) {
        return false;
    }

    // Exactly one CSEL operand is the constant; both-equal is the
    // same-operand identity (check_csel_self's shape). The surviving
    // operand becomes the CSINC/CSINV's Rn -- ZR included, which is
    // the CSET/CSETM alias -- with the condition inverted when the
    // constant sat in the then slot (it must move to the else
    // branch, where the increment or complement produces it):
    //   mov w8, #1  ; csel wd, w8, wn, cc -> csinc wd, wn, wzr, !cc
    //   mov w8, #1  ; csel wd, wn, w8, cc -> csinc wd, wn, wzr, cc
    //   mov w8, #-1 ; csel wd, wn, w8, cc -> csinv wd, wn, wzr, cc
    unsigned t = state->mov_rd;
    unsigned surviving;
    bool invert;
    if (rn == t && rm != t) {
        surviving = rm;
        invert = true;              // then slot: cc ? 1 : rm
    } else if (rm == t && rn != t) {
        surviving = rn;
        invert = false;             // else slot: cc ? rn : 1
    } else {
        return false;
    }

    unsigned csinc_cond = invert ? (cond ^ 1u) : cond;
    char w_or_x = state->mov_is_64bit ? 'x' : 'w';
    char rn_buf[8], rm_buf[8], surv_buf[8];
    format_reg(rn_buf, sizeof(rn_buf), w_or_x, rn);
    format_reg(rm_buf, sizeof(rm_buf), w_or_x, rm);
    format_reg(surv_buf, sizeof(surv_buf), w_or_x, surviving);

    out->name = ones
        ? "MOV #-1 + CSEL foldable to CSINV/CSETM"
        : "MOV #1 + CSEL foldable to CSINC/CSET";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    // A ZR surviving operand is the boolean materialisation itself:
    // CSET Rd, cc is the alias of CSINC Rd, ZR, ZR, !cc (CSETM of
    // CSINV likewise), so the alias condition is the field inverted
    // -- the condition under which the result is the constant.
    if (surviving == 31) {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, %s",
            ones ? "csetm" : "cset",
            w_or_x, rd, a64_cond_names[csinc_cond ^ 1u]);
    } else {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, %s, %czr, %s",
            ones ? "csinv" : "csinc",
            w_or_x, rd, surv_buf, w_or_x,
            a64_cond_names[csinc_cond]);
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
        unsigned mshift = (unsigned)e->shift_div_16 * 16u;
        if (mshift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, w_or_x, state->mov_rd, e->imm16, mshift);
        }
    }
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "csel %c%u, %s, %s, %s",
        w_or_x, rd, rn_buf, rm_buf, a64_cond_names[cond]);

    // The rewrite deletes the MOV. A select whose destination IS the
    // constant register overwrites it at the consumer itself and
    // reports immediately; otherwise emission defers until the
    // constant register is provably dead.
    if (rd == t) {
        return true;
    }
    return defer_dead_mov(state, out, state->mov_rd);
}

bool check_mov_shift_fold(armlint_state *state, const cs_insn *insn,
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

    // Variable shifts LSLV/LSRV/ASRV/RORV (Data-processing 2-source,
    // opcode 0010xx): sf 00 11010110 Rm 0010 op2 Rn Rd. Assemblers
    // and Capstone spell them lsl/lsr/asr/ror with a register
    // amount; every one has an immediate-form twin (UBFM/SBFM
    // aliases, EXTR for ROR).
    if ((op & 0x7FE0F000u) != 0x1AC02000u) {
        return false;
    }
    unsigned sf = (op >> 31) & 1u;
    unsigned rd = op & 0x1Fu;
    unsigned rn = (op >> 5) & 0x1Fu;
    unsigned rm = (op >> 16) & 0x1Fu;

    if ((sf != 0) != state->mov_is_64bit) {
        return false;
    }
    // The chain must feed the amount operand Rm. The shifted operand
    // Rn must not be the constant register (the rewrite would still
    // read it, so the MOV could never be deleted) nor ZR (shifting
    // zero is a constant, a different idiom). Rd = 31 discards the
    // shift.
    if (rm != state->mov_rd || rn == state->mov_rd || rn == 31
            || rd == 31) {
        return false;
    }

    // The register form shifts by UInt(Rm) MOD datasize, so the
    // folded immediate is the chain's value reduced -- a chain of
    // #67 feeding a 64-bit shift folds to #3. A residue of 0 shifts
    // by nothing (a register copy, not a shift) and is left alone as
    // degenerate.
    unsigned datasize = sf ? 64u : 32u;
    unsigned amount = (unsigned)(state->mov_value & (datasize - 1u));
    if (amount == 0) {
        return false;
    }

    char w_or_x = sf ? 'x' : 'w';

    out->name = "MOV + variable shift foldable to immediate shift";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    snprintf(out->detail, sizeof(out->detail),
        "-> %s %c%u, %c%u, #%u",
        insn->mnemonic, w_or_x, rd, w_or_x, rn, amount);

    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mov_mnem = e->opc == 2 ? "movz"
                          : (e->opc == 0 ? "movn" : "movk");
        unsigned mshift = (unsigned)e->shift_div_16 * 16u;
        if (mshift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, w_or_x, state->mov_rd, e->imm16, mshift);
        }
    }
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s %s", insn->mnemonic, insn->op_str);

    // The rewrite deletes the MOV; the immediate and register shift
    // forms themselves cost the same. A shift whose destination IS
    // the constant register overwrites it at the consumer and
    // reports immediately; otherwise emission defers until the
    // constant register is provably dead.
    if (rd == state->mov_rd) {
        return true;
    }
    return defer_dead_mov(state, out, state->mov_rd);
}

bool check_mov_madd_fold(armlint_state *state, const cs_insn *insn,
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

    // MADD/MSUB (Data-processing 3-source, op31 = 000): sf 00 11011
    // 000 Rm o0 Ra Rn Rd; o0 = 0 is MADD, 1 is MSUB.
    if ((op & 0x7FE00000u) != 0x1B000000u) {
        return false;
    }
    bool is_msub = ((op >> 15) & 1u) != 0;
    unsigned sf = (op >> 31) & 1u;
    unsigned rd = op & 0x1Fu;
    unsigned rn = (op >> 5) & 0x1Fu;
    unsigned ra = (op >> 10) & 0x1Fu;
    unsigned rm = (op >> 16) & 0x1Fu;

    if ((sf != 0) != state->mov_is_64bit) {
        return false;
    }
    // Ra = 31 is the MUL/MNEG alias, owned by the strength-reduction
    // checks; Rd = 31 discards the result. The accumulator must not
    // be the constant register (the rewrite still reads it, so the
    // MOV could never be deleted).
    if (ra == 31 || rd == 31 || ra == state->mov_rd) {
        return false;
    }

    // The multiply commutes: the chain may sit in Rn or Rm, and the
    // other multiply operand survives as the shifted register. That
    // operand must not itself be the constant (a constant-squared
    // shape, not this fold) nor ZR (a zero product -- the pair is a
    // register copy).
    unsigned surviving;
    if (rm == state->mov_rd && rn != state->mov_rd) {
        surviving = rn;
    } else if (rn == state->mov_rd && rm != state->mov_rd) {
        surviving = rm;
    } else {
        return false;
    }
    if (surviving == 31) {
        return false;
    }

    // A power-of-two multiplier rides the consumer's shifted-register
    // operand: Ra +/- (Rn << N). N = 0 (a multiplier of 1) folds to
    // the plain ADD/SUB. Anything else has no single-instruction
    // form here.
    uint64_t c = state->mov_value;
    unsigned datasize = sf ? 64u : 32u;
    if (c == 0 || (c & (c - 1u)) != 0) {
        return false;
    }
    unsigned n = 0;
    for (uint64_t t = c; (t & 1u) == 0; t >>= 1) {
        n++;
    }
    if (n >= datasize) {
        return false;
    }

    char w_or_x = sf ? 'x' : 'w';
    const char *fold_mnem = is_msub ? "sub" : "add";

    out->name = "MOV + MADD/MSUB foldable to shifted ADD/SUB";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    if (n == 0) {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, %c%u, %c%u",
            fold_mnem, w_or_x, rd, w_or_x, ra, w_or_x, surviving);
    } else {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %c%u, %c%u, %c%u, lsl #%u",
            fold_mnem, w_or_x, rd, w_or_x, ra, w_or_x, surviving, n);
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
        unsigned mshift = (unsigned)e->shift_div_16 * 16u;
        if (mshift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, w_or_x, state->mov_rd, e->imm16, mshift);
        }
    }
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s %s", insn->mnemonic, insn->op_str);

    // The rewrite deletes the MOV and moves the multiply off the
    // multiplier pipe. A MAC whose destination IS the constant
    // register overwrites it at the consumer and reports
    // immediately; otherwise emission defers until the constant
    // register is provably dead.
    if (rd == state->mov_rd) {
        return true;
    }
    return defer_dead_mov(state, out, state->mov_rd);
}

bool check_udiv_msub_remainder(armlint_state *state, const cs_insn *insn,
                               size_t offset, armlint_finding *out)
{
    (void)offset;
    if (insn->size != 4) {
        state->rem_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: is this the MSUB computing dividend - quotient*2^N?
    //     The unsigned remainder by a power of two is a single AND
    //     with 2^N - 1 (UDIV truncates, which for unsigned values is
    //     the flooring the mod identity needs). The rewrite deletes
    //     all three instructions, leaving TWO temporaries to prove
    //     dead -- the quotient and the constant. The MSUB's own
    //     destination kills one structurally; the forward scan gates
    //     the other. A fresh destination would need two liveness
    //     proofs at once, which the single deferral slot cannot
    //     express, and is conservatively skipped.
    if (state->rem_active) {
        if ((op & 0x7FE08000u) == 0x1B008000u) {
            unsigned sf = (op >> 31) & 1u;
            unsigned rd = op & 0x1Fu;
            unsigned rn = (op >> 5) & 0x1Fu;
            unsigned ra = (op >> 10) & 0x1Fu;
            unsigned rm = (op >> 16) & 0x1Fu;
            // The multiply commutes: quotient and constant may sit in
            // either operand. The accumulator must be the original
            // dividend, which the adjacent pair provably left
            // unmodified.
            bool ops_match =
                (rn == state->rem_xq && rm == state->rem_x8)
                || (rn == state->rem_x8 && rm == state->rem_xq);
            if (((sf != 0) == state->rem_is_64bit)
                    && ops_match
                    && ra == state->rem_xn
                    && (rd == state->rem_xq || rd == state->rem_x8)) {
                char w_or_x = state->rem_is_64bit ? 'x' : 'w';
                uint64_t mask = (1ull << state->rem_n) - 1u;

                *out = state->rem_finding;
                snprintf(out->detail, sizeof(out->detail),
                    "-> and %c%u, %c%u, #0x%" PRIx64,
                    w_or_x, rd, w_or_x, state->rem_xn, mask);
                snprintf(out->lines[state->rem_lines],
                    sizeof(out->lines[state->rem_lines]),
                    "%s %s", insn->mnemonic, insn->op_str);

                // The destination killed one temporary; defer on the
                // other until it is provably dead.
                unsigned gate = (rd == state->rem_xq)
                    ? state->rem_x8 : state->rem_xq;
                defer_dead_mov(state, out, gate);
            }
        }
        // Strict adjacency: clear regardless of match.
        state->rem_active = false;
    }

    // (2) Open: a UDIV whose divisor is a MOV-chain power of two?
    //     UDIV is Data-processing 2-source, opcode 000010. The
    //     quotient must be a fresh register: xq == xn would clobber
    //     the dividend the MSUB re-reads, xq == the constant would
    //     clobber the divisor it re-reads, and ZR operands are
    //     degenerate. N = 0 (dividing by 1) is the identity, a
    //     different idiom.
    if (state->mov_active
            && (op & 0x7FE0FC00u) == 0x1AC00800u) {
        unsigned sf = (op >> 31) & 1u;
        unsigned xq = op & 0x1Fu;
        unsigned xn = (op >> 5) & 0x1Fu;
        unsigned rm = (op >> 16) & 0x1Fu;
        uint64_t c = state->mov_value;
        unsigned datasize = sf ? 64u : 32u;
        if (((sf != 0) == state->mov_is_64bit)
                && rm == state->mov_rd
                && xq != 31 && xq != xn && xq != state->mov_rd
                && xn != 31 && xn != state->mov_rd
                && c != 0 && (c & (c - 1u)) == 0) {
            unsigned n = 0;
            for (uint64_t t = c; (t & 1u) == 0; t >>= 1) {
                n++;
            }
            if (n >= 1 && n < datasize) {
                char w_or_x = sf ? 'x' : 'w';
                armlint_finding *p = &state->rem_finding;
                p->name = "remainder by power of two foldable to AND";
                p->start_offset = state->mov_start_offset;
                p->insn_count = state->mov_insn_count + 2;
                clear_finding_strings(p);

                // Two lines are reserved for the UDIV and MSUB, so a
                // long chain truncates like the other MOV-chain folds.
                unsigned max_chain = ARMLINT_FINDING_LINES - 2u;
                unsigned chain_n = state->mov_insn_count;
                if (chain_n > max_chain) {
                    chain_n = max_chain;
                }
                for (unsigned i = 0; i < chain_n; i++) {
                    const mov_entry *e = &state->mov_entries[i];
                    const char *mov_mnem = e->opc == 2 ? "movz"
                                      : (e->opc == 0 ? "movn" : "movk");
                    unsigned mshift = (unsigned)e->shift_div_16 * 16u;
                    if (mshift == 0) {
                        snprintf(p->lines[i], sizeof(p->lines[i]),
                            "%s %c%u, #0x%x",
                            mov_mnem, w_or_x, state->mov_rd, e->imm16);
                    } else {
                        snprintf(p->lines[i], sizeof(p->lines[i]),
                            "%s %c%u, #0x%x, lsl #%u",
                            mov_mnem, w_or_x, state->mov_rd, e->imm16,
                            mshift);
                    }
                }
                snprintf(p->lines[chain_n], sizeof(p->lines[chain_n]),
                    "%s %s", insn->mnemonic, insn->op_str);

                state->rem_active = true;
                state->rem_is_64bit = (sf != 0);
                state->rem_xq = xq;
                state->rem_x8 = state->mov_rd;
                state->rem_xn = xn;
                state->rem_n = n;
                state->rem_lines = chain_n + 1;
            }
        }
    }

    return false;
}

bool check_fmul_fneg_fold(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->fmn_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Close: an in-place FNEG of the pending FMUL's destination,
    //     at the same precision? FNMUL's pseudocode is FPMul followed
    //     by FPNeg of the ROUNDED product -- negation is a pure sign
    //     flip, after rounding and raising nothing -- so the fold is
    //     bit-exact in every FPCR rounding mode with identical FPSR
    //     exceptions, NaNs included (both spellings apply the same
    //     FPNeg to the same FPMul result). Contrast the unsound
    //     sibling: negating an OPERAND first computes
    //     round(-(a*b)), which differs from -(round(a*b)) under the
    //     directed rounding modes, and is deliberately not matched.
    //     The FNEG must read the product (Rn == the FMUL's Rd). An
    //     in-place destination kills it structurally; a fresh one
    //     defers through the vector-register liveness scan.
    //     All three scalar writes zero the vector register above the
    //     lane, so the final 128-bit state is identical too.
    if (state->fmn_active) {
        if ((op & 0xFF3FFC00u) == 0x1E214000u) {
            unsigned type = (op >> 22) & 0x3u;
            unsigned rd = op & 0x1Fu;
            unsigned rn = (op >> 5) & 0x1Fu;
            if (type == state->fmn_type
                    && rn == state->fmn_rd) {
                char sd = state->fmn_type ? 'd' : 's';

                out->name = "FMUL + FNEG foldable to FNMUL";
                out->start_offset = state->fmn_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                snprintf(out->detail, sizeof(out->detail),
                    "-> fnmul %c%u, %c%u, %c%u",
                    sd, rd, sd, state->fmn_rn,
                    sd, state->fmn_rm);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->fmn_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);

                // The rewrite deletes both instructions; the product
                // register must be dead afterward. An in-place FNEG
                // overwrites it on the spot; a fresh destination
                // defers through the vector-register liveness scan.
                if (rd == state->fmn_rd) {
                    produced = true;
                } else {
                    defer_dead_fpreg(state, out, state->fmn_rd);
                }
            }
        }
        // Strict adjacency: clear regardless of match.
        state->fmn_active = false;
    }

    // (2) Open: a scalar FMUL? Single and double precision only;
    //     half precision (FEAT_FP16) is not matched, consistent with
    //     the FMOV folds.
    if ((op & 0xFF20FC00u) == 0x1E200800u) {
        unsigned type = (op >> 22) & 0x3u;
        if (type <= 1u) {
            state->fmn_active = true;
            state->fmn_type = type;
            state->fmn_rd = op & 0x1Fu;
            state->fmn_rn = (op >> 5) & 0x1Fu;
            state->fmn_rm = (op >> 16) & 0x1Fu;
            state->fmn_offset = offset;
            snprintf(state->fmn_disasm, sizeof(state->fmn_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
    }

    return produced;
}

bool check_ldr_cvtf_fold(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->lcv_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: a width-matched SCVTF/UCVTF of the loaded register?
    //     Loading the same bytes into the FP register and converting
    //     in-SIMD performs the identical conversion -- same 32/64-bit
    //     integer value, same FPCR rounding, same FPSR exceptions,
    //     and both spellings zero the vector register above the
    //     written lane -- without the GPR -> FP transfer the
    //     GPR-source form pays for (a separate several-cycle move on
    //     current cores; vendor optimization guides recommend exactly
    //     this rewrite). Widths must match on both sides: only the
    //     int32 -> single and int64 -> double pairs have an in-SIMD
    //     twin (there is no cross-width scalar conversion), which is
    //     also why only the plain W/X loads open below.
    if (state->lcv_active) {
        bool src_64, is_double, is_unsigned;
        unsigned c_rn, c_rd;
        if (decode_cvtf_from_gpr(op, &src_64, &is_double, &is_unsigned,
                                 &c_rn, &c_rd)
                && c_rn == state->lcv_rt
                && src_64 == state->lcv_is_64bit
                && is_double == state->lcv_is_64bit) {
            char sd = is_double ? 'd' : 's';
            const char *cvt = is_unsigned ? "ucvtf" : "scvtf";
            unsigned scale = state->lcv_is_64bit ? 8u : 4u;
            unsigned byte_off = state->lcv_imm12 * scale;
            char base_buf[8];
            if (state->lcv_rn == 31) {
                snprintf(base_buf, sizeof(base_buf), "sp");
            } else {
                snprintf(base_buf, sizeof(base_buf), "x%u",
                    state->lcv_rn);
            }

            out->name = "load + SCVTF/UCVTF via GPR foldable to "
                "FP load + convert";
            out->start_offset = state->lcv_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            if (byte_off == 0) {
                snprintf(out->detail, sizeof(out->detail),
                    "-> ldr %c%u, [%s] ; %s %c%u, %c%u",
                    sd, c_rd, base_buf, cvt, sd, c_rd, sd, c_rd);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> ldr %c%u, [%s, #0x%x] ; %s %c%u, %c%u",
                    sd, c_rd, base_buf, byte_off, cvt, sd, c_rd,
                    sd, c_rd);
            }
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->lcv_disasm);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %s", insn->mnemonic, insn->op_str);

            // The rewrite stops writing the GPR entirely, so the
            // loaded register must be dead afterward. The conversion
            // writes only an FP register and can never kill it, so
            // the finding always defers through the forward
            // register-liveness scan.
            state->lcv_active = false;
            return defer_dead_mov(state, out, state->lcv_rt);
        }
        // Strict adjacency: clear regardless of match.
        state->lcv_active = false;
    }

    // (2) Open: a plain unsigned-offset LDR W/X? The byte and
    //     halfword loads have no in-SIMD conversion width, and the
    //     sign-extending loads change the integer value's width, so
    //     neither opens. Rt = 31 discards the load.
    unsigned size, imm12, rn, rt;
    if (decode_ldr_uimm_any_size(op, &size, &imm12, &rn, &rt)
            && size >= 2u && rt != 31) {
        state->lcv_active = true;
        state->lcv_is_64bit = (size == 3u);
        state->lcv_rt = rt;
        state->lcv_rn = rn;
        state->lcv_imm12 = imm12;
        state->lcv_offset = offset;
        snprintf(state->lcv_disasm, sizeof(state->lcv_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return false;
}

// Single-instruction "MOV Rd, #imm" encodability: MOVZ (one non-zero
// halfword), MOVN (all-but-one halfwords all-ones at width), or a
// logical bitmask immediate (the ORR-ZR alias) -- exactly the forms
// the assembler accepts for the mov-immediate pseudo-instruction.
static bool mov_imm_encodable(uint64_t v, bool is_64)
{
    uint64_t mask = is_64 ? ~0ull : 0xFFFFFFFFull;
    v &= mask;
    unsigned hws = is_64 ? 4u : 2u;
    for (unsigned i = 0; i < hws; i++) {
        uint64_t hw = 0xFFFFull << (16u * i);
        if ((v & ~hw) == 0) {
            return true;                    // MOVZ
        }
        if (((v ^ mask) & ~hw) == 0) {
            return true;                    // MOVN
        }
    }
    return is_bitmask_immediate(v, is_64 ? 64u : 32u);
}

// AdvSimdExpandImm in reverse, integer forms: does a 128-bit pattern
// whose two 64-bit halves both equal `half` have a single MOVI/MVNI
// spelling? Every MOVI form replicates its element across the full
// vector, so equal halves are the caller's precondition. Checked
// smallest element first, so the simplest spelling wins: byte
// (16B), halfword (8H, LSL #0/8, MOVI then MVNI), word (4S,
// LSL #0/8/16/24 and the MSL "shifting ones", MOVI then MVNI), and
// finally the 2D per-byte mask (every byte 00 or FF). The FP-vector
// immediates (cmode 1111) are not attempted. Renders the winning
// spelling into buf.
static bool q_movi_spelling(uint64_t half, unsigned vt,
                            char *buf, size_t bufsz)
{
    uint64_t b0 = half & 0xFFu;
    if (half == 0x0101010101010101ull * b0) {
        snprintf(buf, bufsz, "movi v%u.16b, #0x%" PRIx64, vt, b0);
        return true;
    }

    uint64_t h0 = half & 0xFFFFu;
    if (half == 0x0001000100010001ull * h0) {
        uint64_t nh = ~h0 & 0xFFFFu;
        if ((h0 & 0xFF00u) == 0) {
            snprintf(buf, bufsz, "movi v%u.8h, #0x%" PRIx64, vt, h0);
            return true;
        }
        if ((h0 & 0x00FFu) == 0) {
            snprintf(buf, bufsz, "movi v%u.8h, #0x%" PRIx64 ", lsl #8",
                vt, h0 >> 8);
            return true;
        }
        if ((nh & 0xFF00u) == 0) {
            snprintf(buf, bufsz, "mvni v%u.8h, #0x%" PRIx64, vt, nh);
            return true;
        }
        if ((nh & 0x00FFu) == 0) {
            snprintf(buf, bufsz, "mvni v%u.8h, #0x%" PRIx64 ", lsl #8",
                vt, nh >> 8);
            return true;
        }
    }

    uint64_t w0 = half & 0xFFFFFFFFu;
    if (half == 0x0000000100000001ull * w0) {
        uint64_t nw = ~w0 & 0xFFFFFFFFu;
        for (unsigned s = 0; s < 32; s += 8) {
            if ((w0 & ~(0xFFull << s)) == 0) {
                if (s == 0) {
                    snprintf(buf, bufsz, "movi v%u.4s, #0x%" PRIx64,
                        vt, w0);
                } else {
                    snprintf(buf, bufsz,
                        "movi v%u.4s, #0x%" PRIx64 ", lsl #%u",
                        vt, w0 >> s, s);
                }
                return true;
            }
        }
        if ((w0 & 0xFFu) == 0xFFu && (w0 >> 8) <= 0xFFu) {
            snprintf(buf, bufsz, "movi v%u.4s, #0x%" PRIx64 ", msl #8",
                vt, w0 >> 8);
            return true;
        }
        if ((w0 & 0xFFFFu) == 0xFFFFu && (w0 >> 16) <= 0xFFu) {
            snprintf(buf, bufsz, "movi v%u.4s, #0x%" PRIx64 ", msl #16",
                vt, w0 >> 16);
            return true;
        }
        for (unsigned s = 0; s < 32; s += 8) {
            if ((nw & ~(0xFFull << s)) == 0) {
                if (s == 0) {
                    snprintf(buf, bufsz, "mvni v%u.4s, #0x%" PRIx64,
                        vt, nw);
                } else {
                    snprintf(buf, bufsz,
                        "mvni v%u.4s, #0x%" PRIx64 ", lsl #%u",
                        vt, nw >> s, s);
                }
                return true;
            }
        }
        if ((nw & 0xFFu) == 0xFFu && (nw >> 8) <= 0xFFu) {
            snprintf(buf, bufsz, "mvni v%u.4s, #0x%" PRIx64 ", msl #8",
                vt, nw >> 8);
            return true;
        }
        if ((nw & 0xFFFFu) == 0xFFFFu && (nw >> 16) <= 0xFFu) {
            snprintf(buf, bufsz, "mvni v%u.4s, #0x%" PRIx64 ", msl #16",
                vt, nw >> 16);
            return true;
        }
    }

    // MOVI .2D: each byte of the 64-bit element independently 00 or
    // FF (op = 1, cmode = 1110).
    bool mask_ok = true;
    for (unsigned i = 0; i < 8; i++) {
        unsigned byte = (unsigned)((half >> (8u * i)) & 0xFFu);
        if (byte != 0x00u && byte != 0xFFu) {
            mask_ok = false;
            break;
        }
    }
    if (mask_ok) {
        snprintf(buf, bufsz, "movi v%u.2d, #0x%016" PRIx64, vt, half);
        return true;
    }
    return false;
}

bool check_ldr_literal_const(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out)
{
    if (insn->size != 4 || state->buf == NULL) {
        return false;
    }

    uint32_t op = insn_word(insn);

    // LDR (literal): opc(31:30) 011 V 00 imm19 Rt. GPR (V = 0):
    // opc 00 = W, 01 = X, 10 = LDRSW (11 = PRFM, not a load).
    // SIMD&FP (V = 1): opc 00 = S, 01 = D, 10 = Q (11 unallocated).
    // W/X fold via the mov-immediate forms, LDRSW via the same at X
    // width after sign-extending the loaded word, S/D via FMOV-imm8,
    // and Q via the integer MOVI/MVNI immediates.
    if ((op & 0x3B000000u) != 0x18000000u) {
        return false;
    }
    unsigned opc = (op >> 30) & 0x3u;
    if (opc == 3u) {
        return false;
    }
    bool is_fp = ((op >> 26) & 1u) != 0;
    unsigned rt = op & 0x1Fu;
    if (!is_fp && rt == 31) {
        return false;   // literal load to ZR: a discarded load
    }

    // The pool must land inside the scanned buffer: the target is
    // PC-relative, so an out-of-section pool (or a truncated read at
    // the buffer edge) is silently skipped. LDRSW transfers 4 bytes;
    // the Q form 16.
    int64_t rel = ((int64_t)(int32_t)(op << 8) >> 13) * 4;
    int64_t target = (int64_t)offset + rel;
    unsigned nbytes;
    if (is_fp) {
        nbytes = 4u << opc;
    } else {
        nbytes = (opc == 1u) ? 8u : 4u;
    }
    if (target < 0 || (uint64_t)target + nbytes > state->buf_len) {
        return false;
    }

    uint64_t bits = 0;
    uint64_t bits_hi = 0;
    for (unsigned i = 0; i < nbytes && i < 8u; i++) {
        bits |= (uint64_t)state->buf[(size_t)target + i] << (8u * i);
    }
    for (unsigned i = 8; i < nbytes; i++) {
        bits_hi |= (uint64_t)state->buf[(size_t)target + i]
            << (8u * (i - 8u));
    }

    char detail[ARMLINT_FINDING_LINE_LEN];
    if (is_fp && opc == 2u) {
        // Q: every MOVI form replicates across the full vector, so
        // unequal halves can never fold.
        char spell_buf[64];
        if (bits != bits_hi
                || !q_movi_spelling(bits, rt, spell_buf,
                                    sizeof(spell_buf))) {
            return false;
        }
        snprintf(detail, sizeof(detail), "-> %s", spell_buf);
    } else if (is_fp) {
        bool is_64 = opc == 1u;
        if (!fp8_encodable(bits, is_64)) {
            return false;
        }
        double dval;
        if (is_64) {
            memcpy(&dval, &bits, sizeof(dval));
        } else {
            float fval;
            uint32_t b32 = (uint32_t)bits;
            memcpy(&fval, &b32, sizeof(fval));
            dval = (double)fval;
        }
        char val_buf[32];
        format_fp8(val_buf, sizeof(val_buf), dval);
        snprintf(detail, sizeof(detail), "-> fmov %c%u, #%s",
            is_64 ? 'd' : 's', rt, val_buf);
    } else {
        // LDRSW writes the sign-extension of the loaded word, so its
        // materialisation is the 64-bit sign-extended value.
        bool is_64 = opc != 0u;
        if (opc == 2u) {
            bits = (uint64_t)(int64_t)(int32_t)(uint32_t)bits;
        }
        if (!mov_imm_encodable(bits, is_64)) {
            return false;
        }
        snprintf(detail, sizeof(detail), "-> mov %c%u, #0x%" PRIx64,
            is_64 ? 'x' : 'w', rt, bits);
    }

    // A one-for-one rewrite: same destination, no other register or
    // flag touched, and the loaded value is reproduced exactly, so
    // the finding emits immediately -- no liveness proof needed. The
    // win is the removed memory access (load-use latency and a cache
    // line); the pool slot itself is only reclaimed if nothing else
    // references it.
    out->name = "LDR literal foldable to MOV/FMOV immediate";
    out->start_offset = offset;
    out->insn_count = 1;
    clear_finding_strings(out);
    snprintf(out->detail, sizeof(out->detail), "%s", detail);
    snprintf(out->lines[0], sizeof(out->lines[0]),
        "%s %s", insn->mnemonic, insn->op_str);
    return true;
}

bool check_adr_fold(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->adf_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    if (state->adf_active) {
        unsigned t = state->adf_rd;

        // (1a) Close: a zero-offset load through the address? Every
        //     literal-capable width folds -- LDR W/X, LDRSW, and the
        //     SIMD&FP S/D/Q -- to LDR (literal), which performs the
        //     identical access (same address, same size) without
        //     materialising the address at all. The byte and halfword
        //     loads have no literal form and never fold.
        //
        //     Encodability: the literal's imm19 is word-scaled and
        //     anchored at the LOAD's PC, one instruction after the
        //     ADR's -- the target must be 4-byte aligned (ADR can
        //     name any byte) and the re-anchored displacement must
        //     still fit +/-1MB (it can fall off the low edge when
        //     the ADR named exactly -1MB). The target may lie outside
        //     the scanned buffer: the original pair accessed it too,
        //     and the fold never reads the data.
        bool is_load = false;
        bool structural = false;
        char rt_buf[8];
        const char *ld_mnem = NULL;
        {
            unsigned size, imm12, rn, rt;
            unsigned fp_lg2 = 0;
            bool fp_is_load = false;
            if (decode_ldr_uimm_any_size(op, &size, &imm12, &rn, &rt)
                    && size >= 2u && imm12 == 0 && rn == t) {
                is_load = true;
                ld_mnem = "ldr";
                structural = rt == t;
                format_reg(rt_buf, sizeof(rt_buf),
                    size == 3u ? 'x' : 'w', rt);
            } else if (decode_ldrsw_uimm(op, &imm12, &rn, &rt)
                    && imm12 == 0 && rn == t) {
                is_load = true;
                ld_mnem = "ldrsw";
                structural = rt == t;
                format_reg(rt_buf, sizeof(rt_buf), 'x', rt);
            } else if (decode_fp_ldr_str_uimm(op, &fp_is_load, &fp_lg2,
                                              &imm12, &rn, &rt)
                    && fp_is_load && fp_lg2 >= 2u && imm12 == 0
                    && rn == t) {
                // An FP destination can never overwrite the GPR
                // address, so this arm always defers.
                is_load = true;
                ld_mnem = "ldr";
                static const char fp_class[5] = { 'b', 'h', 's', 'd',
                                                  'q' };
                snprintf(rt_buf, sizeof(rt_buf), "%c%u",
                    fp_class[fp_lg2], rt);
            }
        }
        if (is_load) {
            int64_t disp = state->adf_target
                - (int64_t)(state->adf_offset + 4u);
            if ((disp & 3) == 0
                    && disp >= -(int64_t)0x100000
                    && disp <= 0xFFFFC) {
                out->name = "ADR + load of its target foldable to "
                    "LDR (literal)";
                out->start_offset = state->adf_offset;
                out->insn_count = 2;
                clear_finding_strings(out);
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, #0x%" PRIx64,
                    ld_mnem, rt_buf, (uint64_t)state->adf_target);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->adf_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);

                // The rewrite deletes the ADR; the address register
                // must be dead afterward. A load whose destination IS
                // that register kills it on the spot; otherwise the
                // finding defers through the forward
                // register-liveness scan.
                if (structural) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, t);
                }
            }
        }

        // (1b) Close: BR of the address? The target is statically
        //     known, so the indirect branch is a direct b -- and B's
        //     +/-128MB range strictly covers ADR's +/-1MB, so no
        //     range check is needed. BR never writes the address
        //     register and the linear liveness scan cannot follow the
        //     branch, so v1 folds only x16/x17 (IP0/IP1): the ABI
        //     reserves them as veneer scratch, and code at the target
        //     is not entitled to receive values in them across
        //     exactly this shape. BLR is excluded outright -- a
        //     callee legitimately receives registers, x8 in
        //     particular (the indirect-result pointer).
        if ((op & 0xFFFFFC1Fu) == 0xD61F0000u) {
            unsigned rn = (op >> 5) & 0x1Fu;
            if (rn == t && (t == 16u || t == 17u)) {
                out->name = "ADR + BR foldable to direct branch";
                out->start_offset = state->adf_offset;
                out->insn_count = 2;
                clear_finding_strings(out);
                snprintf(out->detail, sizeof(out->detail),
                    "-> b #0x%" PRIx64, (uint64_t)state->adf_target);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->adf_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);
                produced = true;
            }
        }

        // Strict adjacency: clear regardless of match.
        state->adf_active = false;
    }

    // (2) Open: an ADR? ADRP (op = 1) computes a page address --
    //     different arithmetic, different fold -- and Rd = 31 is a
    //     dead write (ADR has no SP form).
    if ((op & 0x9F000000u) == 0x10000000u) {
        unsigned rd = op & 0x1Fu;
        if (rd != 31) {
            unsigned immlo = (op >> 29) & 0x3u;
            uint32_t immhi = (op >> 5) & 0x7FFFFu;
            int64_t disp = (int64_t)(int32_t)((immhi << 2 | immlo) << 11)
                >> 11;
            state->adf_active = true;
            state->adf_rd = rd;
            state->adf_target = (int64_t)offset + disp;
            state->adf_offset = offset;
            snprintf(state->adf_disasm, sizeof(state->adf_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
    }

    return produced;
}

bool check_cssc_minmax(armlint_state *state, const cs_insn *insn,
                       size_t offset, armlint_finding *out)
{
    if (insn->size != 4 || !(state->features & ARMLINT_FEATURE_CSSC)) {
        state->cmx_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: a CSEL selecting between the compared registers?
    //     CSSC's MAX/MIN family computes the pair in one instruction:
    //       cmp x1, x2 ; csel x0, x1, x2, gt -> smax x0, x1, x2
    //     Signedness and direction come from the condition -- GT/GE
    //     pick the larger (the equal case selects equal values, so
    //     both conditions work), LT/LE the smaller, HI/HS and LO/LS
    //     their unsigned twins -- and swapped CSEL operands flip the
    //     direction. The rewrite reads the same registers (the pair
    //     left them unchanged) but DELETES the compare and sets no
    //     flags, so emission defers until NZCV is provably dead.
    //     Rd = 31 discards the select.
    if (state->cmx_active) {
        if ((op & 0x7FE00C00u) == 0x1A800000u) {
            unsigned c_sf = (op >> 31) & 1u;
            unsigned c_rd = op & 0x1Fu;
            unsigned c_rn = (op >> 5) & 0x1Fu;
            unsigned c_rm = (op >> 16) & 0x1Fu;
            unsigned cond = (op >> 12) & 0xFu;
            bool direct = c_rn == state->cmx_rn && c_rm == state->cmx_rm;
            bool swapped = c_rn == state->cmx_rm && c_rm == state->cmx_rn;
            const char *mnem = NULL;
            if (((c_sf != 0) == state->cmx_is_64bit)
                    && c_rd != 31 && (direct || swapped)) {
                // Selecting the first compared operand when it wins
                // the comparison is MAX; swapped operands invert.
                switch (cond) {
                case 10: case 12:               // GE, GT
                    mnem = direct ? "smax" : "smin";
                    break;
                case 11: case 13:               // LT, LE
                    mnem = direct ? "smin" : "smax";
                    break;
                case 2: case 8:                 // HS, HI
                    mnem = direct ? "umax" : "umin";
                    break;
                case 3: case 9:                 // LO, LS
                    mnem = direct ? "umin" : "umax";
                    break;
                default:
                    break;
                }
            }
            if (mnem != NULL) {
                char w_or_x = state->cmx_is_64bit ? 'x' : 'w';
                char rn_buf[8], rm_buf[8], crn_buf[8], crm_buf[8];
                format_reg(rn_buf, sizeof(rn_buf), w_or_x,
                    state->cmx_rn);
                format_reg(rm_buf, sizeof(rm_buf), w_or_x,
                    state->cmx_rm);
                format_reg(crn_buf, sizeof(crn_buf), w_or_x, c_rn);
                format_reg(crm_buf, sizeof(crm_buf), w_or_x, c_rm);

                out->name = "CMP + CSEL foldable to MAX/MIN (CSSC)";
                out->start_offset = state->cmx_offset;
                out->insn_count = 2;
                clear_finding_strings(out);
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %c%u, %s, %s",
                    mnem, w_or_x, c_rd, rn_buf, rm_buf);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->cmx_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "csel %c%u, %s, %s, %s",
                    w_or_x, c_rd, crn_buf, crm_buf,
                    a64_cond_names[cond]);
                defer_dead_nzcv_cssc(state, out);
            }
        }
        // Strict adjacency: clear regardless of match.
        state->cmx_active = false;
    }

    // (2) Open: a plain register compare (CMP shifted-register,
    //     LSL #0)? Identical operands are degenerate (max(a, a));
    //     the immediate and extended forms have no register pair to
    //     select between.
    if ((op & 0x7FE0FC1Fu) == 0x6B00001Fu) {
        unsigned rn = (op >> 5) & 0x1Fu;
        unsigned rm = (op >> 16) & 0x1Fu;
        if (rn != rm) {
            state->cmx_active = true;
            state->cmx_is_64bit = ((op >> 31) & 1u) != 0;
            state->cmx_rn = rn;
            state->cmx_rm = rm;
            state->cmx_offset = offset;
            snprintf(state->cmx_disasm, sizeof(state->cmx_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
    }

    return false;
}

bool check_cssc_abs(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out)
{
    if (insn->size != 4 || !(state->features & ARMLINT_FEATURE_CSSC)) {
        state->cab_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: a CNEG of the compared register that negates exactly
    //     the negative (or non-positive) case? CNEG Rd, Rn, cond is
    //     CSNEG Rd, Rn, Rn, !cond, so the raw match is a CSNEG with
    //     both sources equal to the compared register and a condition
    //     in {PL, GE, GT}: cond ? r : -r computes |r| when the
    //     condition holds exactly for r >= 0 (PL; GE with V = 0 after
    //     a zero compare) or r > 0 (GT: the r = 0 else-branch yields
    //     -0 = 0). The rewrite is CSSC's ABS, which reads the same
    //     register but DELETES the compare and sets no flags, so
    //     emission defers until NZCV is provably dead. Rd = 31
    //     discards the result.
    if (state->cab_active) {
        if ((op & 0x7FE00C00u) == 0x5A800400u) {
            unsigned c_sf = (op >> 31) & 1u;
            unsigned c_rd = op & 0x1Fu;
            unsigned c_rn = (op >> 5) & 0x1Fu;
            unsigned c_rm = (op >> 16) & 0x1Fu;
            unsigned cond = (op >> 12) & 0xFu;
            if (((c_sf != 0) == state->cab_is_64bit)
                    && c_rd != 31
                    && c_rn == state->cab_rn && c_rm == state->cab_rn
                    && (cond == 5u || cond == 10u || cond == 12u)) {
                char w_or_x = state->cab_is_64bit ? 'x' : 'w';

                out->name = "CMP #0 + CNEG foldable to ABS (CSSC)";
                out->start_offset = state->cab_offset;
                out->insn_count = 2;
                clear_finding_strings(out);
                snprintf(out->detail, sizeof(out->detail),
                    "-> abs %c%u, %c%u",
                    w_or_x, c_rd, w_or_x, state->cab_rn);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->cab_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);
                defer_dead_nzcv_cssc(state, out);
            }
        }
        // Strict adjacency: clear regardless of match.
        state->cab_active = false;
    }

    // (2) Open: CMP Rn, #0 (SUBS immediate, Rd = 31, imm12 = 0; both
    //     shift encodings of zero)? Rn = 31 compares SP, which ABS
    //     cannot name.
    if ((op & 0x7F80001Fu) == 0x7100001Fu
            && ((op >> 10) & 0xFFFu) == 0
            && ((op >> 22) & 0x3u) < 2u) {
        unsigned rn = (op >> 5) & 0x1Fu;
        if (rn != 31) {
            state->cab_active = true;
            state->cab_is_64bit = ((op >> 31) & 1u) != 0;
            state->cab_rn = rn;
            state->cab_offset = offset;
            snprintf(state->cab_disasm, sizeof(state->cab_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
    }

    return false;
}

bool check_cssc_ctz(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out)
{
    if (insn->size != 4 || !(state->features & ARMLINT_FEATURE_CSSC)) {
        state->rbc_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Close: a CLZ of the bit-reversed register? Counting leading
    //     zeros of a bit reversal counts trailing zeros of the
    //     original -- CSSC's CTZ in one instruction. The rewrite
    //     reads the RBIT's own source, which still holds its original
    //     value at the consumer once the RBIT is deleted (even for
    //     the in-place rbit wt, wt); no flags are involved. The
    //     reversed value must be dead: a CLZ destination that IS the
    //     reversed register kills it structurally, otherwise the
    //     finding defers through the forward register-liveness scan.
    if (state->rbc_active) {
        if ((op & 0x7FFFFC00u) == 0x5AC01000u) {
            unsigned c_sf = (op >> 31) & 1u;
            unsigned c_rd = op & 0x1Fu;
            unsigned c_rn = (op >> 5) & 0x1Fu;
            if (((c_sf != 0) == state->rbc_is_64bit)
                    && c_rn == state->rbc_rd
                    && c_rd != 31) {
                char w_or_x = state->rbc_is_64bit ? 'x' : 'w';

                out->name = "RBIT + CLZ foldable to CTZ (CSSC)";
                out->start_offset = state->rbc_offset;
                out->insn_count = 2;
                clear_finding_strings(out);
                snprintf(out->detail, sizeof(out->detail),
                    "-> ctz %c%u, %c%u",
                    w_or_x, c_rd, w_or_x, state->rbc_rs);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->rbc_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);

                if (c_rd == state->rbc_rd) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, state->rbc_rd);
                }
            }
        }
        // Strict adjacency: clear regardless of match.
        state->rbc_active = false;
    }

    // (2) Open: an RBIT? Rd = 31 is a dead write; Rs = 31 reverses
    //     the zero register, a constant idiom.
    if ((op & 0x7FFFFC00u) == 0x5AC00000u) {
        unsigned rd = op & 0x1Fu;
        unsigned rs = (op >> 5) & 0x1Fu;
        if (rd != 31 && rs != 31) {
            state->rbc_active = true;
            state->rbc_is_64bit = ((op >> 31) & 1u) != 0;
            state->rbc_rd = rd;
            state->rbc_rs = rs;
            state->rbc_offset = offset;
            snprintf(state->rbc_disasm, sizeof(state->rbc_disasm),
                "%s %s", insn->mnemonic, insn->op_str);
        }
    }

    return produced;
}

// FMOV (scalar, immediate) encodability: VFPExpandImm in reverse.
// imm8 = a:b:cd:efgh expands to
//   sign = a,  exp = NOT(b) : Replicate(b, 8 or 5) : cd,
//   frac = efgh : Zeros(48 or 19)
// i.e. the 256 values +/-(16..31)/16 * 2^n, n in [-3, 4]. Zero,
// infinities, NaNs and denormals all fail the exponent shape; extra
// fraction bits fail the low-zeros test. Pure bit inspection -- no
// floating-point comparison. The caller passes the 32-bit pattern in
// the low half for !is_double.
static bool fp8_encodable(uint64_t bits, bool is_double)
{
    if (is_double) {
        if ((bits & 0xFFFFFFFFFFFFull) != 0) {
            return false;
        }
        unsigned exp = (unsigned)((bits >> 52) & 0x7FFu);
        // NOT(b):Replicate(b,8):cd -> 0b0_11111111_cd or 0b1_00000000_cd.
        return (exp >= 0x3FCu && exp <= 0x3FFu)
            || (exp >= 0x400u && exp <= 0x403u);
    }
    if ((bits & 0x7FFFFu) != 0) {
        return false;
    }
    unsigned exp = (unsigned)((bits >> 23) & 0xFFu);
    // NOT(b):Replicate(b,5):cd -> 0b0_11111_cd or 0b1_00000_cd.
    return (exp >= 0x7Cu && exp <= 0x7Fu)
        || (exp >= 0x80u && exp <= 0x83u);
}

// Render an FMOV-encodable value in its assembler spelling: 1.0, -0.5,
// 0.2421875. Encodable values are (16..31)/16 * 2^n with n in [-3, 4],
// so nine significant digits always print exactly; a bare integer
// gains ".0" so the operand reads as floating-point.
static void format_fp8(char *buf, size_t bufsz, double v)
{
    int n = snprintf(buf, bufsz, "%.9g", v);
    if (n > 0 && (size_t)n + 2 < bufsz && strchr(buf, '.') == NULL) {
        buf[n] = '.';
        buf[n + 1] = '0';
        buf[n + 2] = '\0';
    }
}

// FMOV (general), GPR -> FPR direction only:
//   sf 0 0 11110 type 1 rmode(00) opcode(111) 000000 Rn Rd
// Exactly two allocated forms move a whole GPR into a scalar
// single/double register: fmov Sd, Wn (sf=0, type=00, 0x1E270000) and
// fmov Dd, Xn (sf=1, type=01, 0x9E670000). The FPR -> GPR direction
// (opcode 110), the upper-half form (rmode 01) and the half-precision
// form (type 11, FEAT_FP16) fall outside the two exact matches.
static bool decode_fmov_from_gpr(uint32_t op, bool *out_is_double,
                                 unsigned *out_rn, unsigned *out_rd)
{
    uint32_t hi = op & 0xFFFFFC00u;
    if (hi == 0x1E270000u) {
        *out_is_double = false;
    } else if (hi == 0x9E670000u) {
        *out_is_double = true;
    } else {
        return false;
    }
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rd = op & 0x1Fu;
    return true;
}

// SCVTF/UCVTF (scalar, from GPR):
//   sf 0 0 11110 type 1 rmode(00) opcode(01 u) 000000 Rn Rd
// Mask 0x7FBEFC00 fixes everything but sf (source GPR width), type's
// low bit (single/double destination; type's high bit stays 0, which
// excludes the half-precision forms) and u (signed/unsigned). rmode
// and the opcode high bits exclude the FCVT* round-to-int family.
static bool decode_cvtf_from_gpr(uint32_t op, bool *out_src_64,
                                 bool *out_is_double,
                                 bool *out_is_unsigned,
                                 unsigned *out_rn, unsigned *out_rd)
{
    if ((op & 0x7FBEFC00u) != 0x1E220000u) {
        return false;
    }
    *out_src_64 = ((op >> 31) & 1u) != 0;
    *out_is_double = ((op >> 22) & 1u) != 0;
    *out_is_unsigned = ((op >> 16) & 1u) != 0;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rd = op & 0x1Fu;
    return true;
}

bool check_mov_fmov_imm_fold(armlint_state *state, const cs_insn *insn,
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

    // Consumer: FMOV (general, GPR->FPR) or SCVTF/UCVTF from a GPR.
    // src_64 is the GPR source's width, is_double the FP destination's.
    bool is_fmov, is_double, is_unsigned = false, src_64;
    unsigned rn, rd;
    if (decode_fmov_from_gpr(op, &is_double, &rn, &rd)) {
        is_fmov = true;
        src_64 = is_double;     // fmov Sd, Wn / fmov Dd, Xn only
    } else if (decode_cvtf_from_gpr(op, &src_64, &is_double,
                                    &is_unsigned, &rn, &rd)) {
        is_fmov = false;
    } else {
        return false;
    }

    if (rn != state->mov_rd) {
        return false;
    }

    // Width admission mirrors the register-offset fold: a 64-bit
    // source also accepts a W-form chain, whose W write zeroed
    // X[63:32] and so pins the full 64-bit read. A W source requires
    // a W chain -- reading the low half of an X-form constant is a
    // pathological shape not worth matching.
    if (!src_64 && state->mov_is_64bit) {
        return false;
    }

    // The FP value the destination receives, as its exact bit pattern.
    // For the conversions, soundness requires the conversion be exact:
    // SCVTF/UCVTF round per the dynamic FPCR mode, and only exactness
    // makes the result mode-independent (an exact conversion raises no
    // FP exceptions either, preserving FPSR). Encodability already
    // implies it -- an imm8 value's magnitude is at most 31.5, so the
    // integer's is at most 31 -- but the round-trip check enforces it
    // explicitly. Casting back is safe only after the encodability
    // test bounds the value.
    double value;
    if (is_fmov) {
        uint64_t bits = state->mov_value;
        if (!fp8_encodable(bits, is_double)) {
            return false;
        }
        if (is_double) {
            memcpy(&value, &bits, sizeof(value));
        } else {
            uint32_t b32 = (uint32_t)bits;
            float f;
            memcpy(&f, &b32, sizeof(f));
            value = (double)f;
        }
    } else {
        // The source GPR's contents: an X read of a W chain sees the
        // zero-extended (hence non-negative) stored value; a W read
        // sign-extends the 32-bit pattern when the conversion is
        // signed.
        uint64_t uval = state->mov_value;
        int64_t sval = src_64 ? (int64_t)state->mov_value
            : (int64_t)(int32_t)(uint32_t)state->mov_value;
        if (is_double) {
            double d = is_unsigned ? (double)uval : (double)sval;
            uint64_t b;
            memcpy(&b, &d, sizeof(b));
            if (!fp8_encodable(b, true)) {
                return false;
            }
            if (is_unsigned ? (uint64_t)d != uval : (int64_t)d != sval) {
                return false;
            }
            value = d;
        } else {
            float f = is_unsigned ? (float)uval : (float)sval;
            uint32_t b32;
            memcpy(&b32, &f, sizeof(b32));
            if (!fp8_encodable(b32, false)) {
                return false;
            }
            if (is_unsigned ? (uint64_t)f != uval : (int64_t)f != sval) {
                return false;
            }
            value = (double)f;
        }
    }

    char fp_c = is_double ? 'd' : 's';
    char src_c = src_64 ? 'x' : 'w';
    const char *mnem = is_fmov ? "fmov"
        : (is_unsigned ? "ucvtf" : "scvtf");

    char val_buf[32];
    format_fp8(val_buf, sizeof(val_buf), value);

    out->name = "MOV + FMOV/SCVTF/UCVTF foldable to FMOV immediate";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    snprintf(out->detail, sizeof(out->detail),
        "-> fmov %c%u, #%s", fp_c, rd, val_buf);

    // Chain lines render in the chain's own width; the consumer line
    // in the source width (they differ for a W chain read as X).
    char w_or_x = state->mov_is_64bit ? 'x' : 'w';
    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mov_mnem = e->opc == 2 ? "movz"
                          : (e->opc == 0 ? "movn" : "movk");
        unsigned mshift = (unsigned)e->shift_div_16 * 16u;
        if (mshift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, w_or_x, state->mov_rd, e->imm16, mshift);
        }
    }
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s %c%u, %c%u", mnem, fp_c, rd, src_c, rn);

    // The rewrite deletes the MOV, and the consumer writes only an FP
    // register -- it can never kill the constant GPR itself -- so the
    // finding always defers until mov_rd is provably dead.
    return defer_dead_mov(state, out, state->mov_rd);
}

// Arrangement specifiers for DUP (general) and the MOVI rewrite,
// indexed by element-size log2 and Q. The 64-bit element without Q
// ("1d") is RESERVED and never decoded.
static const char *const dup_arrangements[4][2] = {
    { "8b", "16b" },
    { "4h", "8h" },
    { "2s", "4s" },
    { NULL, "2d" },
};

// DUP (general) -- broadcast a GPR into every vector lane:
//   0 Q 0 01110000 imm5 000011 Rn Rd
// imm5's lowest set bit selects the element size (B/H/S read Wn, D
// reads Xn). imm5 with none of the low four bits set is UNALLOCATED,
// and the D element requires Q (there is no "1d" arrangement). Bits
// 15..10 distinguish this from DUP (element) (000001) and the INS
// forms, so partial-lane writes never match.
static bool decode_dup_from_gpr(uint32_t op, unsigned *out_q,
                                unsigned *out_esz, unsigned *out_rn,
                                unsigned *out_rd)
{
    if ((op & 0xBFE0FC00u) != 0x0E000C00u) {
        return false;
    }
    unsigned imm5 = (op >> 16) & 0x1Fu;
    unsigned q = (op >> 30) & 1u;
    unsigned esz;
    if (imm5 & 1u) {
        esz = 0;
    } else if (imm5 & 2u) {
        esz = 1;
    } else if (imm5 & 4u) {
        esz = 2;
    } else if (imm5 & 8u) {
        esz = 3;
    } else {
        return false;           // UNALLOCATED
    }
    if (esz == 3u && q == 0u) {
        return false;           // RESERVED
    }
    *out_q = q;
    *out_esz = esz;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rd = op & 0x1Fu;
    return true;
}

bool check_fp_zero_to_movi(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        return false;
    }

    uint32_t op = insn_word(insn);

    // A GPR -> FP/vector consumer whose result, given a zero source,
    // is an all-zeros register: FMOV (general, GPR->FPR), SCVTF/UCVTF
    // (integer zero converts to +0.0 -- the all-zeros pattern -- in
    // every FPCR rounding mode: FixedToFP returns FPZero for a zero
    // input, signed or not, raising no exceptions), or DUP (general)
    // broadcasting the zero into every lane. All three zero the
    // vector register above what they write, exactly as MOVI #0 does,
    // so the final register state is bit-identical.
    bool is_dup = false;
    bool is_double, is_unsigned, src_64;
    unsigned rn, rd, q = 0, esz = 0;
    if (decode_fmov_from_gpr(op, &is_double, &rn, &rd)) {
        src_64 = is_double;
    } else if (decode_cvtf_from_gpr(op, &src_64, &is_double,
                                    &is_unsigned, &rn, &rd)) {
        // (signedness is irrelevant for a zero source)
    } else if (decode_dup_from_gpr(op, &q, &esz, &rn, &rd)) {
        is_dup = true;
        src_64 = (esz == 3u);
    } else {
        return false;
    }
    (void)is_double;
    (void)is_unsigned;

    // The zero source: the zero register itself, or a MOV-chain
    // register whose pinned value is zero. Width admission matches
    // the FMOV immediate fold: a 64-bit source also accepts a W-form
    // chain (the W write zeroed X[63:32]); a W source requires a W
    // chain.
    bool from_zr = (rn == 31u);
    if (!from_zr) {
        if (!state->mov_active || rn != state->mov_rd
                || state->mov_value != 0
                || (!src_64 && state->mov_is_64bit)) {
            return false;
        }
    }

    // The rewrite: scalar consumers all become the canonical 64-bit
    // scalar zeroing (the whole vector register ends up zero either
    // way); DUP keeps its arrangement.
    char movi_buf[24];
    if (is_dup) {
        snprintf(movi_buf, sizeof(movi_buf), "movi v%u.%s, #0",
            rd, dup_arrangements[esz][q]);
    } else {
        snprintf(movi_buf, sizeof(movi_buf), "movi d%u, #0", rd);
    }

    out->name = "FP/vector zeroing via GPR foldable to MOVI";
    clear_finding_strings(out);
    snprintf(out->detail, sizeof(out->detail), "-> %s", movi_buf);

    // Reading ZR directly, the rewrite is one-for-one -- MOVI zeroes
    // on the FP side instead of crossing the register files -- with
    // no deleted write, so it emits immediately.
    if (from_zr) {
        out->start_offset = offset;
        out->insn_count = 1;
        snprintf(out->lines[0], sizeof(out->lines[0]),
            "%s %s", insn->mnemonic, insn->op_str);
        return true;
    }

    // The chain form also deletes the MOV #0 (this consumer is
    // deliberately not in the MOV #0 -> ZR check's set: substituting
    // WZR would still leave the cross-file transfer that MOVI
    // eliminates). The consumer writes only an FP register and never
    // kills the constant GPR, so the finding always defers until it
    // provably dies.
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;

    char w_or_x = state->mov_is_64bit ? 'x' : 'w';
    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mov_mnem = e->opc == 2 ? "movz"
                          : (e->opc == 0 ? "movn" : "movk");
        unsigned mshift = (unsigned)e->shift_div_16 * 16u;
        if (mshift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, w_or_x, state->mov_rd, e->imm16, mshift);
        }
    }
    snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
        "%s %s", insn->mnemonic, insn->op_str);

    return defer_dead_mov(state, out, state->mov_rd);
}

bool check_extend_cvtf_fold(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->xtc_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: a 64-bit-source SCVTF/UCVTF reading the extended
    //     register? The W-source form performs the extension itself,
    //     so the pair converts the same mathematical value -- an
    //     exact identity in every FPCR rounding mode.
    if (state->xtc_active) {
        state->xtc_active = false;      // strict adjacency
        bool src_64, is_double, is_unsigned;
        unsigned c_rn, c_rd;
        if (decode_cvtf_from_gpr(op, &src_64, &is_double, &is_unsigned,
                                 &c_rn, &c_rd)
                && src_64
                && c_rn == state->xtc_rd
                // A sign-extended source folds only into the signed
                // conversion: the unsigned reading of sext(negative)
                // is a huge value, not the 32-bit one. A zero-extended
                // source folds into either -- its 64-bit value IS the
                // unsigned 32-bit value -- and both spell UCVTF of the
                // W register.
                && !(state->xtc_signed && is_unsigned)) {
            const char *new_mnem =
                state->xtc_signed ? "scvtf" : "ucvtf";
            char fp_c = is_double ? 'd' : 's';

            out->name = "widening extend + SCVTF/UCVTF foldable to "
                        "W-form conversion";
            out->start_offset = state->xtc_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            snprintf(out->detail, sizeof(out->detail),
                "-> %s %c%u, w%u",
                new_mnem, fp_c, c_rd, state->xtc_rn);
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->xtc_disasm);
            snprintf(out->lines[1], sizeof(out->lines[1]),
                "%s %s", insn->mnemonic, insn->op_str);

            // The rewrite deletes the extend and instead reads its
            // source, which the adjacent pair leaves unchanged (even
            // in-place: SXTW and MOV Wd, Wm keep the low 32 bits of
            // their destination equal to the source). The conversion
            // writes only an FP register and can never kill the
            // extended GPR itself, so the finding always defers until
            // it provably dies.
            return defer_dead_mov(state, out, state->xtc_rd);
        }
    }

    // (2) Open: SXTW Xd, Wn, or the zero-extending MOV Wd, Wm
    //     (ORR Wd, WZR, Wm, LSL #0) -- the canonical uint32 -> 64
    //     widening, whose W write zeroes the upper half. ZR operands
    //     are degenerate (a constant-zero extend).
    unsigned s_s, s_w, p_rd, p_rn;
    if (decode_sbfm_sext(op, &s_s, &s_w, &p_rd, &p_rn)
            && s_s == 32u && p_rd != 31 && p_rn != 31) {
        state->xtc_active = true;
        state->xtc_signed = true;
        state->xtc_rd = p_rd;
        state->xtc_rn = p_rn;
        state->xtc_offset = offset;
        snprintf(state->xtc_disasm, sizeof(state->xtc_disasm),
            "sxtw x%u, w%u", p_rd, p_rn);
    } else if ((op & 0xFFE0FFE0u) == 0x2A0003E0u) {
        unsigned m_rd = op & 0x1Fu;
        unsigned m_rm = (op >> 16) & 0x1Fu;
        if (m_rd != 31 && m_rm != 31) {
            state->xtc_active = true;
            state->xtc_signed = false;
            state->xtc_rd = m_rd;
            state->xtc_rn = m_rm;
            state->xtc_offset = offset;
            snprintf(state->xtc_disasm, sizeof(state->xtc_disasm),
                "mov w%u, w%u", m_rd, m_rm);
        }
    }

    return false;
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
    //     The rewrite deletes the MUL, so the product register must be
    //     dead afterward: a consumer that overwrites it proves that on
    //     the spot, and one writing a fresh register defers through
    //     the forward register-liveness scan (Rd = 31 is a dead write
    //     and excluded).
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
            if (rd != 31) {
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
            // An ADD whose other operand is XZR adds nothing -- the
            // pair is MUL + register copy, not an accumulate; a MADD
            // with a ZR accumulator would just respell the MUL. (The
            // SUB form with xc == 31 is NEG, the MNEG fold below.)
            if (valid && !is_sub && xc == 31) {
                valid = false;
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
                if (produced && rd != t) {
                    produced = defer_dead_mov(state, out, t);
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
    //     rejected. The rewrite deletes the multiply, so the product
    //     register must be dead afterward: a consumer that overwrites
    //     it proves that on the spot, and one writing a fresh register
    //     defers through the forward register-liveness scan (Rd = 31
    //     is a dead write and excluded).
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
            if (rd != 31) {
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
            // An ADD whose other operand is XZR adds nothing -- the
            // pair is a multiply + register copy, not an accumulate.
            // (The SUB form with xc == 31 is NEG, the SMNEGL/UMNEGL
            // fold below.)
            if (valid && !is_sub && xc == 31) {
                valid = false;
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
                if (produced && rd != t) {
                    produced = defer_dead_mov(state, out, t);
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
    //     The rewrite deletes the NEG, so its destination must be dead
    //     afterward: a consumer that overwrites it proves that on the
    //     spot, and one writing a fresh register defers through the
    //     forward register-liveness scan (Rd = 31 is a dead write and
    //     excluded). The surviving operand must not be XZR either:
    //     "add xd, xzr, xt" is a register copy of the negation (its
    //     fold is NEG, not this rewrite) and "sub xd, xzr, xt" is
    //     NEG of the negation (a plain copy) -- both are double-
    //     negation shapes, not accumulates, and the rewrite would
    //     render register 31 as an operand.
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
            if (rd != 31) {
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

            if (valid && xc != t && xc != 31) {
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

                if (rd == t) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, t);
                }
            }
        }

        // CSEL consumer: CSNEG's else-branch is a negation
        // (Rd = cond ? Rn : -Rm), so a NEG feeding either CSEL operand
        // folds into it. With the negation in the else slot (Rm) the
        // condition carries over; in the then slot (Rn) the rewrite
        // swaps the operands and inverts the condition:
        //   neg wt, ws ; csel wd, wn, wt, cc -> csneg wd, wn, ws, cc
        //   neg wt, ws ; csel wd, wt, wm, cc -> csneg wd, wm, ws, !cc
        // The rewrite reads the same NZCV the CSEL did (a NEG writes
        // no flags) and reads ws, which the adjacent pair leaves
        // unchanged even for the in-place neg wt, wt. AL/NV are
        // excluded: ConditionHolds treats both as always-true, so
        // such a CSEL is a plain MOV and the then-slot inversion
        // (AL <-> NV) would still be always-taken. Rd = 31 discards
        // the select; a CSEL reading wt in BOTH slots is the
        // same-operand identity, check_csel_self's shape. Reported
        // as "NEG + CSEL foldable to CSNEG"; op2 = 00 fixes CSEL
        // proper (CSINC/CSINV/CSNEG have different else-branches).
        if ((op & 0x7FE00C00u) == 0x1A800000u) {
            unsigned c_sf = (op >> 31) & 1u;
            unsigned c_rd = op & 0x1Fu;
            unsigned c_rn = (op >> 5) & 0x1Fu;
            unsigned c_rm = (op >> 16) & 0x1Fu;
            unsigned cond = (op >> 12) & 0xFu;
            unsigned t = state->neg_pending_rd;
            bool then_slot = false;
            bool valid = false;
            unsigned surviving = 0;
            if ((c_sf != 0) == state->neg_pending_is_64bit
                    && c_rd != 31 && cond < 14u) {
                if (c_rm == t && c_rn != t) {
                    valid = true;
                    surviving = c_rn;   // else slot: condition unchanged
                } else if (c_rn == t && c_rm != t) {
                    valid = true;
                    surviving = c_rm;   // then slot: swap and invert
                    then_slot = true;
                }
            }

            if (valid) {
                char w_or_x = state->neg_pending_is_64bit ? 'x' : 'w';
                unsigned new_cond = then_slot ? (cond ^ 1u) : cond;
                char surv_buf[8], rn_buf[8], rm_buf[8];
                format_reg(surv_buf, sizeof(surv_buf), w_or_x, surviving);
                format_reg(rn_buf, sizeof(rn_buf), w_or_x, c_rn);
                format_reg(rm_buf, sizeof(rm_buf), w_or_x, c_rm);

                out->name = "NEG + CSEL foldable to CSNEG";
                out->start_offset = state->neg_pending_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                snprintf(out->detail, sizeof(out->detail),
                    "-> csneg %c%u, %s, %c%u, %s",
                    w_or_x, c_rd, surv_buf,
                    w_or_x, state->neg_pending_rs,
                    a64_cond_names[new_cond]);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->neg_pending_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "csel %c%u, %s, %s, %s",
                    w_or_x, c_rd, rn_buf, rm_buf,
                    a64_cond_names[cond]);

                if (c_rd == t) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, t);
                }
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
    // The rewrite deletes the MVN, so its destination must be dead
    // afterward: a consumer that overwrites it proves that on the
    // spot, and one writing a fresh register defers through the
    // forward register-liveness scan. Rd = 31 consumers are excluded
    // (a dead write, or the TST alias for ANDS), as is an XZR
    // surviving operand -- "orr rd, xzr, t" is the MOV alias, whose
    // fold is MVN itself, and the AND/EOR forms are constant
    // materialisations; none are this rewrite.
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
            if (rd != 31) {
                if (rm == t && rn != t) {
                    valid = true;
                    indep = rn;
                } else if (rn == t && rm != t) {
                    valid = true;
                    indep = rm;
                }
            }

            if (valid && indep != 31) {
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

                if (rd == t) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, t);
                }
            }
        }

        // CSEL consumer: CSINV's else-branch is a complement
        // (Rd = cond ? Rn : ~Rm), so an MVN feeding either CSEL
        // operand folds into it. With the complement in the else slot
        // (Rm) the condition carries over; in the then slot (Rn) the
        // rewrite swaps the operands and inverts the condition:
        //   mvn wt, ws ; csel wd, wn, wt, cc -> csinv wd, wn, ws, cc
        //   mvn wt, ws ; csel wd, wt, wm, cc -> csinv wd, wm, ws, !cc
        // The rewrite reads the same NZCV the CSEL did (an MVN writes
        // no flags) and reads ws, which still holds its original
        // value at the consumer once the MVN is deleted -- even for
        // the in-place mvn wt, wt. AL/NV are excluded:
        // ConditionHolds treats both as always-true, so such a CSEL
        // is a plain MOV and the then-slot inversion would still be
        // always-taken. Rd = 31 discards the select; a CSEL reading
        // wt in BOTH slots is the same-operand identity,
        // check_csel_self's shape. Reported as "MVN + CSEL foldable
        // to CSINV"; op2 = 00 fixes CSEL proper (CSINC/CSINV/CSNEG
        // have different else-branches).
        if ((op & 0x7FE00C00u) == 0x1A800000u) {
            unsigned c_sf = (op >> 31) & 1u;
            unsigned c_rd = op & 0x1Fu;
            unsigned c_rn = (op >> 5) & 0x1Fu;
            unsigned c_rm = (op >> 16) & 0x1Fu;
            unsigned cond = (op >> 12) & 0xFu;
            unsigned t = state->mvn_pending_rd;
            bool then_slot = false;
            bool valid = false;
            unsigned surviving = 0;
            if ((c_sf != 0) == state->mvn_pending_is_64bit
                    && c_rd != 31 && cond < 14u) {
                if (c_rm == t && c_rn != t) {
                    valid = true;
                    surviving = c_rn;   // else slot: condition unchanged
                } else if (c_rn == t && c_rm != t) {
                    valid = true;
                    surviving = c_rm;   // then slot: swap and invert
                    then_slot = true;
                }
            }

            if (valid) {
                char w_or_x = state->mvn_pending_is_64bit ? 'x' : 'w';
                unsigned new_cond = then_slot ? (cond ^ 1u) : cond;
                char surv_buf[8], rn_buf[8], rm_buf[8];
                format_reg(surv_buf, sizeof(surv_buf), w_or_x, surviving);
                format_reg(rn_buf, sizeof(rn_buf), w_or_x, c_rn);
                format_reg(rm_buf, sizeof(rm_buf), w_or_x, c_rm);

                out->name = "MVN + CSEL foldable to CSINV";
                out->start_offset = state->mvn_pending_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                snprintf(out->detail, sizeof(out->detail),
                    "-> csinv %c%u, %s, %c%u, %s",
                    w_or_x, c_rd, surv_buf,
                    w_or_x, state->mvn_pending_rs,
                    a64_cond_names[new_cond]);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->mvn_pending_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "csel %c%u, %s, %s, %s",
                    w_or_x, c_rd, rn_buf, rm_buf,
                    a64_cond_names[cond]);

                if (c_rd == t) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, t);
                }
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

bool check_add_one_csel_fold(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out)
{
    if (insn->size != 4) {
        state->ao_pending = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    bool produced = false;

    // (1) Close: a CSEL reading the incremented register? CSINC's
    //     else-branch is an increment (Rd = cond ? Rn : Rm + 1), the
    //     exact mirror of the CSNEG and CSINV folds: the else slot
    //     carries the condition over, the then slot swaps operands
    //     and inverts it:
    //       add wt, ws, #1 ; csel wd, wn, wt, cc -> csinc wd, wn, ws, cc
    //       add wt, ws, #1 ; csel wd, wt, wm, cc -> csinc wd, wm, ws, !cc
    //     The rewrite reads the same NZCV the CSEL did (the non-S ADD
    //     writes no flags) and reads ws, which still holds its
    //     original value at the consumer once the ADD is deleted --
    //     even for the in-place add wt, wt, #1. AL/NV are excluded
    //     (the select is unconditional and the then-slot inversion
    //     would still be always-taken); Rd = 31 discards the select;
    //     both slots reading wt is check_csel_self's shape.
    if (state->ao_pending) {
        if ((op & 0x7FE00C00u) == 0x1A800000u) {
            unsigned c_sf = (op >> 31) & 1u;
            unsigned c_rd = op & 0x1Fu;
            unsigned c_rn = (op >> 5) & 0x1Fu;
            unsigned c_rm = (op >> 16) & 0x1Fu;
            unsigned cond = (op >> 12) & 0xFu;
            unsigned t = state->ao_rd;
            bool then_slot = false;
            bool valid = false;
            unsigned surviving = 0;
            if ((c_sf != 0) == state->ao_is_64bit
                    && c_rd != 31 && cond < 14u) {
                if (c_rm == t && c_rn != t) {
                    valid = true;
                    surviving = c_rn;   // else slot: condition unchanged
                } else if (c_rn == t && c_rm != t) {
                    valid = true;
                    surviving = c_rm;   // then slot: swap and invert
                    then_slot = true;
                }
            }

            if (valid) {
                char w_or_x = state->ao_is_64bit ? 'x' : 'w';
                unsigned new_cond = then_slot ? (cond ^ 1u) : cond;
                char surv_buf[8], rn_buf[8], rm_buf[8];
                format_reg(surv_buf, sizeof(surv_buf), w_or_x, surviving);
                format_reg(rn_buf, sizeof(rn_buf), w_or_x, c_rn);
                format_reg(rm_buf, sizeof(rm_buf), w_or_x, c_rm);

                out->name = "ADD #1 + CSEL foldable to CSINC";
                out->start_offset = state->ao_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                snprintf(out->detail, sizeof(out->detail),
                    "-> csinc %c%u, %s, %c%u, %s",
                    w_or_x, c_rd, surv_buf,
                    w_or_x, state->ao_rs,
                    a64_cond_names[new_cond]);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->ao_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "csel %c%u, %s, %s, %s",
                    w_or_x, c_rd, rn_buf, rm_buf,
                    a64_cond_names[cond]);

                if (c_rd == t) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, t);
                }
            }
        }
        // Strict adjacency: clear regardless of match.
        state->ao_pending = false;
    }

    // (2) Open: an ADD Rt, Rs, #1 (immediate, no shift, non-S)?
    //     Register 31 in ADD-immediate means SP for both Rd and Rn,
    //     while CSINC's slots are ZR-flavoured: an SP source has no
    //     CSINC expression and an SP destination is not a select
    //     temporary, so both are excluded.
    if ((op & 0x7FFFFC00u) == 0x11000400u) {
        unsigned a_sf = (op >> 31) & 1u;
        unsigned a_rd = op & 0x1Fu;
        unsigned a_rn = (op >> 5) & 0x1Fu;
        if (a_rd != 31 && a_rn != 31) {
            state->ao_pending = true;
            state->ao_is_64bit = (a_sf != 0);
            state->ao_rd = a_rd;
            state->ao_rs = a_rn;
            state->ao_offset = offset;
            char w_or_x = (a_sf != 0) ? 'x' : 'w';
            snprintf(state->ao_disasm, sizeof(state->ao_disasm),
                "add %c%u, %c%u, #1",
                w_or_x, a_rd, w_or_x, a_rn);
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
            // would change the operand. Rd = 31 is excluded for the
            // same reason, and more sharply: the shifted-register
            // consumer's Rd = 31 is a discarded ZR write, but the
            // extended-register rewrite's Rd = 31 is SP -- the fold
            // would turn dead code into a stack-pointer update.
            // The rewrite deletes the extend, so its destination must
            // be dead afterward: a consumer that overwrites it proves
            // that on the spot, and one writing a fresh register
            // defers through the forward register-liveness scan.
            if (rd != 31) {
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

                if (rd == t) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, t);
                }
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

// Stash a MOV #0 + use finding for forward register-liveness verification
// instead of emitting it immediately. armlint_advance_pending_mz emits it only
// once the materialized zero register (state->mov_rd) is shown to be dead after
// the consumer. Returns false so the driver records no finding at this point.
static bool mov_zero_defer(armlint_state *state, armlint_finding *out)
{
    return defer_dead_mov(state, out, state->mov_rd);
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

    // (a) STR (any size, unsigned-offset) with Rt == mov_rd. The base
    // Rn must NOT also be mov_rd: only the Rt data slot is rewritten to
    // ZR, so a store whose base is the zeroed register still reads it as
    // an address. The forward-liveness scan begins after the store and
    // never sees that base read, so it could wrongly prove the MOV dead
    // -- deleting `mov xN, #0` would then change `str xN, [xN]`'s address
    // from 0 to whatever xN held before.
    {
        unsigned size, imm12, rn, rt;
        if (decode_str_uimm_any_size(op, &size, &imm12, &rn, &rt)
                && rt == state->mov_rd
                && rn != state->mov_rd) {
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
            return mov_zero_defer(state, out);
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
                return mov_zero_defer(state, out);
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
                return mov_zero_defer(state, out);
            }
        }
    }

    // (d) Conditional select family (CSEL/CSINC/CSINV/CSNEG) with
    // mov_rd as Rn or Rm. ZR is legal in either slot for all four
    // ops. Both slots being the zero register is left to
    // check_csel_self (a same-operand identity, a strictly better
    // rewrite than two ZR substitutions that still need the select).
    {
        if ((op & 0x3FE00800u) == 0x1A800000u) {
            unsigned sf = (op >> 31) & 1u;
            unsigned rd = op & 0x1Fu;
            unsigned rn = (op >> 5) & 0x1Fu;
            unsigned rm = (op >> 16) & 0x1Fu;
            unsigned cond = (op >> 12) & 0xFu;
            unsigned opsel = (((op >> 30) & 1u) << 1) | ((op >> 10) & 1u);
            bool rn_hit = rn == state->mov_rd;
            bool rm_hit = rm == state->mov_rd;
            if ((rn_hit || rm_hit) && !(rn_hit && rm_hit)) {
                static const char *const sel_mnems[4] = {
                    "csel", "csinc", "csinv", "csneg",
                };
                char wx = (sf != 0) ? 'x' : 'w';
                unsigned new_rn = rn_hit ? 31u : rn;
                unsigned new_rm = rm_hit ? 31u : rm;

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
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, %s, %s, %s",
                    sel_mnems[opsel], rd_buf, new_rn_buf, new_rm_buf,
                    a64_cond_names[cond]);
                snprintf(consumer_line, sizeof(consumer_line),
                    "%s %s, %s, %s, %s",
                    sel_mnems[opsel], rd_buf, orig_rn_buf, orig_rm_buf,
                    a64_cond_names[cond]);
                mov_zero_finding_render_lines(state, out, consumer_line);
                return mov_zero_defer(state, out);
            }
        }
    }

    // (e) Register-form CCMP/CCMN with mov_rd as Rn, the left
    // operand, which has no immediate slot -- the Rm slot is
    // check_mov_ccmp_imm_fold's territory (a zero there folds to the
    // #0 immediate form, deleting the register read outright). Both
    // slots being the zero register would leave the rewrite still
    // reading it; skipped.
    {
        if ((op & 0x3FE00C10u) == 0x3A400000u) {
            unsigned sf = (op >> 31) & 1u;
            unsigned rn = (op >> 5) & 0x1Fu;
            unsigned rm = (op >> 16) & 0x1Fu;
            unsigned cond = (op >> 12) & 0xFu;
            unsigned nzcv = op & 0xFu;
            bool is_ccmp = ((op >> 30) & 1u) != 0;
            if (rn == state->mov_rd && rm != state->mov_rd) {
                char wx = (sf != 0) ? 'x' : 'w';
                const char *mnem = is_ccmp ? "ccmp" : "ccmn";

                char orig_rn_buf[8], rm_buf[8];
                format_reg(orig_rn_buf, sizeof(orig_rn_buf), wx, rn);
                format_reg(rm_buf, sizeof(rm_buf), wx, rm);

                out->name = "MOV #0 + use foldable to ZR";
                out->start_offset = state->mov_start_offset;
                out->insn_count = state->mov_insn_count + 1;
                clear_finding_strings(out);

                char consumer_line[ARMLINT_FINDING_LINE_LEN];
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %czr, %s, #0x%x, %s",
                    mnem, wx, rm_buf, nzcv, a64_cond_names[cond]);
                snprintf(consumer_line, sizeof(consumer_line),
                    "%s %s, %s, #0x%x, %s",
                    mnem, orig_rn_buf, rm_buf, nzcv,
                    a64_cond_names[cond]);
                mov_zero_finding_render_lines(state, out, consumer_line);
                return mov_zero_defer(state, out);
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

// Decode a MOVI (Advanced SIMD modified immediate) whose result is the
// all-zero vector -- the zeroing producer of the SIMD compare-with-zero
// fold. The format is
//   0 Q op 0111100000 abc cmode 0 1 defgh Rd        imm8 = abc:defgh
// and the value is zero exactly when imm8 == 0 and (op, cmode) name a MOVI
// that does not fill in low ones: op=0 with an even cmode other than 0b1100
// (the MSL #8 form yields 0x..FF), or op=1 with cmode=0b1110 (MOVI Vd.2D).
// MVNI/BIC (op=1, other cmodes), ORR (op=0, odd cmode), and FMOV (cmode
// 0b1111) are excluded. The producer's arrangement is irrelevant: any
// zeroing MOVI clears all 128 bits (a 64-bit form zeros the upper half),
// so it feeds a compare of any arrangement. Returns the V-register number.
static bool decode_simd_zero_movi(uint32_t op, unsigned *out_rd)
{
    // Fixed modified-immediate bits: bit31=0, 28:19=0111100000, o2(bit11)=0,
    // bit10=1. Q, op, abc, cmode, defgh, Rd are free.
    if ((op & 0x9FF80C00u) != 0x0F000400u) {
        return false;
    }
    unsigned imm8 = (((op >> 16) & 0x7u) << 5) | ((op >> 5) & 0x1Fu);
    if (imm8 != 0u) {
        return false;
    }
    unsigned opbit = (op >> 29) & 1u;
    unsigned cmode = (op >> 12) & 0xFu;
    bool zero = opbit == 0u
        ? ((cmode & 1u) == 0u && cmode != 0xCu)   // MOVI, not MSL/FMOV
        : (cmode == 0xEu);                          // MOVI Vd.2D, #0
    if (!zero) {
        return false;
    }
    *out_rd = op & 0x1Fu;
    return true;
}

// A decoded vector compare in register form.
typedef struct {
    bool is_fp;
    unsigned kind;          // 0 = EQ, 1 = GE, 2 = GT
    unsigned vd, vn, vm;
    unsigned size;          // integer size (23:22), or FP sz (bit 22)
    unsigned q;
} simd_cmp_reg_t;

// Decode the signed integer compares CMEQ/CMGE/CMGT and the FP compares
// FCMEQ/FCMGE/FCMGT in Advanced SIMD three-same register form -- the
// consumers of the compare-with-zero fold. Unsigned (CMHI/CMHS), bitwise
// (CMTST), absolute (FACGE/FACGT), and half-precision compares are not
// matched: they have no direct compare-with-#0 equivalent here. The
// reserved 1D arrangements (integer size=3 / FP sz=1 with Q=0) are
// rejected so the suggested rewrite is always a legal encoding.
static bool decode_simd_cmp_reg(uint32_t op, simd_cmp_reg_t *out)
{
    // Outer Advanced SIMD three-same format (integer and FP share it):
    // bit31=0, 28:24=01110, bit21=1, bit10=1.
    if ((op & 0x9F200400u) != 0x0E200400u) {
        return false;
    }
    unsigned u = (op >> 29) & 1u;
    unsigned opcode = (op >> 11) & 0x1Fu;
    unsigned q = (op >> 30) & 1u;
    if (opcode == 0x1Cu) {
        // FP three-same: bit23 is the E-bit, bit22 the sz (single/double).
        unsigned ebit = (op >> 23) & 1u;
        if (u == 0u && ebit == 0u) {
            out->kind = 0;          // FCMEQ
        } else if (u == 1u && ebit == 0u) {
            out->kind = 1;          // FCMGE
        } else if (u == 1u && ebit == 1u) {
            out->kind = 2;          // FCMGT
        } else {
            return false;
        }
        out->size = (op >> 22) & 1u;
        if (out->size == 1u && q == 0u) {
            return false;           // reserved 1D
        }
        out->is_fp = true;
    } else {
        // Integer three-same: opcode + U select the signed compares.
        if (u == 1u && opcode == 0x11u) {
            out->kind = 0;          // CMEQ
        } else if (u == 0u && opcode == 0x07u) {
            out->kind = 1;          // CMGE
        } else if (u == 0u && opcode == 0x06u) {
            out->kind = 2;          // CMGT
        } else {
            return false;           // CMTST/CMHI/CMHS/ADD/SUB/MUL/...
        }
        out->size = (op >> 22) & 3u;
        if (out->size == 3u && q == 0u) {
            return false;           // reserved 1D
        }
        out->is_fp = false;
    }
    out->q = q;
    out->vm = (op >> 16) & 0x1Fu;
    out->vn = (op >> 5) & 0x1Fu;
    out->vd = op & 0x1Fu;
    return true;
}

// Arrangement specifier for a vector compare operand (all three share it).
static const char *simd_arr_str(bool is_fp, unsigned size, unsigned q)
{
    if (is_fp) {
        return size == 0u ? (q ? "4s" : "2s") : "2d";   // sz: single / double
    }
    switch (size) {
    case 0:  return q ? "16b" : "8b";
    case 1:  return q ? "8h"  : "4h";
    case 2:  return q ? "4s"  : "2s";
    default: return "2d";                                // size 3 (Q=0 gated)
    }
}

bool check_simd_cmp_zero(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out)
{
    bool produced = false;

    if (insn->size != 4) {
        state->simd_zero_active = false;
        return false;
    }

    uint32_t op = insn_word(insn);

    // (1) Close: a vector compare consuming the pending zero vector. Require
    //     Vd == the zero register so the compare overwrites it (the zero is
    //     structurally dead), and exactly one source to be the zero vector
    //     -- the other is the live operand X.
    if (state->simd_zero_active) {
        simd_cmp_reg_t c;
        if (decode_simd_cmp_reg(op, &c) && c.vd == state->simd_zero_reg) {
            unsigned vz = state->simd_zero_reg;
            bool zero_in_vn = (c.vn == vz);
            bool zero_in_vm = (c.vm == vz);
            if (zero_in_vn != zero_in_vm) {
                unsigned x = zero_in_vn ? c.vm : c.vn;
                // EQ is symmetric. For the ordered compares a zero LEFT
                // operand flips the sense: 0 >= X == X <= 0, 0 > X == X < 0.
                const char *mnem;
                if (c.kind == 0) {
                    mnem = c.is_fp ? "fcmeq" : "cmeq";
                } else if (c.kind == 1) {
                    mnem = zero_in_vm ? (c.is_fp ? "fcmge" : "cmge")
                                      : (c.is_fp ? "fcmle" : "cmle");
                } else {
                    mnem = zero_in_vm ? (c.is_fp ? "fcmgt" : "cmgt")
                                      : (c.is_fp ? "fcmlt" : "cmlt");
                }
                const char *arr = simd_arr_str(c.is_fp, c.size, c.q);
                const char *imm = c.is_fp ? "#0.0" : "#0";

                out->name =
                    "MOVI #0 + vector compare foldable to compare-with-zero";
                out->start_offset = state->simd_zero_offset;
                out->insn_count = 2;
                clear_finding_strings(out);
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s v%u.%s, v%u.%s, %s",
                    mnem, c.vd, arr, x, arr, imm);
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->simd_zero_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s", insn->mnemonic, insn->op_str);
                produced = true;
            }
        }
        // Strict adjacency: any non-matching instruction expires the window.
        state->simd_zero_active = false;
    }

    // (2) Open: a zeroing MOVI starts a new pending window.
    unsigned vz;
    if (decode_simd_zero_movi(op, &vz)) {
        state->simd_zero_active = true;
        state->simd_zero_reg = vz;
        state->simd_zero_offset = offset;
        snprintf(state->simd_zero_disasm, sizeof(state->simd_zero_disasm),
            "%s %s", insn->mnemonic, insn->op_str);
    }

    return produced;
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
    //   - distinct destination registers for LOADS: LDP/LDPSW with
    //     Rt1 == Rt2 is CONSTRAINED UNPREDICTABLE. Stores have no
    //     such restriction -- STP Rt, Rt stores the value twice --
    //     so a repeated source register pairs fine.
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

    // A pair of adjacent W-form zero-register stores writes the same
    // eight bytes as one STR XZR: prefer that narrower rewrite over
    // the STP WZR, WZR the general path would emit.
    bool zero_store = !is_load && !is_fp && !is_64bit && !is_sext
        && state->lsp_rt == 31u && rt == 31u;

    if ((forward || reverse)
            && state->lsp_is_sext == is_sext
            && state->lsp_is_fp == is_fp
            && (!is_fp || state->lsp_lg2size == lg2size)
            && state->lsp_is_load == is_load
            && (is_fp || state->lsp_is_64bit == is_64bit)
            && state->lsp_rn == rn
            && (!is_load || rt != state->lsp_rt)
            && low_imm12 <= 63u
            && (!is_load || is_fp || state->lsp_rt != rn)) {
        // LDPSW always loads Xt with 4-byte transfer; SIMD&FP pairs
        // take their class letter and log2 size; otherwise the register
        // width follows is_64bit and the transfer size matches. rt_size
        // feeds format_ls_rt, which renders register 31 as the zero
        // register rather than the non-assemblable "w31"/"x31".
        unsigned rt_size;
        unsigned xfer;
        if (is_fp) {
            rt_size = lg2size;
            xfer = 1u << lg2size;
        } else if (is_sext) {
            rt_size = 3u;            // LDPSW transfers 4 bytes into Xt
            xfer = 4u;
        } else {
            rt_size = is_64bit ? 3u : 2u;
            xfer = is_64bit ? 8u : 4u;
        }
        unsigned byte_off = low_imm12 * xfer;

        out->start_offset = state->lsp_offset;
        out->insn_count = 2;
        clear_finding_strings(out);

        char rn_buf[8];
        if (rn == 31) {
            snprintf(rn_buf, sizeof(rn_buf), "sp");
        } else {
            snprintf(rn_buf, sizeof(rn_buf), "x%u", rn);
        }

        if (zero_store) {
            // STR's scaled offset must be a non-negative multiple of 8;
            // the odd 4-byte slot (byte_off % 8 == 4) needs unscaled
            // STUR. byte_off <= 252 here, in range for both forms.
            const char *mnem = byte_off % 8u == 0u ? "str" : "stur";
            out->name = "adjacent zero STRs foldable into STR xzr";
            snprintf(out->detail, sizeof(out->detail),
                "-> %s xzr, [%s, #%u]", mnem, rn_buf, byte_off);
        } else {
            const char *pair_mnem;
            if (is_sext) {
                pair_mnem = "ldpsw";
            } else {
                pair_mnem = is_load ? "ldp" : "stp";
            }
            // LDP/STP encodes the register at the lower address first.
            unsigned first_rt  = forward ? state->lsp_rt : rt;
            unsigned second_rt = forward ? rt : state->lsp_rt;

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
            char rt1_buf[8], rt2_buf[8];
            format_ls_rt(rt1_buf, sizeof(rt1_buf), is_fp, rt_size,
                first_rt);
            format_ls_rt(rt2_buf, sizeof(rt2_buf), is_fp, rt_size,
                second_rt);
            snprintf(out->detail, sizeof(out->detail),
                "-> %s %s, %s, [%s, #%u]",
                pair_mnem, rt1_buf, rt2_buf, rn_buf, byte_off);
        }
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

// STP WZR, WZR, [Xn, #imm] (W-form, signed offset, no writeback) zeroes
// eight contiguous bytes -- exactly what one STR XZR does -- but as a
// store-pair op. Recognize the all-zero-source pair and suggest the
// single wider store. Only the 32-bit form collapses: STP XZR, XZR
// zeroes sixteen bytes, which has no single-GPR-store equivalent (it is
// already the canonical 16-byte zero store). Writeback forms (pre- and
// post-index) and STNP are excluded by the encoding match below; they
// are not equivalent to a plain STR.
bool check_stp_wzr_to_str_xzr(armlint_state *state, const cs_insn *insn,
                              size_t offset, armlint_finding *out)
{
    (void)state;

    if (insn->size != 4) {
        return false;
    }

    uint32_t op = insn_word(insn);

    // STP, 32-bit, signed-offset (no writeback): opc=00, 101, V=0,
    // mode=010, L=0. Mask 0xFFC00000 fixes bits 31..22; value 0x29000000
    // is the W-form store. Pre-index (011), post-index (001), STNP (000),
    // the LDP load (L=1), and the X-form (opc=10) all differ in these
    // bits and so do not match.
    if ((op & 0xFFC00000u) != 0x29000000u) {
        return false;
    }

    unsigned rt  = op & 0x1Fu;
    unsigned rt2 = (op >> 10) & 0x1Fu;
    if (rt != 31u || rt2 != 31u) {
        return false;   // not a pair of zero-register sources
    }

    unsigned rn = (op >> 5) & 0x1Fu;

    // imm7 is a signed multiple of the 4-byte transfer size.
    int imm7 = (int)((op >> 15) & 0x7Fu);
    imm7 = (imm7 ^ 0x40) - 0x40;            // sign-extend bit 6
    int byte_off = imm7 * 4;

    char rn_buf[8];
    if (rn == 31) {
        snprintf(rn_buf, sizeof(rn_buf), "sp");
    } else {
        snprintf(rn_buf, sizeof(rn_buf), "x%u", rn);
    }

    // STR's scaled offset must be a non-negative multiple of 8; a
    // negative or odd-slot offset needs unscaled STUR. byte_off is in
    // [-256, 252], in range for whichever form applies.
    const char *mnem = byte_off >= 0 && byte_off % 8 == 0 ? "str" : "stur";

    out->name = "STP wzr, wzr foldable into STR xzr";
    out->start_offset = offset;
    out->insn_count = 1;
    clear_finding_strings(out);
    snprintf(out->detail, sizeof(out->detail),
        "-> %s xzr, [%s, #%d]", mnem, rn_buf, byte_off);
    snprintf(out->lines[0], sizeof(out->lines[0]),
        "%s %s", insn->mnemonic, insn->op_str);
    return true;
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

// Store counterpart of classify_int_load: opc == 00 is
// STRB/STRH/STR W/STR X by size. The data register Rt is read, not
// written -- which matters to the callers' deadness reasoning (a
// store never kills the constant or address register it consumes).
static bool classify_int_store(unsigned size, unsigned opc,
                               const char **out_mnem, char *out_rt_wx)
{
    static const char *const store_mnem[4] = {
        "strb", "strh", "str", "str"
    };
    if (opc != 0) {
        return false;
    }
    *out_mnem = store_mnem[size];
    *out_rt_wx = (size == 3u) ? 'x' : 'w';
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

    // (1) Try to close: is this an unsigned-offset, zero-imm12 integer
    //     load or store consuming the pending ADD as its base? A
    //     sign-extending load folds identically to a plain one: it too
    //     overwrites the full X register named by Rt, and the
    //     register-offset LDRS*/STR* forms exist for every accepted
    //     pair. The rewrite deletes the ADD, so the address register
    //     must be dead afterward: a load whose Rt IS the address
    //     register proves that on the spot, and every other consumer
    //     -- a store, or a load into a different register -- defers
    //     through the forward register-liveness scan until the address
    //     register is provably overwritten before any read.
    if (state->add_pending) {
        unsigned size, imm12, ls_rn, ls_rt;
        const char *ls_mnem;
        char rt_wx;
        bool is_store = false;
        bool matched = decode_int_load_uimm(op, &size, &ls_mnem, &rt_wx,
                                            &imm12, &ls_rn, &ls_rt);
        if (!matched
                && decode_str_uimm_any_size(op, &size, &imm12,
                                            &ls_rn, &ls_rt)
                && classify_int_store(size, 0u, &ls_mnem, &rt_wx)) {
            matched = true;
            is_store = true;
        }
        // A store whose data register is the ADD's Rd cannot fold:
        // the rewritten store would read the deleted sum.
        if (matched && imm12 == 0
                && ls_rn == state->add_pending_rd
                && !(is_store && ls_rt == state->add_pending_rd)) {
            // The register-offset form accepts only two shift
            // amounts: 0 or log2(access_size). size encodes log2
            // directly: 0=B, 1=H, 2=W, 3=X.
            unsigned s = state->add_pending_shift;
            if (s == 0 || s == size) {
                // Rt = 31 is WZR/XZR here (a zero store, or a load to
                // the discard register), never SP.
                char rt_buf[8];
                format_reg(rt_buf, sizeof(rt_buf), rt_wx, ls_rt);
                out->name = is_store
                    ? "ADD + STR foldable to register-offset STR"
                    : "ADD + LDR foldable to register-offset LDR";
                out->start_offset = state->add_pending_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                if (s == 0) {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %s, [x%u, x%u]",
                        ls_mnem, rt_buf,
                        state->add_pending_rn, state->add_pending_rm);
                } else {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %s, [x%u, x%u, lsl #%u]",
                        ls_mnem, rt_buf,
                        state->add_pending_rn, state->add_pending_rm,
                        s);
                }
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->add_pending_disasm);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s, [x%u]",
                    ls_mnem, rt_buf, ls_rn);
                if (!is_store && ls_rt == state->add_pending_rd) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, state->add_pending_rd);
                }
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

    // (1) Try to close: a register-offset load or store that uses the
    //     SXTW result as a plain X-register index? The rewrite deletes
    //     the SXTW, so the extended index must be dead afterward: a
    //     load whose Rt IS the index proves that on the spot (it
    //     overwrites the full X register), and every other consumer --
    //     a store, or a load into a different register -- defers
    //     through the forward register-liveness scan until the index
    //     is provably overwritten before any read.
    if (state->sxl_pending) {
        unsigned size, opc, rm, option, s, rn, rt;
        const char *ls_mnem;
        char rt_wx;
        bool is_store = false;
        bool classified = false;
        if (decode_ldr_reg_offset(op, &size, &opc, &rm, &option, &s,
                                  &rn, &rt)) {
            // Any integer load, zero- or sign-extending, or STRB/STRH/
            // STR (not PRFM, whose Rt is a prefetch op, so the index
            // register can never be proven dead through it).
            classified = classify_int_load(size, opc, &ls_mnem, &rt_wx);
            if (!classified
                    && classify_int_store(size, opc, &ls_mnem, &rt_wx)) {
                classified = true;
                is_store = true;
            }
        }
        // A store whose data register is the index cannot fold: the
        // rewritten store would read the deleted extend's result.
        if (classified
                && option == 3u         // LSL/UXTX: a full 64-bit offset
                && rm == state->sxl_rd  // index is the SXTW result
                && rn != state->sxl_rd
                && !(is_store && rt == state->sxl_rd)) {
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
            // Rt = 31 is WZR/XZR here (a zero store, or a load to the
            // discard register), never SP.
            char rt_buf[8];
            format_reg(rt_buf, sizeof(rt_buf), rt_wx, rt);

            out->name = is_store
                ? "SXTW + register-offset STR foldable into the store"
                : "SXTW + register-offset LDR foldable into the load";
            out->start_offset = state->sxl_offset;
            out->insn_count = 2;
            clear_finding_strings(out);

            if (s == 0) {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, [%s, w%u, sxtw]",
                    ls_mnem, rt_buf, base_buf, state->sxl_rs);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s, [%s, x%u]",
                    ls_mnem, rt_buf, base_buf, rm);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, [%s, w%u, sxtw #%u]",
                    ls_mnem, rt_buf, base_buf, state->sxl_rs, size);
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s, [%s, x%u, lsl #%u]",
                    ls_mnem, rt_buf, base_buf, rm, size);
            }
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->sxl_disasm);
            if (!is_store && rt == state->sxl_rd) {
                produced = true;
            } else {
                defer_dead_mov(state, out, state->sxl_rd);
            }
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

// Map an accepted load/store mnemonic to its unscaled (LDUR/STUR
// family) counterpart, used when the folded byte offset is negative or
// misaligned and only the signed-9-bit unscaled form encodes it.
static const char *unscaled_mnem(const char *mnem)
{
    static const struct {
        const char *scaled;
        const char *unscaled;
    } map[] = {
        { "ldr",   "ldur"   }, { "ldrb",  "ldurb"  },
        { "ldrh",  "ldurh"  }, { "ldrsb", "ldursb" },
        { "ldrsh", "ldursh" }, { "ldrsw", "ldursw" },
        { "str",   "stur"   }, { "strb",  "sturb"  },
        { "strh",  "sturh"  },
    };
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if (strcmp(mnem, map[i].scaled) == 0) {
            return map[i].unscaled;
        }
    }
    return mnem;
}

bool check_mov_reg_offset_fold(armlint_state *state, const cs_insn *insn,
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

    unsigned size, opc, rm, option, s, rn, rt;
    if (!decode_ldr_reg_offset(op, &size, &opc, &rm, &option, &s,
                               &rn, &rt)) {
        return false;
    }

    // Only the LSL/UXTX index option (011): the index is the full X
    // register, whose 64-bit value the MOV chain pins exactly. A
    // W-form chain qualifies too -- its W write zeroed X[63:32], so
    // the index equals the (non-negative) 32-bit constant. The extend
    // options (UXTW/SXTW/SXTX) re-interpret the index register and
    // are not matched.
    if (option != 3u) {
        return false;
    }
    if (rm != state->mov_rd) {
        return false;
    }

    bool is_store;
    const char *mnem;
    char rt_wx;
    if (classify_int_store(size, opc, &mnem, &rt_wx)) {
        is_store = true;
    } else if (classify_int_load(size, opc, &mnem, &rt_wx)) {
        is_store = false;
    } else {
        return false;       // PRFM or unallocated (size, opc)
    }

    // The base must not be the constant register: the immediate
    // rewrite would still read it, so the MOV could never be deleted.
    // A store whose data register is the constant keeps it live the
    // same way. (Rn = 31 in this form is SP and mov_rd is never 31,
    // so the SP case sails through and renders as "sp".)
    if (rn == state->mov_rd) {
        return false;
    }
    if (is_store && rt == state->mov_rd) {
        return false;
    }

    // Effective byte offset: the constant, scaled by log2(access
    // size) when the S bit is set. Bound the raw constant first: the
    // largest encodable byte offset is 4095*8 = 32760 (scaled X form)
    // and the smallest is -256 (unscaled), so anything outside cannot
    // fold at any shift, and the pre-bound keeps the multiply from
    // overflowing. A W-form chain's value is stored zero-extended, so
    // v is non-negative there; only an X-form MOVN chain reaches the
    // negative (unscaled) encodings.
    int64_t v = (int64_t)state->mov_value;
    if (v < -256 || v > 32760) {
        return false;
    }
    unsigned shift = s ? size : 0u;
    int64_t byte_off = v * (int64_t)(1u << shift);

    unsigned asize = 1u << size;
    bool fits_scaled = byte_off >= 0
        && (byte_off % (int64_t)asize) == 0
        && (byte_off / (int64_t)asize) <= 4095;
    bool fits_unscaled = byte_off >= -256 && byte_off <= 255;
    if (!fits_scaled && !fits_unscaled) {
        return false;
    }
    const char *new_mnem = fits_scaled ? mnem : unscaled_mnem(mnem);

    char base_buf[8];
    if (rn == 31) {
        snprintf(base_buf, sizeof(base_buf), "sp");
    } else {
        snprintf(base_buf, sizeof(base_buf), "x%u", rn);
    }
    // Rt = 31 is the zero register here (a store of zero, or a load
    // to the discard register), never SP.
    char rt_buf[8];
    format_reg(rt_buf, sizeof(rt_buf), rt_wx, rt);

    out->name =
        "MOV + register-offset LDR/STR foldable to immediate offset";
    out->start_offset = state->mov_start_offset;
    out->insn_count = state->mov_insn_count + 1;
    clear_finding_strings(out);

    if (byte_off == 0) {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %s, [%s]", new_mnem, rt_buf, base_buf);
    } else if (byte_off < 0) {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %s, [%s, #-0x%" PRIx64 "]",
            new_mnem, rt_buf, base_buf, (uint64_t)-byte_off);
    } else {
        snprintf(out->detail, sizeof(out->detail),
            "-> %s %s, [%s, #0x%" PRIx64 "]",
            new_mnem, rt_buf, base_buf, (uint64_t)byte_off);
    }

    char w_or_x = state->mov_is_64bit ? 'x' : 'w';
    unsigned max_mov_lines = ARMLINT_FINDING_LINES - 1u;
    unsigned chain_n = state->mov_insn_count;
    if (chain_n > max_mov_lines) {
        chain_n = max_mov_lines;
    }
    for (unsigned i = 0; i < chain_n; i++) {
        const mov_entry *e = &state->mov_entries[i];
        const char *mov_mnem = e->opc == 2 ? "movz"
                          : (e->opc == 0 ? "movn" : "movk");
        unsigned mshift = (unsigned)e->shift_div_16 * 16u;
        if (mshift == 0) {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x",
                mov_mnem, w_or_x, state->mov_rd, e->imm16);
        } else {
            snprintf(out->lines[i], sizeof(out->lines[i]),
                "%s %c%u, #0x%x, lsl #%u",
                mov_mnem, w_or_x, state->mov_rd, e->imm16, mshift);
        }
    }
    if (s == 0) {
        snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
            "%s %s, [%s, x%u]", mnem, rt_buf, base_buf, rm);
    } else {
        snprintf(out->lines[chain_n], sizeof(out->lines[chain_n]),
            "%s %s, [%s, x%u, lsl #%u]",
            mnem, rt_buf, base_buf, rm, shift);
    }

    // The rewrite deletes the MOV. A load whose destination is the
    // constant register overwrites it -- the constant dies at the
    // consumer itself, so emit now. Otherwise defer until a later
    // instruction proves mov_rd dead before any read (stores never
    // kill it, so they always defer).
    if (!is_store && rt == state->mov_rd) {
        return true;
    }
    return defer_dead_mov(state, out, state->mov_rd);
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

    // (1) Try to close: is this an unsigned-offset integer load or
    //     store consuming the pending ADD as its base? Sign-extending
    //     loads overwrite the full X register named by Rt just like
    //     plain LDR, and every accepted pair has an unsigned-offset
    //     LDRS*/STR* form, so the fold carries over. The rewrite
    //     deletes the ADD, so the address register must be dead
    //     afterward: a load whose Rt IS the address register proves
    //     that on the spot, and every other consumer -- a store, or a
    //     load into a different register -- defers through the forward
    //     register-liveness scan until the address register is
    //     provably overwritten before any read.
    if (state->addi_pending) {
        unsigned size, imm12, ls_rn, ls_rt;
        const char *ls_mnem;
        char rt_wx;
        bool is_store = false;
        bool matched = decode_int_load_uimm(op, &size, &ls_mnem, &rt_wx,
                                            &imm12, &ls_rn, &ls_rt);
        if (!matched
                && decode_str_uimm_any_size(op, &size, &imm12,
                                            &ls_rn, &ls_rt)
                && classify_int_store(size, 0u, &ls_mnem, &rt_wx)) {
            matched = true;
            is_store = true;
        }
        // A store whose data register is the ADD's Rd cannot fold:
        // the rewritten store would read the deleted sum.
        if (matched
                && ls_rn == state->addi_pending_rd
                && !(is_store && ls_rt == state->addi_pending_rd)) {
            // The access's own byte offset is imm12 * access_size,
            // already a multiple of access_size by construction. So the
            // combined offset's alignment depends only on the ADD's imm,
            // and the scaled total must fit in 12 bits. ls_byte_imm +
            // add_imm cannot overflow uint32_t: add_imm <= 0xFFF000 (24
            // bits) and ls_byte_imm <= 4095 * 8 = 0x7FF8 (15 bits).
            unsigned access_size = 1u << size;
            uint32_t add_imm = state->addi_pending_imm;
            uint32_t ls_byte_imm = (uint32_t)imm12 * access_size;
            uint32_t combined = add_imm + ls_byte_imm;
            if ((add_imm & (access_size - 1u)) == 0
                    && (combined >> size) <= 0xFFFu) {
                // Rt = 31 is WZR/XZR here (a zero store, or a load to
                // the discard register), never SP.
                char rt_buf[8];
                format_reg(rt_buf, sizeof(rt_buf), rt_wx, ls_rt);
                out->name = is_store
                    ? "ADD + STR foldable to immediate-offset STR"
                    : "ADD + LDR foldable to immediate-offset LDR";
                out->start_offset = state->addi_pending_offset;
                out->insn_count = 2;
                clear_finding_strings(out);

                // combined == 0 is reachable only via the MOV-from-SP
                // alias (imm == 0 requires Rn = SP) with a zero-offset
                // access; render the bare [sp] form.
                if (combined == 0) {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %s, [sp]",
                        ls_mnem, rt_buf);
                } else if (state->addi_pending_rn == 31) {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %s, [sp, #0x%x]",
                        ls_mnem, rt_buf, combined);
                } else {
                    snprintf(out->detail, sizeof(out->detail),
                        "-> %s %s, [x%u, #0x%x]",
                        ls_mnem, rt_buf,
                        state->addi_pending_rn, combined);
                }
                snprintf(out->lines[0], sizeof(out->lines[0]),
                    "%s", state->addi_pending_disasm);
                if (ls_byte_imm == 0) {
                    snprintf(out->lines[1], sizeof(out->lines[1]),
                        "%s %s, [x%u]",
                        ls_mnem, rt_buf, ls_rn);
                } else {
                    snprintf(out->lines[1], sizeof(out->lines[1]),
                        "%s %s, [x%u, #0x%x]",
                        ls_mnem, rt_buf, ls_rn, ls_byte_imm);
                }
                if (!is_store && ls_rt == state->addi_pending_rd) {
                    produced = true;
                } else {
                    defer_dead_mov(state, out, state->addi_pending_rd);
                }
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

// Decode a load/store pair, signed-offset (no-writeback) form:
// opc(2) 101 V(1) 010 L(1) imm7 Rt2 Rn Rt. Accepts exactly the
// combinations that have pre-/post-indexed counterparts: integer W
// (opc=00) and X (opc=10) pairs, LDPSW (opc=01 with L=1: two 4-byte
// sign-extending loads into Xt destinations, flagged in out_is_sw),
// and SIMD&FP S/D/Q pairs (V=1, opc=00/01/10). opc=11 and the opc=01
// integer store are unallocated. out_lg2size is the log2 PER-REGISTER
// transfer bytes (2/3/4); imm7 (returned sign-extended) and the
// writeback immediate of the indexed forms are scaled by that size.
// LDNP/STNP use a different mode field (000) and do not match.
static bool decode_pair_soff(uint32_t op, bool *out_is_load,
                             bool *out_is_fp, bool *out_is_sw,
                             unsigned *out_lg2size, int *out_imm7,
                             unsigned *out_rn, unsigned *out_rt,
                             unsigned *out_rt2)
{
    if ((op & 0x3B800000u) != 0x29000000u) {
        return false;
    }
    unsigned opc = (op >> 30) & 0x3u;
    bool is_fp = ((op >> 26) & 1u) != 0;
    bool is_load = ((op >> 22) & 1u) != 0;
    bool is_sw = false;
    unsigned lg2;
    if (opc == 3u) {
        return false;               // unallocated in both files
    }
    if (is_fp) {
        lg2 = opc + 2u;             // S/D/Q
    } else if (opc == 1u) {
        if (!is_load) {
            return false;           // integer opc=01 store: unallocated
        }
        is_sw = true;               // LDPSW
        lg2 = 2u;
    } else {
        lg2 = opc == 0u ? 2u : 3u;  // W / X
    }
    *out_is_load = is_load;
    *out_is_fp = is_fp;
    *out_is_sw = is_sw;
    *out_lg2size = lg2;
    int imm7 = (int)((op >> 15) & 0x7Fu);
    if (imm7 & 0x40) {
        imm7 -= 128;
    }
    *out_imm7 = imm7;
    *out_rt2 = (op >> 10) & 0x1Fu;
    *out_rn = (op >> 5) & 0x1Fu;
    *out_rt = op & 0x1Fu;
    return true;
}

// Pair mnemonic: LDPSW carries its own; otherwise ldp/stp by
// direction (SIMD&FP pairs share the integer mnemonics).
static const char *pair_mnemonic(bool is_load, bool is_sw)
{
    if (is_sw) {
        return "ldpsw";
    }
    return is_load ? "ldp" : "stp";
}

// Format one data register of a pair. LDPSW transfers 4 bytes per
// register but writes X destinations, so it renders as size 3.
static void format_pair_rt(char *buf, size_t bufsz, bool is_fp,
                           bool is_sw, unsigned lg2size, unsigned rt)
{
    format_ls_rt(buf, bufsz, is_fp, is_sw ? 3u : lg2size, rt);
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
    // self-updates the pending access's base?
    if (state->lspi_pending) {
        unsigned a_rd, a_rn;
        uint32_t a_imm;
        // Rt == Rn writeback is UNPREDICTABLE (CONSTRAINED for stores)
        // unless Rn == 31, where 31 means SP for Rn but XZR for Rt --
        // distinct registers, so no conflict. A pair extends the rule
        // to its second data register. A SIMD&FP Rt lives in a
        // different register file and can never alias the base.
        bool rt_aliases_rn = !state->lspi_pending_is_fp
            && state->lspi_pending_rn != 31
            && (state->lspi_pending_rt == state->lspi_pending_rn
                || (state->lspi_pending_is_pair
                    && state->lspi_pending_rt2 == state->lspi_pending_rn));
        bool is_add = decode_add_imm_x(op, &a_rd, &a_rn, &a_imm);
        bool is_sub = !is_add && decode_sub_imm_x(op, &a_rd, &a_rn, &a_imm);
        // Writeback range. Singles use the 9-bit signed byte slot:
        // ADD imm in 1..255 folds to a positive writeback, SUB imm in
        // 1..256 to a negative one (-256 is the signed-9-bit minimum).
        // Pairs use the scaled 7-bit slot: the byte amount must be a
        // multiple of the per-register transfer size with quotient
        // 1..63 (ADD) or 1..64 (SUB). The test sits behind the
        // (is_add || is_sub) guard so a_imm is only read once a
        // decoder has filled it.
        bool imm_in_range = false;
        if (is_add || is_sub) {
            if (state->lspi_pending_is_pair) {
                unsigned scale = 1u << state->lspi_pending_size;
                imm_in_range = a_imm >= scale
                    && a_imm % scale == 0
                    && a_imm / scale <= (is_sub ? 64u : 63u);
            } else {
                imm_in_range = a_imm >= 1
                    && a_imm <= (is_sub ? 256u : 255u);
            }
        }
        if (!rt_aliases_rn
                && (is_add || is_sub)
                && a_rd == state->lspi_pending_rn
                && a_rn == state->lspi_pending_rn
                && imm_in_range) {
            unsigned size = state->lspi_pending_size;
            bool is_load = state->lspi_pending_is_load;
            bool is_fp = state->lspi_pending_is_fp;
            bool is_pair = state->lspi_pending_is_pair;
            const char *mnem = is_pair
                ? pair_mnemonic(is_load, state->lspi_pending_is_sw)
                : ls_mnemonic(is_fp, is_load, size);
            const char *idx_sign = is_sub ? "-" : "";
            const char *upd_mnem = is_sub ? "sub" : "add";

            if (is_pair) {
                if (is_load) {
                    out->name = is_sub
                        ? "LDP + SUB foldable to post-indexed LDP"
                        : "LDP + ADD foldable to post-indexed LDP";
                } else {
                    out->name = is_sub
                        ? "STP + SUB foldable to post-indexed STP"
                        : "STP + ADD foldable to post-indexed STP";
                }
            } else if (is_load) {
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

            // rts holds the data-register list: one register for a
            // single, "rt, rt2" for a pair.
            char rt_buf[8];
            char rts[20];
            if (is_pair) {
                char rt2_buf[8];
                format_pair_rt(rt_buf, sizeof(rt_buf), is_fp,
                    state->lspi_pending_is_sw, size,
                    state->lspi_pending_rt);
                format_pair_rt(rt2_buf, sizeof(rt2_buf), is_fp,
                    state->lspi_pending_is_sw, size,
                    state->lspi_pending_rt2);
                snprintf(rts, sizeof(rts), "%s, %s", rt_buf, rt2_buf);
            } else {
                format_ls_rt(rt_buf, sizeof(rt_buf), is_fp, size,
                    state->lspi_pending_rt);
                snprintf(rts, sizeof(rts), "%s", rt_buf);
            }
            if (state->lspi_pending_rn == 31) {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, [sp], #%s0x%x", mnem, rts, idx_sign, a_imm);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, [x%u], #%s0x%x",
                    mnem, rts, state->lspi_pending_rn, idx_sign, a_imm);
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

    // (2) Try to open: is this a zero-offset unsigned-offset LDR/STR
    // (integer or SIMD&FP -- every FP size has a post-indexed form)
    // or a zero-offset LDP/STP/LDPSW pair? Only the zero-offset case
    // folds cleanly: a non-zero offset plus a post-index update has
    // no single-instruction rewrite (pre-indexed handles a different
    // pattern).
    unsigned size, imm12, rn, rt;
    unsigned rt2 = 0;
    int pair_imm7 = 0;
    bool opened = false;
    bool is_load = false;
    bool is_fp = false;
    bool is_pair = false;
    bool is_sw = false;
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
    } else if (decode_pair_soff(op, &is_load, &is_fp, &is_sw, &size,
                                &pair_imm7, &rn, &rt, &rt2)
            && pair_imm7 == 0
            && !(is_load && rt == rt2)) {
        // A load pair with Rt == Rt2 is CONSTRAINED UNPREDICTABLE in
        // both register files even without writeback, so never treat
        // it as foldable; a store pair with a repeated source is fine
        // (stp xzr, xzr is the common 16-byte zero store).
        opened = true;
        is_pair = true;
    }
    if (opened) {
        state->lspi_pending = true;
        state->lspi_pending_is_load = is_load;
        state->lspi_pending_is_fp = is_fp;
        state->lspi_pending_is_pair = is_pair;
        state->lspi_pending_is_sw = is_sw;
        state->lspi_pending_size = size;
        state->lspi_pending_rn = rn;
        state->lspi_pending_rt = rt;
        state->lspi_pending_rt2 = rt2;
        state->lspi_pending_offset = offset;
        const char *mnem = is_pair
            ? pair_mnemonic(is_load, is_sw)
            : ls_mnemonic(is_fp, is_load, size);
        char rt_buf[8];
        char rts[20];
        if (is_pair) {
            char rt2_buf[8];
            format_pair_rt(rt_buf, sizeof(rt_buf), is_fp, is_sw, size, rt);
            format_pair_rt(rt2_buf, sizeof(rt2_buf), is_fp, is_sw, size,
                rt2);
            snprintf(rts, sizeof(rts), "%s, %s", rt_buf, rt2_buf);
        } else {
            format_ls_rt(rt_buf, sizeof(rt_buf), is_fp, size, rt);
            snprintf(rts, sizeof(rts), "%s", rt_buf);
        }
        if (rn == 31) {
            snprintf(state->lspi_pending_disasm,
                sizeof(state->lspi_pending_disasm),
                "%s %s, [sp]", mnem, rts);
        } else {
            snprintf(state->lspi_pending_disasm,
                sizeof(state->lspi_pending_disasm),
                "%s %s, [x%u]", mnem, rts, rn);
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

    // (1) Try to close: is this a zero-offset LDR/STR or
    // LDP/STP/LDPSW whose base matches the pending ADD self-update?
    if (state->lspr_pending) {
        unsigned size, imm12, rn, rt;
        unsigned rt2 = 0;
        int pair_imm7 = 0;
        bool matched = false;
        bool is_load = false;
        bool is_fp = false;
        bool is_pair = false;
        bool is_sw = false;
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
        } else if (decode_pair_soff(op, &is_load, &is_fp, &is_sw, &size,
                                    &pair_imm7, &rn, &rt, &rt2)
                && pair_imm7 == 0
                && rn == state->lspr_pending_rd
                && !(is_load && rt == rt2)) {
            // A load pair with Rt == Rt2 is CONSTRAINED UNPREDICTABLE
            // even without writeback; never fold it. Store pairs with
            // a repeated source are fine.
            matched = true;
            is_pair = true;
        }
        // Rt == Rn writeback is UNPREDICTABLE for loads and
        // CONSTRAINED UNPREDICTABLE for stores (same rule as
        // post-index); a pair extends the rule to its second data
        // register. Rn == 31 is the exception: Rn means SP and Rt
        // means XZR, so the two encode distinct registers. A SIMD&FP
        // Rt lives in a different register file and never aliases.
        bool rt_aliases_rn = matched && !is_fp && rn != 31
            && (rt == rn || (is_pair && rt2 == rn));
        // The opener admits any imm up to the largest pair writeback;
        // re-check against this consumer's actual slot (9-bit signed
        // bytes for singles, scaled 7-bit for pairs).
        bool imm_in_range = false;
        if (matched) {
            uint32_t pimm = state->lspr_pending_imm;
            if (is_pair) {
                unsigned scale = 1u << size;
                imm_in_range = pimm >= scale
                    && pimm % scale == 0
                    && pimm / scale
                        <= (state->lspr_pending_is_sub ? 64u : 63u);
            } else {
                imm_in_range =
                    pimm <= (state->lspr_pending_is_sub ? 256u : 255u);
            }
        }
        if (matched && !rt_aliases_rn && imm_in_range) {
            const char *mnem = is_pair
                ? pair_mnemonic(is_load, is_sw)
                : ls_mnemonic(is_fp, is_load, size);

            // rts holds the data-register list: one register for a
            // single, "rt, rt2" for a pair.
            char rt_buf[8];
            char rts[20];
            if (is_pair) {
                char rt2_buf[8];
                format_pair_rt(rt_buf, sizeof(rt_buf), is_fp, is_sw,
                    size, rt);
                format_pair_rt(rt2_buf, sizeof(rt2_buf), is_fp, is_sw,
                    size, rt2);
                snprintf(rts, sizeof(rts), "%s, %s", rt_buf, rt2_buf);
            } else {
                format_ls_rt(rt_buf, sizeof(rt_buf), is_fp, size, rt);
                snprintf(rts, sizeof(rts), "%s", rt_buf);
            }

            uint32_t imm = state->lspr_pending_imm;
            const char *idx_sign = state->lspr_pending_is_sub ? "-" : "";
            if (is_pair) {
                if (is_load) {
                    out->name = state->lspr_pending_is_sub
                        ? "SUB + LDP foldable to pre-indexed LDP"
                        : "ADD + LDP foldable to pre-indexed LDP";
                } else {
                    out->name = state->lspr_pending_is_sub
                        ? "SUB + STP foldable to pre-indexed STP"
                        : "ADD + STP foldable to pre-indexed STP";
                }
            } else if (is_load) {
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
                    "-> %s %s, [sp, #%s0x%x]!", mnem, rts, idx_sign, imm);
            } else {
                snprintf(out->detail, sizeof(out->detail),
                    "-> %s %s, [x%u, #%s0x%x]!", mnem, rts, rn, idx_sign, imm);
            }
            snprintf(out->lines[0], sizeof(out->lines[0]),
                "%s", state->lspr_pending_disasm);
            if (rn == 31) {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s, [sp]", mnem, rts);
            } else {
                snprintf(out->lines[1], sizeof(out->lines[1]),
                    "%s %s, [x%u]", mnem, rts, rn);
            }
            produced = true;
        }
        // Strict adjacency: clear regardless of match.
        state->lspr_pending = false;
    }

    // (2) Try to open: is this an X-form ADD/SUB-immediate self-update
    // (Rd == Rn) small enough for some writeback slot? The widest is
    // a Q pair's scaled 7-bit immediate: 63 * 16 = 1008 for ADD,
    // 64 * 16 = 1024 for SUB. The close re-checks the actual
    // consumer's range (9-bit signed bytes for singles: ADD 1..255 /
    // SUB 1..256).
    unsigned a_rd, a_rn;
    uint32_t a_imm;
    bool is_add = decode_add_imm_x(op, &a_rd, &a_rn, &a_imm);
    bool is_sub = !is_add && decode_sub_imm_x(op, &a_rd, &a_rn, &a_imm);
    if ((is_add || is_sub)
            && a_rd == a_rn
            && a_imm >= 1
            && a_imm <= (is_sub ? 1024u : 1008u)) {
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
    armlint_advance_pending_zs,
    armlint_advance_pending_cssc,
    armlint_advance_pending_fp,
    armlint_advance_pending_mz,
    armlint_advance_pending_tb,
    check_mul_strength_reduce,
    check_mneg_strength_reduce,
    check_udiv_strength_reduce,
    check_mov_add_sub_imm_fold,
    check_mov_logic_imm_fold,
    check_mov_ccmp_imm_fold,
    check_mov_csel_fold,
    check_mov_shift_fold,
    check_mov_madd_fold,
    check_udiv_msub_remainder,
    check_fmul_fneg_fold,
    check_ldr_cvtf_fold,
    check_ldr_literal_const,
    check_adr_fold,
    check_cssc_minmax,
    check_cssc_abs,
    check_cssc_ctz,
    check_mov_fmov_imm_fold,
    check_fp_zero_to_movi,
    check_extend_cvtf_fold,
    check_mov_zero_to_xzr,
    check_mov_reg_offset_fold,
    check_movz_movk_bitmask,
    check_lsl_fold,
    check_funnel_to_extr,
    check_cmp_zero_branch,
    check_tst_cset,     // reads tst_* state; must precede its owner,
    check_tst_branch,   // which expires the pair on any non-branch
    check_single_bit_cbz,
    check_cset_fold,
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
    check_fcsel_self,
    check_bfxil_synth,
    check_ldp_stp_coalesce,
    check_simd_cmp_zero,
    check_stp_wzr_to_str_xzr,
    check_redundant_cmp_after_s_variant,
    check_zero_cmp_to_s_variant,
    check_sub_cmp_fold,
    check_subs_cmp_redundant,
    check_mul_add_sub_fold,
    check_widening_mul_add_sub_fold,
    check_neg_add_sub_fold,
    check_mvn_logic_fold,
    check_add_one_csel_fold,
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
                       armlint_summary *summary, unsigned features)
{
    armlint_state *state = armlint_state_create();
    if (state == NULL) {
        return -1;
    }
    armlint_state_set_buffer(state, inst, len);
    armlint_state_set_features(state, features);
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
