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

#ifndef ARMLINT_H
#define ARMLINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <capstone/capstone.h>

#ifdef __cplusplus
extern "C" {
#endif

// Pure predicate: true iff imm is encodable as an AArch64 logical
// (bitmask) immediate at the given register width (32 or 64).
//
// Exposed for direct testing. The encoding excludes 0 and the
// all-ones value at the given width.
bool is_bitmask_immediate(uint64_t imm, unsigned reg_width);

// NZCV flag-liveness classification of a single 32-bit A64 instruction
// word, used by the forward scan that drops a CMP/TST once the flags are
// provably dead. Exposed so the test suite can cross-validate it against
// Capstone's register-access model (test_liveness_matches_capstone).
//
// The classifier is hand-rolled rather than derived from Capstone because
// Capstone's implicit-flag model is incomplete: as of 5.0.x cs_regs_access
// does not record the NZCV read of BC.cond, MRS NZCV, CFINV/XAFLAG/AXFLAG,
// RMIF, or SETF8/SETF16 -- precisely the readers that must not be dropped.
// The cross-check therefore treats Capstone as a one-directional partial
// oracle (see the test for the exact properties).
typedef enum {
    LIV_UNKNOWN,        // no effect on NZCV; keep scanning
    LIV_OVERWRITE,      // writes all NZCV without reading them first
    LIV_READ,           // reads any of NZCV
    LIV_TERM_SAFE,      // terminator after which prior NZCV is unobservable
    LIV_TERM_UNSAFE,    // terminator whose target may observe NZCV
} liveness_t;

liveness_t classify_liveness(uint32_t op);

// State carried across instructions for sequence-based checks. Owned by
// the caller; created once per scan and reset between non-contiguous
// regions (e.g. between executable sections).
typedef struct armlint_state armlint_state;

armlint_state *armlint_state_create(void);
void armlint_state_destroy(armlint_state *state);
void armlint_state_reset(armlint_state *state);

// ISA-extension feature bits for armlint_state_set_features. Checks
// that suggest extension instructions stay silent unless their
// feature is enabled (the CLI maps -m cssc etc. onto these).
#define ARMLINT_FEATURE_CSSC (1u << 0)

// Enable ISA-extension-gated checks (a bitmask of ARMLINT_FEATURE_*).
void armlint_state_set_features(armlint_state *state, unsigned features);

// Give binary-aware checks access to the full scanned buffer (the
// bytes the driver is disassembling, offset 0 = the first byte).
// Checks that chase PC-relative data -- literal pools -- read from
// it; without a buffer those checks stay silent. The pointer must
// outlive the scan.
void armlint_state_set_buffer(armlint_state *state, const uint8_t *buf,
                              size_t len);

// Findings reported by check functions. start_offset is the offset of
// the first instruction of the suboptimal run; insn_count is its length.
// detail is a short summary (e.g. the constructed constant, or the
// suggested folded instruction) shown in the header. lines[] holds the
// disassembled offending instructions, one per line; unused slots are
// empty strings.
//
// Checks own the formatting of their detail and lines so that reporting
// does not need to retain the original cs_insn array (cs_disasm_iter
// recycles a single cs_insn slot).
#define ARMLINT_FINDING_LINES      4
#define ARMLINT_FINDING_LINE_LEN   96
#define ARMLINT_FINDING_DETAIL_LEN 128

typedef struct {
    const char *name;
    size_t start_offset;
    unsigned insn_count;
    char detail[ARMLINT_FINDING_DETAIL_LEN];
    char lines[ARMLINT_FINDING_LINES][ARMLINT_FINDING_LINE_LEN];
} armlint_finding;

// Shared signature for per-instruction checks and pre-instruction
// pending-state advancers. Each returns true and fills *out when it
// produces a finding for the given instruction; the advancers ignore
// offset (their finding's offset was recorded when the deferred state
// was opened).
typedef bool (*armlint_check_fn)(armlint_state *state, const cs_insn *insn,
                                 size_t offset, armlint_finding *out);

// Ordered table of every check the driver runs per instruction. The
// pre-instruction advancers (armlint_advance_pending*) appear at the
// front of the list and must run before the per-instruction checks --
// see the comment on armlint_advance_pending for why ordering matters.
// Iterate from 0 to armlint_check_registry_count - 1; both
// check_instructions (driver) and the test harness drive findings off
// this single list, so adding a check requires editing only one place.
extern const armlint_check_fn armlint_check_registry[];
extern const size_t armlint_check_registry_count;

// Track MOVZ/MOVN + MOVK chains and flag one whose final value is
// reachable more cheaply: either as a single bitmask-immediate MOV
// (ORR Rd, ZR, #imm), or by a shorter move-wide sequence -- the
// minimal length is one instruction per non-zero halfword for a
// MOVZ-based chain and one per non-0xFFFF halfword for a MOVN-based
// chain (each with a floor of one), whichever is smaller. Despite the
// name, the bitmask immediate is just one of the two rewrites.
//
// May produce a finding when a non-matching instruction closes a
// previously open sequence, so callers must invoke armlint_flush
// after the last instruction of a region to catch a trailing
// sequence.
bool check_movz_movk_bitmask(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out);

// Detect a shift (immediate) -- LSL/LSR/ASR, or ROR via the
// same-register EXTR alias -- immediately followed by an arithmetic or
// logical shifted-register op that consumes the shift's destination.
// The pair can be replaced by a single shifted-register form (the
// shift rides on the consumer's Rm). ROR folds only into the logical
// consumers: the arithmetic shifted-register encoding reserves shift
// type 11.
//
// The rewrite deletes the shift, so its destination must be dead
// afterward: a consumer that overwrites it proves that on the spot,
// and one writing a fresh register defers through the forward
// register-liveness scan (see armlint_advance_pending_mz). Rd = 31
// consumers are excluded -- the non-S forms are dead writes, the S
// forms the CMP/CMN/TST aliases.
//
// The shift result may sit in the consumer's Rm slot (any consumer) or
// its Rn slot (commutative consumers only -- ADD/ADDS/AND/ANDS/ORR/EOR
// and EON, which is XNOR; the fold swaps the two sources so the shifted
// value lands on Rm). The other ("independent") source operand must not
// also be the shift destination: with both sources equal to it (e.g.
// `lsl wt,ws,#k ; add wt,wt,wt`) the rewrite would read a stale
// pre-shift value, so that case is rejected. An XZR independent
// operand is likewise rejected -- such consumers are shifted register
// copies or constants, not ops the shift rides into.
bool check_lsl_fold(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out);

// Detect an immediate LSL/LSR shift immediately followed by an ORR/EOR/ADD
// whose Rm carries the complementary shift (opposite direction, amounts
// summing to the register width) and whose Rn is the shift's destination.
// The pair is a funnel shift and folds to a single EXTR Rd, Rhi, Rlo, #lsb
// (where the LSR'd source is the low half and the LSL'd source the high
// half); when both funnel sources are the same register it is a rotate and
// folds to ROR Rd, Rs, #lsb. Only ADD/ORR/EOR qualify -- the two shifted
// fields are disjoint, so all three agree with EXTR bit-for-bit -- and the
// consumer's shift must be logical (LSL/LSR), never ASR (its sign fill would
// collide with the other field). Like check_lsl_fold, the rewrite deletes
// the shift, so its destination must be dead afterward: a consumer that
// overwrites it proves that on the spot, and one writing a fresh register
// defers through the forward register-liveness scan (Rd = 31 is a dead
// write and excluded); the inline-shifted source must be a different
// register so the shift does not clobber it.
bool check_funnel_to_extr(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out);

// Detect a zero test of Rn -- any of CMP Rn, #0 / CMP Rn, ZR /
// CMN Rn, #0 / CMN Rn, ZR / TST Rn, Rn (all Rd=31 aliases that leave
// Z = (Rn == 0)) -- immediately followed by B.EQ or B.NE; the pair is
// replaceable by CBZ Rn / CBNZ Rn with the same branch target. The
// unsigned B.HI / B.LS fold the same way after the SUBS-based zero
// tests (CMP Rn, #0 / CMP Rn, ZR): subtracting zero never borrows, so
// C is known set and HI (C && !Z) reduces to NE, LS (!C || Z) to EQ.
// The TST Rn, Rn and CMN forms are excluded from the hi/ls fold --
// ANDS clears C, and adding zero never carries, making HI never taken
// and LS always taken for those spellings. Emission is deferred via
// the pending-finding mechanism so the rewrite is only suggested when
// downstream code provably does not observe the dropped NZCV state --
// see armlint_advance_pending.
bool check_cmp_zero_branch(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out);

// Detect TST Rn, #(1<<k) (ANDS XZR, Rn, #imm) immediately followed by
// B.EQ or B.NE; the pair is replaceable by TBZ Rn, #k or TBNZ Rn, #k
// when the branch target fits in TBZ's shorter (14-bit signed) range.
// Like check_cmp_zero_branch, emission is deferred until the forward
// liveness scan confirms NZCV is dead.
bool check_tst_branch(armlint_state *state, const cs_insn *insn,
                      size_t offset, armlint_finding *out);

// Detect TST Rn, #(1<<k) immediately followed by CSET or CSETM of a
// condition the masked bit fully determines; the pair is a flag-free
// single-instruction bit extract:
//   tst w0, #0x10 ; cset w8, ne  -> ubfx w8, w0, #4, #1
//   tst w0, #0x10 ; csetm w8, ne -> sbfx w8, w0, #4, #1
// NE folds directly (Z clear <=> the bit is set); MI is accepted as
// its synonym when the isolated bit is the producer's sign bit (N is
// that bit). EQ/PL would need an inverted extract (no single
// instruction), and every other condition is constant after TST
// (C = V = 0) -- all are skipped.
//
// CSET's 0/1 result zero-extends identically at either width, so any
// W/X producer/consumer combination folds (the extract renders at the
// consumer's width, bumped to X for bits above 31). CSETM's all-ones
// must replicate at its own width, so a W-form CSETM after an X TST
// of a high bit is skipped. Reads the tst_* pair state owned by
// check_tst_branch (this check runs first in the registry and does
// not expire it).
//
// The rewrite deletes the TST and writes no flags, so all four NZCV
// flags disappear; emission defers through the forward flag-liveness
// scan (armlint_advance_pending) until NZCV is provably dead, exactly
// like the TBZ folds.
bool check_tst_cset(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out);

// Flag-free counterpart of check_tst_branch: a producer that isolates
// a single bit k of Rs into Rd -- a non-flag-setting AND with a
// one-bit mask, or a one-bit UBFM/SBFM extract (`ubfx/sbfx Rd, Rs,
// #k, #1`, including the `lsr/asr Rd, Rs, #(datasize-1)` sign-bit
// aliases) -- immediately followed by CBZ/CBNZ of Rd. Rd == 0 iff
// Rs[k] == 0, so the pair folds to TBZ/TBNZ Rs, #k with the same
// target. No NZCV is involved on either side.
//
// The rewrite deletes the producer, so the masked temp Rd must be
// dead afterward -- on BOTH edges of the branch. Emission is deferred
// (armlint_advance_pending_tb): the forward register-liveness scan
// proves the fall-through path (Rd overwritten before any read or
// control transfer), and the taken path is covered by containment --
// the finding is emitted only when the branch target lies within
// [fall-through, kill], the span the scan just proved free of reads
// and control transfers, so the taken edge enters that clean span and
// reaches the same kill. Backward targets and targets beyond the kill
// are conservatively dropped. This is the canonical skip-a-small-
// block shape; if/else diamonds whose kill precedes the join are left
// unflagged.
//
// A W-form CBZ after a producer isolating bit >= 32 is rejected (the
// branch cannot observe the bit -- degenerate). ANDS producers are
// excluded (deleting one loses the NZCV write), as are ZR sources
// (constant branches) and ZR destinations. The TBZ displacement
// (imm19 + 1 units) is range-checked against the signed 14-bit
// encoding, though the containment gate restricts it far more
// tightly in practice.
bool check_single_bit_cbz(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out);

// Detect CSET Rd, cond (CSINC Rd, ZR, ZR, invert(cond)) immediately
// followed by one of three consumers of Rd -- each expressible as a
// single instruction reading the same still-live NZCV, making the
// CSET deletable:
//   cset w8, eq ; cbnz w8, L      -> b.eq L   (CBZ inverts: b.ne L)
//   cset w8, eq ; eor w9, w8, #1  -> cset w9, ne
//   cset w8, eq ; neg w9, w8      -> csetm w9, eq
// The temp is 0 or 1 zero-extended across the full X register, so a
// consumer of either width observes the same truth value and all
// width combinations fold; the rewrite takes the consumer's width.
// Raw CSINC condition fields AL/NV (a constant 0, not a conditional)
// and ZR destinations are excluded, as are EOR immediates other than
// 1, EOR writing SP (Rd = 31 in a logical immediate), shifted or
// flag-setting NEG forms, and NEG/EOR discarding to ZR.
//
// Deleting the CSET requires the temp dead afterward. For the branch
// consumer that means dead on BOTH edges: emission defers through the
// two-edge scan (armlint_advance_pending_tb) built for the single-bit
// fold -- the forward scan proves the fall-through path and the taken
// edge is covered by containment in [fall-through, kill]; backward
// targets are dropped at the consumer. B.cond's displacement (imm19 +
// 1 units, replacing the producer) is range-checked at the positive
// encoding limit. For EOR/NEG, a consumer overwriting the temp itself
// kills it on the spot (emit immediately); otherwise emission defers
// through the plain forward scan (defer_dead_mov).
bool check_cset_fold(armlint_state *state, const cs_insn *insn,
                     size_t offset, armlint_finding *out);

// Detect a producer that provably zeros bits 63..P of its destination,
// immediately followed by an in-place zero-extension consumer that
// clears bits >= C with P <= C -- a no-op. Producers: any W-form
// data-processing write (P=32) and the W-form integer loads (P=8/16/32
// by access width), with sharper value-derived thresholds -- in both W
// and X form -- for UBFM (P from the field geometry, covering
// LSR/UBFX/UXTB/UXTH), AND/ANDS immediate (P = top set bit of the mask
// + 1), MOVZ (P = bit count of the known value), and CSINC Rd, ZR, ZR
// (CSET: P = 1). Consumers: an in-place UBFM with immr=0 of any width
// (UXTB/UXTH/UXTW and general UBFX #0, #C), an AND with a contiguous
// low mask (C = mask width), or MOV Wd, Wd (C = 32 via the W write).
bool check_redundant_zext(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out);

// Detect a sign-extending producer (LDRSB / LDRSH / LDRSW, or any
// SBFM: the SXTB / SXTH / SXTW aliases, ASR immediate, and the
// general SBFX / SBFIZ shapes, whose sign threshold follows from the
// field geometry) immediately followed by an SXTB / SXTH / SXTW
// consumer whose destination width matches the producer's and whose
// sign threshold is at least the producer's. The consumer is
// redundant: the producer already replicated the sign bit through the
// same upper bits.
bool check_redundant_sext(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out);

// Detect LSL Rd, Rs, #a immediately followed by LSR/ASR Rd, Rd, #b
// with b >= a. The pair extracts bits Rs[datasize-a-1 .. b-a] and
// zero- or sign-extends them; equivalent to a single UBFX/SBFX
// Rd, Rs, #(b-a), #(datasize-b).
bool check_lsl_lsr_to_ubfx(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out);

// Detect LSR Rd, Rs, #n immediately followed by AND Rd, Rd, #((1<<w)-1)
// (any width 1..datasize-1). The pair extracts bits Rs[n+w-1 .. n] and
// zero-extends; equivalent to a single UBFX Rd, Rs, #n, #w (capping
// width at datasize-n if the mask is wider than the LSR-fillable bits).
bool check_lsr_and_to_ubfx(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out);

// Mirror of check_lsr_and_to_ubfx for the opposite ("mask then
// shift-right") order. Detect AND Rd, Rs, #mask -- where mask is a
// single contiguous run of 1s [lo, hi] -- immediately followed by
// LSR Rd, Rd, #n (the LSR reads and writes the AND's destination). The
// pair extracts Rs[hi .. n] (the run bits at or above the shift) into
// the low bits; equivalent to a single UBFX Rd, Rs, #n, #(hi+1-n).
//
// Foldable only when lo <= n <= hi: lo > n would leave the field above
// bit 0 (no single-UBFX form), and n > hi shifts the whole run out
// (a degenerate zero result). Replicated/rotated-wrapping masks are
// not single runs and are skipped. ANDS (flag-setting) is excluded.
bool check_and_lsr_to_ubfx(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out);

// The left-shift mirror of the two checks above: an AND-low-mask or LSR
// immediately followed by LSL Rd, Rd, #n (the LSL reads and writes the
// producer's destination).
//   and wd, ws, #((1<<w)-1) ; lsl wd, wd, #n -> ubfiz wd, ws, #n, #w
//     ((ws & low-w-bits) << n; width capped at datasize-n when it would
//      overflow), and
//   lsr wd, ws, #a ; lsl wd, wd, #a -> and wd, ws, #~((1<<a)-1)
//     (equal shifts clear the low a bits).
// LSR + LSL with unequal shifts has no single-instruction form -- the
// surviving field is neither low- nor zero-aligned -- and is not
// flagged. ANDS (flag-setting) is excluded by the low-mask decoder.
bool check_and_lsr_lsl_fold(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out);

// Detect MOV Xd, Xd encoded as ORR Xd, XZR, Xd, LSL #0 -- a literal
// no-op that reads and writes the same 64 bits. The W-form MOV Wd, Wd
// is NOT flagged here: it zero-extends X[63:32] and is handled as a
// consumer in check_redundant_zext.
bool check_mov_reg_self(armlint_state *state, const cs_insn *insn,
                        size_t offset, armlint_finding *out);

// Detect ADD/SUB (immediate) with imm = 0 and the non-flag-setting
// variant (S = 0). When Rd == Rn the instruction is a no-op; when
// Rd != Rn it is equivalent to MOV Rd, Rn. The SP encoding (Rd = 31
// or Rn = 31) is excluded because that's the canonical MOV-to/from-SP
// alias. The Rd == Rn case immediately following an ADR/ADRP with
// the same Rd is also excluded: that's the linker-resolved
// "page-relative addressing" pair where the offset happened to be 0,
// removable only by re-linking.
bool check_add_sub_zero(armlint_state *state, const cs_insn *insn,
                        size_t offset, armlint_finding *out);

// Detect self-op identities: AND/ORR Rd, Rs, Rs (shifted-register,
// LSL #0, Rn == Rm) collapses to MOV Rd, Rs; EOR/SUB/BIC Rd, Rs, Rs
// collapses to MOV Rd, XZR (zero); ORN/EON Rd, Rs, Rs collapses to
// MOV Rd, #-1 (MOVN Rd, #0). Flag-setting variants (ANDS/SUBS/BICS)
// are skipped because the flag-set is the user's intent.
bool check_self_op(armlint_state *state, const cs_insn *insn,
                   size_t offset, armlint_finding *out);

// Detect CSEL Rd, Rn, Rn, cond -- the same-operand case where both
// branches of the conditional select produce Rn. The cond is
// irrelevant, the NZCV read is wasted, and the instruction is
// equivalent to MOV Rd, Rn. Only matches CSEL (op2 = 00); the other
// members of the family -- CSINC / CSINV / CSNEG -- have different
// "else" branches and are NOT identities when Rn == Rm.
bool check_csel_self(armlint_state *state, const cs_insn *insn,
                     size_t offset, armlint_finding *out);

// FP mirror of check_csel_self: FCSEL Vd, Vn, Vm, cond with Vn == Vm
// selects the same value on both branches, so the condition is
// irrelevant and the instruction is a register copy --
// FMOV (register). FCSEL is a pure bit-pattern select (no
// arithmetic, no NaN processing), and both FCSEL and FMOV zero the
// vector register above the written lane, so the rewrite is exact
// for the full 128 bits; the pointless NZCV read disappears too.
// Single and double precision only (half precision, FEAT_FP16, is
// not matched, consistent with the other FP checks); FP registers
// have no ZR/SP encoding, so no operand exclusions apply. Reported
// as "FCSEL same-operand identity".
bool check_fcsel_self(armlint_state *state, const cs_insn *insn,
                     size_t offset, armlint_finding *out);

// Detect the 3-instruction BFXIL synthesis pattern:
//   AND Rd, Rd, #~mask    ; clear Rd[w-1..0]
//   AND Rt, Rs, #mask     ; isolate Rs[w-1..0] into Rt
//   ORR Rd, Rd, Rt        ; combine
// (the two ANDs in either order). Equivalent to a single
// BFXIL Rd, Rs, #0, #w. Aliasing constraints: Rt != Rd (so the
// isolate doesn't clobber the cleared Rd in place), Rt != Rs (so
// the isolate doesn't modify the source), and Rs != Rd (the
// degenerate case where the source is the just-cleared register
// yields a no-op instead of BFXIL).
//
// The BFXIL/BFI rewrite writes only Rd and drops the isolate's temp Rt
// (it is never written by the rewrite). Emission is therefore deferred
// until the forward register-liveness scan (armlint_advance_pending_mz)
// proves Rt dead after the ORR; a downstream read of Rt before it is
// overwritten would make dropping the isolate unsound.
bool check_bfxil_synth(armlint_state *state, const cs_insn *insn,
                       size_t offset, armlint_finding *out);

// Detect MUL Rd, Rn, Rm (the MADD Rd, Rn, Rm, ZR alias) where one
// operand is set by an immediately preceding MOV chain (MOVZ/MOVN +
// optional MOVKs) to a constant C. The MUL is foldable to a single
// shifted-register instruction when C is a small step from a power
// of two:
//   C = 2^N (N >= 1)     -> LSL Rd, R<other>, #N
//   C = 2^N + 1 (N >= 1) -> ADD Rd, R<other>, R<other>, LSL #N
// The 2^N - 1 case is intentionally not folded: AArch64 has no single
// shifted-register form computing x*(2^N - 1) directly --
// SUB Xn, Xn, Xn, LSL #N gives x*(1 - 2^N), the negation -- so the
// rewrite needs two instructions (LSL+SUB or SUB+NEG), at parity with
// MOV+MUL in instruction count. The MOV chain's width (W vs X) must
// match the MUL's; MUL is commutative, so either Rn or Rm may be the
// MOV destination. ZR as Rd or as the "other" operand is excluded, as
// is the surviving operand being the MOV destination itself
// (MUL Rd, Xc, Xc): the rewrite would still read the constant
// register, so the MOV could never be deleted.
//
// Runs before check_movz_movk_bitmask in the registry: that check
// closes the MOV chain on any non-MOV instruction, so ours must
// inspect state->mov_active first.
bool check_mul_strength_reduce(armlint_state *state, const cs_insn *insn,
                               size_t offset, armlint_finding *out);

// Detect MNEG Rd, Rn, Rm (the MSUB Rd, Rn, Rm, ZR alias) where one
// operand is set by an immediately preceding MOV chain to a constant
// C. The MNEG is foldable to a single shifted-register instruction
// for three families of constants:
//   C = 1                -> NEG Rd, R<other>
//   C = 2^N (N >= 1)     -> NEG Rd, R<other>, LSL #N
//   C = 2^N - 1 (N >= 2) -> SUB Rd, R<other>, R<other>, LSL #N
// The 2^N - 1 family is the elegant complement of MUL's 2^N + 1:
// SUB Xd, Xn, Xn, LSL #N computes x*(1 - 2^N) = -x*(2^N - 1), exactly
// what MNEG needs.
//
// 2^N + 1 (N >= 1) is NOT folded: the rewrite -((x << N) + x) is two
// instructions (ADD-shifted then NEG, or SUB+NEG), at parity with
// MOV+MNEG.
//
// Same plumbing as check_mul_strength_reduce -- runs before
// check_movz_movk_bitmask so the MOV chain state is still active.
// Shares its exclusions, including the surviving operand being the
// MOV destination itself (MNEG Rd, Xc, Xc).
bool check_mneg_strength_reduce(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Detect UDIV Rd, Rn, Rm where Rm is set by an immediately preceding
// MOV chain to a constant C that is a power of two (C = 2^N, N >= 1).
// The pair folds to a single shift:
//   mov xc, #2^N ; udiv xd, xn, xc  ->  lsr xd, xn, #N
// Width (W vs X) of the MOV chain must match the UDIV.
//
// UDIV is NOT commutative, so unlike the MUL strength reduction only
// the divisor (Rm) can come from the MOV; an Rn-from-MOV match would
// be a reciprocal-multiply problem, not a shift. Non-pow2 divisors
// have no single-instruction shift rewrite and are excluded.
//
// SDIV is intentionally NOT included: SDIV by 2^N is not equivalent
// to ASR by N on negative dividends (SDIV rounds toward zero; ASR
// rounds toward -inf), so the fold would be incorrect.
//
// C == 0 is degenerate (UDIV by zero produces 0 on AArch64, no trap)
// and C == 1 is the identity case; both are excluded. Rd == ZR
// discards the result and Rn == ZR makes the dividend always zero --
// different idioms, not strength reduction. The dividend must also
// not be the MOV destination itself (UDIV Rd, Xc, Xc): the LSR
// rewrite would still read the constant register, so the MOV could
// never be deleted.
//
// Runs alongside check_mul_strength_reduce / check_mneg_strength_reduce
// before check_movz_movk_bitmask so the MOV chain state is still
// active.
bool check_udiv_strength_reduce(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Detect ADD/ADDS/SUB/SUBS (shifted-register, LSL #0) where one
// operand is set by an immediately preceding MOV chain to a constant
// C that fits the AArch64 ADD/SUB immediate form (12-bit imm with
// optional LSL #12: C in [1, 0xFFF] or C a multiple of 0x1000 with
// C/0x1000 in [1, 0xFFF]). The pair folds to a single immediate-form
// instruction:
//   mov xc, #C ; add  xd, xn, xc -> add  xd, xn, #C
//   mov xc, #C ; adds xd, xn, xc -> adds xd, xn, #C
//   mov xc, #C ; sub  xd, xn, xc -> sub  xd, xn, #C
//   mov xc, #C ; subs xd, xn, xc -> subs xd, xn, #C
// CMP and CMN (S-variant with Rd == ZR) are rendered as the aliases.
//
// A NEGATIVE constant whose magnitude fits the encoding folds
// sign-crossed into the opposite consumer (add <-> sub, adds <->
// subs, cmp <-> cmn), reported as "MOV + ADD/SUB foldable to
// sign-crossed immediate form":
//   mov xc, #-5 ; add xd, xn, xc -> sub xd, xn, #5
// The crossing is exact for every flag, not just the result:
// SUBS Rn, Rm with Rm = -C computes Rn + NOT(-C) + 1 = Rn + C, the
// identical 65-bit sum as ADDS Rn, #C, so N, Z, C and V agree
// bit-for-bit (and symmetrically for ADDS of a negative). MOVN
// chains reach these values naturally.
//
// ADD is commutative so either Rn or Rm may be the MOV destination;
// SUB requires Rm == mov_rd (Rn == mov_rd would need a reverse-
// subtract, which AArch64 does not encode in a single instruction).
// Width of the MOV chain (W vs X) must match the ADD/SUB's. C == 0 is
// excluded -- that pattern is the MOV-to-Rn or no-op case already
// handled by check_add_sub_zero. ZR as the non-mov operand is also
// excluded (it makes the ADD/SUB degenerate), as is the surviving
// operand being the MOV destination itself (ADD Rd, Xc, Xc, or
// CMP/SUB of Xc against itself): the immediate rewrite would still
// read the constant register, so the MOV could never be deleted.
//
// Runs alongside check_mul_strength_reduce / check_mneg_strength_reduce
// before check_movz_movk_bitmask so the MOV chain state is still
// active when the consumer is examined.
bool check_mov_add_sub_imm_fold(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Detect a logical shifted-register op (LSL #0) where one operand is
// set by an immediately preceding MOV chain to a constant C, and the
// constant the immediate form needs is a valid AArch64 bitmask
// immediate at the consumer's width. The pair folds to the immediate
// form. For the direct (N = 0) ops the immediate is C itself:
//   mov xc, #C ; and  xd, xn, xc -> and  xd, xn, #C
//   mov xc, #C ; orr  xd, xn, xc -> orr  xd, xn, #C
//   mov xc, #C ; eor  xd, xn, xc -> eor  xd, xn, #C
//   mov xc, #C ; ands xd, xn, xc -> ands xd, xn, #C   (TST when Rd=ZR)
// The N = 1 ops (BIC/ORN/EON/BICS) compute Rn op NOT(Rm), so when the
// constant is the inverted operand the NOT folds into it -- the
// rewrite is the direct-form immediate with ~C:
//   mov xc, #C ; bic  xd, xn, xc -> and  xd, xn, #~C
//   mov xc, #C ; orn  xd, xn, xc -> orr  xd, xn, #~C
//   mov xc, #C ; eon  xd, xn, xc -> eor  xd, xn, #~C
//   mov xc, #C ; bics xd, xn, xc -> ands xd, xn, #~C  (TST when Rd=ZR)
// (BICS and ANDS-immediate set identical NZCV: N/Z from the result,
// C = V = 0.) is_bitmask_immediate is the encodability predicate;
// values 0 and the all-ones-at-width are not bitmask immediates, so
// the trivial-constant cases naturally skip on either side.
//
// AND/ORR/EOR/ANDS are commutative, so either Rn or Rm may be the MOV
// destination; BIC/ORN/EON/BICS invert Rm only, so the constant must
// be Rm (Rn from the MOV computes C op ~Rm, which has no immediate
// form). The surviving operand must not be the MOV destination itself
// (the rewrite would still read the constant register, so the chain
// could never be deleted); ZR as the non-MOV operand is excluded
// (degenerate). The two families report distinct finding names.
bool check_mov_logic_imm_fold(armlint_state *state, const cs_insn *insn,
                              size_t offset, armlint_finding *out);

// Detect a MOV chain materialising a constant C in [0, 31], immediately
// followed by a register-form conditional compare whose Rm is the
// constant. The compare folds to its immediate form, making the MOV
// dead:
//   mov x8, #5 ; ccmp x0, x8, #0, ne -> ccmp x0, #5, #0, ne
// Same for CCMN; the nzcv literal and condition carry over verbatim.
//
// The conditional compare is not commutative: only Rm has an immediate
// slot, so Rn from the chain is not folded (a reversed compare has no
// encoding). The chain's width (W vs X) must match the compare's. The
// surviving Rn must not be the constant register (the rewrite would
// still read it) nor ZR (a degenerate compare-against-zero idiom).
// imm5 is unsigned, so a non-negative C folds only in [0, 31]; a
// NEGATIVE constant whose magnitude fits imm5 folds sign-crossed into
// the opposite compare (ccmp <-> ccmn), reported as "MOV + CCMP/CCMN
// foldable to sign-crossed immediate form" -- the NZCV agree exactly
// (when the condition holds, the compare of -C and the opposite
// compare of #C perform the identical 65-bit sum; when it fails both
// set the carried-over #nzcv literal).
//
// A conditional compare writes only NZCV and never kills the constant
// register, so the finding always defers through the forward
// register-liveness scan (defer_dead_mov) until mov_rd is provably
// dead. Runs before check_movz_movk_bitmask so the chain state is
// still active.
bool check_mov_ccmp_imm_fold(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out);

// Detect a MOV chain materialising exactly 1, immediately followed by
// a CSEL with the constant in either operand slot. CSINC's else-branch
// is Rm + 1, so the 1 is reproduced by incrementing ZR:
//   mov w8, #1 ; csel wd, w8, wn, cc -> csinc wd, wn, wzr, !cc
//   mov w8, #1 ; csel wd, wn, w8, cc -> csinc wd, wn, wzr, cc
// The then-slot form inverts the condition (the 1 moves to the else
// branch); the else-slot form keeps it. When the surviving operand is
// ZR the rewrite is the CSET alias (cset wd, cc / cset wd, !cc
// respectively -- the condition under which the result is 1), the
// common bool-materialisation shape spelled through a constant
// register.
//
// Only CSEL proper (op2 = 00) matches; CSINC/CSINV/CSNEG have
// different else-branches. AL/NV conditions are excluded
// (ConditionHolds treats both as always-true, so the select is a
// plain MOV and the then-slot inversion would still be taken), as are
// Rd = 31 (a discarded select) and a CSEL reading the constant in
// both slots (the same-operand identity, check_csel_self's shape).
// Widths must match (both W or both X), consistent with the other
// integer MOV-chain folds.
//
// The rewrite deletes the MOV. A select whose destination IS the
// constant register overwrites it at the consumer itself and reports
// immediately; otherwise the finding defers through the forward
// register-liveness scan (defer_dead_mov) until the constant register
// is provably dead. Runs before check_movz_movk_bitmask so the chain
// state is still active. Reported as "MOV #1 + CSEL foldable to
// CSINC/CSET".
//
// A materialised all-ones folds identically through CSINV (else
// branch ~Rm: mov w8, #-1 ; csel wd, wn, w8, cc ->
// csinv wd, wn, wzr, cc; ZR surviving operand -> the CSETM alias),
// reported as "MOV #-1 + CSEL foldable to CSINV/CSETM". All-ones is
// width-dependent (0xFFFFFFFF for a W chain), unlike the zero fold's
// width-agnostic value, so the width gate does real work here.
bool check_mov_csel_fold(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out);

// Detect a MOV chain materialising a shift amount, immediately
// followed by a variable shift (LSLV/LSRV/ASRV/RORV -- spelled
// lsl/lsr/asr/ror with a register amount) whose Rm is the constant
// register. Every variable shift has an immediate-form twin (the
// UBFM/SBFM aliases; EXTR for ROR), so the pair folds:
//   mov w8, #5 ; lsl wd, wn, w8 -> lsl wd, wn, #5
// The register form shifts by UInt(Rm) MOD datasize, so the folded
// immediate is the chain's value reduced modulo 32/64 (a chain of
// #67 feeding a 64-bit shift folds to #3); a residue of 0 shifts by
// nothing -- a register copy, not a shift -- and is left alone as
// degenerate. The shifted operand Rn must not be the constant
// register (the rewrite would still read it) nor ZR (a constant),
// Rd = 31 (a discarded shift) is excluded, and the chain's width
// must match the shift's, consistent with the other integer
// MOV-chain folds.
//
// The rewrite deletes the MOV; the immediate and register shift
// forms cost the same. A shift whose destination IS the constant
// register overwrites it at the consumer and reports immediately;
// otherwise the finding defers through the forward register-liveness
// scan (defer_dead_mov) until the constant register is provably
// dead. Runs before check_movz_movk_bitmask so the chain state is
// still active. Reported as "MOV + variable shift foldable to
// immediate shift".
bool check_mov_shift_fold(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out);

// Detect a MOV chain materialising a power of two, immediately
// followed by a MADD/MSUB whose multiplier (either multiply operand;
// the multiply commutes) is the constant register. The multiply
// becomes the consumer's shifted-register operand:
//   mov x8, #8 ; madd xd, xn, x8, xa -> add xd, xa, xn, lsl #3
//   mov x8, #8 ; msub xd, xn, x8, xa -> sub xd, xa, xn, lsl #3
// A multiplier of 1 (N = 0) folds to the plain ADD/SUB. This is the
// non-ZR-accumulator complement of the MUL/MNEG strength reductions:
// Ra = 31 is the MUL/MNEG alias and stays with those checks. Same
// win as theirs -- the multiply leaves the multiplier pipe (2-3
// cycle latency, limited throughput) for a single-cycle shifted ADD
// -- plus the deleted MOV.
//
// Exclusions: Rd = 31 (result discarded); the accumulator must not
// be the constant register (the rewrite still reads it); the
// surviving multiply operand must not be the constant (a
// constant-squared shape) nor ZR (a zero product -- the pair is a
// register copy). The chain's width must match the MAC's. Deadness
// follows the MOV-chain family: a MAC whose destination IS the
// constant register reports immediately, otherwise emission defers
// through the forward register-liveness scan (defer_dead_mov). Runs
// before check_movz_movk_bitmask so the chain state is still
// active. Reported as "MOV + MADD/MSUB foldable to shifted
// ADD/SUB".
bool check_mov_madd_fold(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out);

// Detect the unsigned remainder-by-power-of-two idiom spelled through
// a divide: a MOV chain materialising 2^N, an adjacent UDIV taking it
// as divisor, and an adjacent MSUB reconstructing the remainder:
//   mov x8, #16 ; udiv x9, x1, x8 ; msub x9, x9, x8, x1
//     -> and x9, x1, #0xf
// dividend - (dividend / 2^N) * 2^N is dividend mod 2^N, and UDIV's
// truncation is the flooring the identity needs for unsigned values,
// so a single AND with 2^N - 1 (always a valid bitmask immediate)
// replaces all three instructions -- and retires one of the slowest
// A64 operations. The MSUB's multiply commutes (quotient and constant
// in either operand); its accumulator must be the original dividend,
// which the adjacent pair provably left unmodified. The signed
// (SDIV) idiom does NOT fold: for negative dividends the flooring
// AND disagrees with SDIV's truncation.
//
// Deadness: the rewrite deletes the MOV, the UDIV and the MSUB,
// leaving two temporaries -- the quotient and the constant. The
// MSUB's own destination kills one structurally (compilers reuse the
// quotient register); the forward register-liveness scan
// (defer_dead_mov) gates the other. A fresh destination would need
// two proofs at once and is conservatively skipped. The existing
// MOV + UDIV -> LSR check never double-reports on this shape: its
// own dead-constant scan sees the MSUB re-read the constant and
// discards.
//
// Exclusions at the UDIV: the quotient must be a fresh register
// (xq == dividend clobbers what the MSUB re-reads; xq == the
// constant clobbers the divisor; ZR operands are degenerate), the
// dividend must not be the constant or ZR, N = 0 (dividing by 1) is
// the identity, and all widths must match. Reported as "remainder by
// power of two foldable to AND".
bool check_udiv_msub_remainder(armlint_state *state, const cs_insn *insn,
                               size_t offset, armlint_finding *out);

// Detect a scalar FMUL (S or D) immediately followed by an in-place
// FNEG of its destination; the pair is a single FNMUL:
//   fmul d0, d1, d2 ; fneg d0, d0 -> fnmul d0, d1, d2
// FNMUL's pseudocode is FPMul followed by FPNeg of the ROUNDED
// product -- negation is a pure sign flip, applied after rounding and
// raising nothing -- so the fold is bit-exact in every FPCR rounding
// mode with identical FPSR exceptions, NaNs included: both spellings
// apply the same FPNeg to the same FPMul result. The unsound sibling
// is deliberately not matched: negating an OPERAND first computes
// round(-(a*b)), which differs from -(round(a*b)) under the directed
// rounding modes (FNMUL is the latter).
//
// The FNEG must read the FMUL's destination (Rn == the product
// register). An FNEG that overwrites it in place (Rd == Rn) proves
// the intermediate product dead structurally and reports
// immediately; a fresh destination defers through the FP/vector
// register liveness scan (armlint_advance_pending_fp) until the
// product register provably dies. All three scalar writes zero the
// vector register above the written lane, so the final 128-bit state
// is identical. Half precision (FEAT_FP16) is not matched, consistent
// with the FMOV folds. No aliasing exclusions are needed: the rewrite
// reads the FMUL's own sources at the FMUL's position, and even
// in-place multiplies (Rd among the sources) read before writing in
// both spellings. Reported as "FMUL + FNEG foldable to FNMUL".
bool check_fmul_fneg_fold(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out);

// Detect an int-to-FP conversion routed through a GPR: a plain
// unsigned-offset LDR W/X immediately followed by a width-matched
// SCVTF/UCVTF of the loaded register. Loading into the FP register
// and converting in-SIMD performs the identical conversion without
// the cross-register-file transfer:
//   ldr w8, [x1] ; scvtf s0, w8 -> ldr s0, [x1] ; scvtf s0, s0
//   ldr x8, [x1, #8] ; ucvtf d0, x8 -> ldr d0, [x1, #8] ; ucvtf d0, d0
// Same instruction count; the win is the transfer. The GPR-source
// conversions pay a several-cycle GPR -> FP move on current cores
// (it rides the load pipes on Apple's, the M0 pipe on Neoverse), and
// Apple's CPU optimization guide recommends exactly this rewrite.
// The loaded GPR is freed too.
//
// Exactness: the rewrite performs the identical memory access (same
// address, same size), converts the same 32/64-bit integer value
// under the same FPCR rounding with the same FPSR exceptions, and
// both spellings zero the vector register above the written lane.
// Widths must match on both sides -- only int32 -> single and
// int64 -> double have in-SIMD twins; there is no cross-width scalar
// conversion -- so mixed pairs (scvtf d0, w8), the byte/halfword
// loads and the sign-extending loads never fold. Half precision
// (FEAT_FP16) is excluded by the shared decoder. Rt = 31 (a
// discarded load) does not open.
//
// The rewrite stops writing the GPR entirely, so the loaded register
// must be dead afterward; the conversion writes only an FP register
// and can never kill it, so the finding always defers through the
// forward register-liveness scan (defer_dead_mov). v1 matches the
// unsigned-offset addressing form only, like the other load-rewriting
// folds. Reported as "load + SCVTF/UCVTF via GPR foldable to FP load
// + convert".
bool check_ldr_cvtf_fold(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out);

// Detect a PC-relative literal load (LDR Wt/Xt/St/Dt, <label>) whose
// pooled value has a single-instruction immediate materialisation:
//   ldr w0, <literal holding 0x2a>       -> mov w0, #0x2a
//   ldr d0, <literal holding 1.5>        -> fmov d0, #1.5
// GPR values fold when MOVZ/MOVN/bitmask-immediate encodable (the
// forms the assembler accepts for mov Rd, #imm); FP values when
// FMOV-imm8 encodable (VFPExpandImm in reverse, via fp8_encodable).
// An LDRSW literal materialises the SIGN-EXTENDED value and folds
// when that is mov-encodable at X width. A Q literal folds when the
// 128-bit pattern has an integer MOVI/MVNI spelling
// (q_movi_spelling: halves equal, then 16B/8H/4S LSL+MSL/2D
// byte-mask, smallest element first; the FP-vector immediates are
// not attempted). PRFM is not a load and never folds.
//
// The first binary-aware check: the literal is PC-relative, so the
// check reads the pooled bytes out of the scanned buffer itself
// (armlint_state_set_buffer). A target outside the buffer -- an
// out-of-section pool -- is silently skipped, as is everything when
// no buffer was provided.
//
// A one-for-one rewrite: same destination register, no other
// register or flag touched, and the loaded value is reproduced
// exactly, so the finding emits immediately with no liveness proof.
// What it saves: the memory access -- load-use latency and a cache
// line -- plus the pool slot when nothing else references it.
// Reported as "LDR literal foldable to MOV/FMOV immediate".
bool check_ldr_literal_const(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out);

// Detect an ADR whose materialised address is consumed once by the
// adjacent instruction, where the consumer has a direct PC-relative
// form of its own:
//   adr x8, L ; ldr x8, [x8]   -> ldr x8, L    (LDR (literal))
//   adr x16, L ; br x16        -> b L          (direct branch)
// The load form covers every literal-capable width -- LDR W/X,
// LDRSW, and SIMD&FP S/D/Q; byte/halfword loads have no literal
// form -- at zero offset, and performs the identical access without
// the address ever existing in a register. Encodability gates: the
// literal's word-scaled imm19 is anchored at the LOAD's PC (one
// instruction after the ADR's), so the target must be 4-byte
// aligned and the re-anchored displacement must still fit +/-1MB
// (it can fall off the low edge when the ADR named exactly -1MB).
// The rewrite deletes the ADR, so the address register must be dead:
// a load destination that IS the address register kills it
// structurally; otherwise the finding defers through the forward
// register-liveness scan. The target may lie outside the scanned
// buffer -- the fold never reads the pointed-to data, so no buffer
// is required at all.
//
// The branch form's rewrite range is a non-issue (B reaches
// +/-128MB, strictly covering ADR's +/-1MB), but BR never writes the
// address register and the linear liveness scan cannot follow the
// branch, so v1 folds only x16/x17 (IP0/IP1): the ABI reserves them
// as veneer scratch, and code at the target is not entitled to
// receive values in them across exactly this shape. The general-
// register case would need liveness at the TARGET, future work. BLR
// is excluded outright -- a callee legitimately receives registers,
// x8 (the indirect-result pointer) in particular. ADRP does not
// open (page arithmetic, a different fold); ADR to XZR is a dead
// write. Reported as "ADR + load of its target foldable to LDR
// (literal)" / "ADR + BR foldable to direct branch".
bool check_adr_fold(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out);

// CSSC synthesis checks (gated on ARMLINT_FEATURE_CSSC; silent
// otherwise). Armv8.9/9.4 Common Short Sequence Compression gives
// single instructions for idioms the base ISA spells in two:
//
//   cmp x1, x2 ; csel x0, x1, x2, gt -> smax x0, x1, x2
//     (GE/GT pick the larger -- the equal case selects equal values,
//     so both work -- LT/LE the smaller, HS/HI and LO/LS the
//     unsigned twins; swapped CSEL operands flip the direction. Only
//     the plain shifted-register LSL #0 compare with distinct
//     operands opens.)
//   cmp x1, #0 ; cneg x0, x1, mi -> abs x0, x1
//     (raw CSNEG with both sources the compared register and cond in
//     {PL, GE, GT}: the condition holds exactly for r >= 0, or r > 0
//     where the r = 0 else-branch still yields -0 = 0.)
//   rbit x0, x1 ; clz x0, x0 -> ctz x0, x1
//     (counting leading zeros of a bit reversal counts trailing
//     zeros of the original.)
//
// The MAX/MIN and ABS rewrites DELETE the compare and set no flags,
// so they defer through an NZCV-death scan (a dedicated shared slot,
// armlint_advance_pending_cssc; classify_liveness is exactly right
// because any later flag reader must discard). CTZ involves no flags
// and uses the standard register deferral: a CLZ destination that IS
// the reversed register kills it structurally.
//
// The remaining CSSC candidate -- the NEON popcount round trip
// (fmov d0, x0 ; cnt ; addv ; fmov) -> cnt Xd, Xn -- requires
// proving the vector temporary dead; the FP-register liveness scan
// (armlint_advance_pending_fp) now exists, so only the four-stage
// chain match remains future work.
bool check_cssc_minmax(armlint_state *state, const cs_insn *insn,
                       size_t offset, armlint_finding *out);
bool check_cssc_abs(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out);
bool check_cssc_ctz(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out);

// NZCV-death advancer for the deferred CSSC findings, parallel to
// armlint_advance_pending_zs.
bool armlint_advance_pending_cssc(armlint_state *state,
                                  const cs_insn *insn,
                                  size_t offset, armlint_finding *out);

// Forward FP/vector-register liveness scan, the FP twin of
// armlint_advance_pending_mz: emits a deferred finding once a later
// instruction provably overwrites the watched vector register before
// any read or control transfer. All six views (B/H/S/D/Q/V) of the
// register count as touches. Because vector read-modify-writers are
// pervasive (accumulators, lane inserts, bitwise selects, the vector
// ORR/BIC immediates), a written vector operand is treated as also
// read unless its class is on the pure-overwrite whitelist (scalar FP
// data processing, FP 3-source, SIMD&FP loads) -- unlisted writers
// merely fail to commit, keeping all error in the false-negative
// direction. Used by the FMUL + FNEG fold's fresh-destination
// consumer; unlocks the MOVI + vector-compare fresh destination, the
// CSSC popcount chain, the FCVTZS + STR store fold, and the FMOV
// round trips as follow-ups.
bool armlint_advance_pending_fp(armlint_state *state,
                                const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Detect a MOV chain materialising an FP bit pattern or a small
// integer, immediately followed by the GPR -> FP transfer or
// conversion that consumes it, when FMOV (scalar, immediate) could
// produce the value directly, making the MOV (and the cross-file
// transfer's latency) avoidable:
//   mov w8, #0x3f800000 ; fmov s0, w8  -> fmov s0, #1.0
//   mov x8, #0x3ff0000000000000 ; fmov d0, x8 -> fmov d0, #1.0
//   mov w8, #5 ; scvtf d0, w8          -> fmov d0, #5.0
// Consumers: FMOV (general) in the GPR -> FPR direction (fmov Sd, Wn
// / fmov Dd, Xn) and the scalar conversions SCVTF/UCVTF from either
// GPR width. FMOV's imm8 expands to +/-(16..31)/16 * 2^n for n in
// [-3, 4] (so every integer of magnitude 1..31); zero is NOT
// expressible and never matches -- zeroing idioms are out of scope.
// The encodability test is an exact bit-pattern match. Half-precision
// destinations (FEAT_FP16) are not matched.
//
// A 64-bit source also accepts a W-form chain (the W write zeroed
// X[63:32], pinning the full read); a W source requires a W chain.
// Folding a conversion additionally requires the conversion be exact
// -- SCVTF/UCVTF round per the dynamic FPCR mode, and exactness makes
// the result mode-independent and exception-free. Encodability already
// implies it (an imm8 magnitude is at most 31.5), but a round-trip
// check enforces it explicitly.
//
// The consumer writes only an FP register and never kills the
// constant GPR, so the finding always defers through the forward
// register-liveness scan (defer_dead_mov) until mov_rd is provably
// dead. Runs before check_movz_movk_bitmask so the chain state is
// still active.
bool check_mov_fmov_imm_fold(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out);

// Detect an FP or vector register being zeroed through a
// general-purpose register, where MOVI #0 produces the identical
// all-zeros state on the FP side without the cross-register-file
// transfer:
//   fmov s0, wzr      -> movi d0, #0     (one-for-one, lower latency)
//   scvtf d0, wzr     -> movi d0, #0     (integer zero -> +0.0 in
//                                         every rounding mode)
//   dup v0.4s, wzr    -> movi v0.4s, #0
//   mov w8, #0 ; fmov s0, w8 -> movi d0, #0 (also deletes the MOV)
// Consumers: FMOV (general, GPR->FPR), SCVTF/UCVTF (scalar, from
// GPR) and DUP (general), from ZR directly or from a MOV-chain
// register pinned to zero (width admission as in the FMOV immediate
// fold). All three write semantics zero the vector register above
// the written portion, exactly as the suggested MOVI does, so the
// final state is bit-identical. Scalar consumers render the
// canonical 64-bit zeroing (movi dN, #0); DUP keeps its arrangement.
//
// The ZR forms delete no write and emit immediately. The chain form
// deletes the MOV #0 (this consumer is intentionally not in the
// MOV #0 -> ZR check's set -- WZR substitution would keep the
// transfer) and defers through the forward register-liveness scan
// until the constant register provably dies. Non-zero DUP broadcasts
// that MOVI's expanded immediate could encode are out of scope. Runs
// before check_movz_movk_bitmask so the chain state is still active.
bool check_fp_zero_to_movi(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out);

// Detect a widening extend -- SXTW Xd, Wn, or the zero-extending
// MOV Wd, Wm -- immediately followed by a 64-bit-source SCVTF/UCVTF
// of the extended register. The W-source conversion form performs the
// extension itself, so the pair folds to it and the extend dies:
//   sxtw x8, w0 ; scvtf d0, x8 -> scvtf d0, w0
//   mov w8, w0  ; ucvtf d0, x8 -> ucvtf d0, w0
//   mov w8, w0  ; scvtf d0, x8 -> ucvtf d0, w0   (the zero-extended
//     64-bit value IS the unsigned 32-bit value, so even the signed
//     wide conversion becomes the unsigned narrow one)
// A sign-extended source does NOT fold into UCVTF: the unsigned
// reading of sext(negative) is a huge value, not the 32-bit one.
// Both sides convert the same mathematical value, so the identity is
// exact in every FPCR rounding mode -- no exactness argument needed.
// ZR operands are excluded as degenerate (a constant-zero extend).
//
// The rewrite reads the extend's own source, which the adjacent pair
// leaves unchanged (even in-place: SXTW and MOV Wd, Wm keep the low
// 32 bits of their destination equal to the source). Deleting the
// extend requires its destination dead: the conversion writes only an
// FP register and never kills it, so the finding always defers
// through the forward register-liveness scan (defer_dead_mov).
bool check_extend_cvtf_fold(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out);

// Detect a MOV chain that materialises the constant 0, immediately
// followed by an instruction that reads that register. The read can
// be replaced by XZR/WZR (the architectural zero register), making
// the MOV dead. Five consumer families are covered:
//   - STR (B/H/W/X, unsigned-offset) with Rt == mov_rd
//       -> str <wzr/xzr>, [...]
//   - ADD/SUB/ADDS/SUBS (shifted-register, LSL #0) with Rn or Rm ==
//     mov_rd  -> the same op with that operand replaced by ZR. CMP /
//     CMN aliases (S-variant + Rd == ZR) are rendered as the alias.
//   - AND/ORR/EOR/ANDS (shifted-register, LSL #0, N == 0) with Rn or
//     Rm == mov_rd -> the same op with that operand replaced by ZR.
//     TST alias (ANDS + Rd == ZR) is rendered as the alias.
//   - CSEL/CSINC/CSINV/CSNEG with Rn or Rm == mov_rd -> the same
//     select with that slot as ZR (legal in either slot for all
//     four). Both slots zero is left to check_csel_self, whose
//     same-operand identity is the strictly better rewrite.
//   - Register-form CCMP/CCMN with Rn == mov_rd -> the compare with
//     ZR as the left operand. Only Rn: an Rm-slot zero already folds
//     to the #0 immediate form via check_mov_ccmp_imm_fold, which
//     deletes the register read outright.
//
// The consumer's instruction count does not change; the savings come
// from the now-dead MOV (assuming Xd is not read elsewhere). The
// rewrite suggestion shows the literal "use ZR" form; further
// simplification (e.g. ADD Rd, Rn, XZR -> MOV Rd, Rn, or
// SUB Rd, XZR, Rm -> NEG Rd, Rm) is left to the reader.
//
// Only the STR Rt data slot is rewritten to ZR, never the base Rn:
// Rn = 31 in addressing means SP (not ZR), and Rn = mov_rd would leave
// the store reading the zeroed register as an address, so the MOV is
// not dead and must not be dropped -- both base cases are excluded.
// For arithmetic/logical shifted-register forms, Rn = Rm = 31 both
// denote ZR, so either operand is foldable.
bool check_mov_zero_to_xzr(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out);

// Detect a MOV chain materialising a constant C, immediately followed
// by an integer register-offset load or store whose index register Rm
// is the constant. The access folds to the immediate-offset form,
// making the MOV dead:
//   mov x8, #256 ; ldr x0, [x1, x8]         -> ldr x0, [x1, #256]
//   mov x8, #4   ; ldr x0, [x1, x8, lsl #3] -> ldr x0, [x1, #32]
//   mov x8, #-8  ; ldr x0, [x1, x8]         -> ldur x0, [x1, #-8]
// The effective byte offset is C shifted by the S bit's log2(access
// size); the rewrite is the scaled unsigned-offset form when that
// offset is non-negative, size-aligned, and within 12 bits, else the
// unscaled LDUR/STUR form when within [-256, 255]. All integer sizes
// fold, both the zero- and sign-extending loads (classify_int_load's
// set; PRFM excluded) and the STRB/STRH/STR stores. SIMD&FP accesses
// are not matched.
//
// Only the LSL/UXTX index option (011) is matched: the index is the
// full X register, whose value the chain pins exactly -- a W-form
// chain also qualifies because its W write zeroed X[63:32]. The
// UXTW/SXTW/SXTX extend options re-interpret the index and are
// excluded. The base Rn must not be the constant register (the
// rewrite would still read it), nor may a store's data register be
// (same reason); Rn = 31 means SP in both the register-offset and
// immediate forms, so SP bases fold soundly.
//
// The saving is the deleted MOV, so like the MOV #0 fold the finding
// is deferred via defer_dead_mov until the constant register is
// provably dead -- except when the consumer is a load whose Rt IS the
// constant register, which overwrites it at the consumer itself and
// emits immediately.
bool check_mov_reg_offset_fold(armlint_state *state, const cs_insn *insn,
                               size_t offset, armlint_finding *out);

// Detect MUL Rt, Ra, Rb immediately followed by an ADD/SUB
// (shifted-register, LSL #0, non-S-variant) that consumes Rt. The
// pair folds to a single MADD/MSUB:
//   mul xt, xa, xb ; add xd, xt, xc -> madd xd, xa, xb, xc
//   mul xt, xa, xb ; add xd, xc, xt -> madd xd, xa, xb, xc  (ADD
//                                                            commutes)
//   mul xt, xa, xb ; sub xd, xc, xt -> msub xd, xa, xb, xc
// The form `sub xd, xt, xc` is NOT foldable: MSUB computes
// Ra - Rn*Rm, not Rn*Rm - Ra. S-variants (ADDS/SUBS) are skipped
// because MADD/MSUB have no flag-setting form.
//
// Soundness: the rewrite deletes the MUL, so the product register
// must be dead afterward. An ADD/SUB that overwrites it (Rd == Rt,
// the textbook array-indexing pattern) proves that on the spot and
// reports immediately; one writing a fresh register defers through
// the forward register-liveness scan (Rd = 31 is a dead write and
// excluded). The "accumulator" operand (the one that is not Rt) must
// NOT equal Rt -- otherwise the ADD/SUB reads the MUL's result twice
// while the MADD rewrite reads pre-MUL values, diverging -- and an
// ADD whose accumulator is XZR is a multiply + register copy, not an
// accumulate (a ZR-accumulator MADD just respells the MUL); both are
// rejected. Widths must match: both W or both X. MUL writing to ZR
// is excluded (the pending slot is not opened for MUL Xd=XZR since
// the result is discarded). The degenerate SUB case
// `sub xd, xzr, xt` (i.e. NEG xd, xt) folds to the MSUB-with-ZR
// alias MNEG and is reported as such ("MUL + NEG foldable to MNEG").
bool check_mul_add_sub_fold(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out);

// Widening-multiply analogue of check_mul_add_sub_fold. Detect
// SMULL/UMULL Xt, Wa, Wb (the Ra == XZR aliases of SMADDL/UMADDL)
// immediately followed by an X-form ADD/SUB (shifted-register, LSL #0,
// non-S-variant) that consumes Xt. The pair folds to a single
// long multiply-accumulate:
//   smull xt, wa, wb ; add xt, xt, xc -> smaddl xt, wa, wb, xc
//   smull xt, wa, wb ; add xt, xc, xt -> smaddl xt, wa, wb, xc  (ADD
//                                                            commutes)
//   smull xt, wa, wb ; sub xt, xc, xt -> smsubl xt, wa, wb, xc
// and the UMULL forms fold to UMADDL/UMSUBL. The form `sub xt, xt, xc`
// is NOT foldable (SMSUBL computes Xa - Wn*Wm, not Wn*Wm - Xa).
//
// The 32x32->64 product is always 64-bit, so the consumer MUST be
// X-form; a W-form ADD/SUB would operate on only the low half and is
// rejected. Signedness must match the producer (SMULL -> SMADDL/SMSUBL,
// UMULL -> UMADDL/UMSUBL). The multiply operands stay W-form in the
// rewrite while the destination and accumulator are X-form.
//
// Soundness: identical to check_mul_add_sub_fold -- an ADD/SUB that
// overwrites Xt reports immediately, one writing a fresh register
// defers through the forward register-liveness scan (Rd = 31
// excluded), the accumulator operand must not equal Xt, and an
// XZR-accumulator ADD (a multiply + register copy) is rejected.
// S-variants (ADDS/SUBS) are skipped because the long MAC has no
// flag-setting form. SMULL/UMULL writing to ZR is excluded (result
// discarded). The degenerate SUB case `sub xd, xzr, xt` (NEG) folds
// to the long MSUB-with-ZR alias SMNEGL / UMNEGL and is reported as
// such.
bool check_widening_mul_add_sub_fold(armlint_state *state,
                                     const cs_insn *insn,
                                     size_t offset, armlint_finding *out);

// Detect NEG Rt, Rs (the SUB Rt, XZR, Rs alias, no shift, non-S)
// immediately followed by an ADD/SUB (shifted-register, LSL #0,
// non-S-variant) or a CSEL that consumes Rt. The pair folds to a
// single instruction by absorbing the negation into the consumer:
//   neg xt, xs ; add xd, xt, xc -> sub xd, xc, xs  (ADD commutative)
//   neg xt, xs ; add xd, xc, xt -> sub xd, xc, xs
//   neg xt, xs ; sub xd, xc, xt -> add xd, xc, xs
//   neg xt, xs ; csel xd, xn, xt, cc -> csneg xd, xn, xs, cc
//   neg xt, xs ; csel xd, xt, xm, cc -> csneg xd, xm, xs, !cc
// The form `sub xd, xt, xc` is NOT foldable: there is no single
// AArch64 instruction computing `-xs - xc`. S-variants (ADDS/SUBS)
// are skipped because the fold changes the flag-set definition
// (V/C in particular). NEGS is similarly excluded as a producer.
//
// The CSEL consumer (op2 = 00 only; CSINC/CSINV/CSNEG have different
// else-branches) folds because CSNEG's else-branch is a negation:
// Rd = cond ? Rn : -Rm. A NEG consumed in the else slot keeps the
// condition; one in the then slot swaps the operands and inverts it.
// The rewrite reads the same NZCV the CSEL did (a NEG writes no
// flags). AL/NV conditions are excluded -- ConditionHolds treats
// both as always-true, so the select is a plain MOV and the inverted
// spelling would still be taken -- as is a CSEL reading Rt in both
// slots (the same-operand identity, check_csel_self's shape).
// Reported as "NEG + CSEL foldable to CSNEG".
//
// Soundness: the rewrite deletes the NEG, so its destination must be
// dead afterward. A consumer that overwrites it proves that on the
// spot and reports immediately; one writing a fresh register defers
// through the forward register-liveness scan (Rd = 31 -- a dead
// write, or a discarded select -- is excluded). The ADD/SUB
// "accumulator" operand (the one that is not Rt) must NOT equal Rt
// -- otherwise both ADD/SUB sources are -xs, computing -2*xs or 0
// instead of the additive identity the fold assumes -- nor XZR,
// whose shapes are double negations (a copy of the negation, or the
// negation of it), not accumulates; a CSEL's surviving operand may
// be XZR (csneg xd, xzr, xs, cc has no shorter form). Widths must
// match: both W or both X. NEG writing to ZR is excluded (the
// result is discarded), as is NEG of ZR (which computes 0 -- a
// different idiom, not strength reduction).
bool check_neg_add_sub_fold(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out);

// Logical-op analogue of check_neg_add_sub_fold. Detect MVN Rt, Rs (the
// ORN Rt, XZR, Rs alias, no shift) immediately followed by an
// AND/ORR/EOR/ANDS (shifted-register, LSL #0, N=0) that consumes Rt.
// The pair folds the bitwise-NOT into the consumer's built-in
// negated-operand form:
//   mvn wt, ws ; and  wd, wn, wt -> bic  wd, wn, ws
//   mvn wt, ws ; orr  wd, wn, wt -> orn  wd, wn, ws
//   mvn wt, ws ; eor  wd, wn, wt -> eon  wd, wn, ws
//   mvn wt, ws ; ands wd, wn, wt -> bics wd, wn, ws
// All four consumers commute, so Rt may sit in either source slot; the
// fold puts the other ("independent") operand in Rn and Rs in the
// negated Rm slot.
//
// Soundness (mirrors check_neg_add_sub_fold): the rewrite deletes the
// MVN, so its destination must be dead afterward -- a consumer that
// overwrites it reports immediately, one writing a fresh register
// defers through the forward register-liveness scan. Rd = 31
// consumers are excluded (a dead write, or the TST alias for ANDS).
// The independent operand must not also be Rt (the both-equal case
// is a self-op, handled by check_self_op) nor XZR ("orr rd, xzr, t"
// is the MOV alias, whose fold is MVN itself; the AND/EOR forms are
// constants). The shifted MVN form is not handled -- the consumer
// would shift the complemented value, not Rs. MVN writing ZR, and
// MVN of ZR (the all-ones constant), are excluded.
//
// A CSEL consumer folds to CSINV, whose else-branch is a complement
// (Rd = cond ? Rn : ~Rm) -- the exact mirror of the NEG + CSEL ->
// CSNEG fold in check_neg_add_sub_fold:
//   mvn wt, ws ; csel wd, wn, wt, cc -> csinv wd, wn, ws, cc
//   mvn wt, ws ; csel wd, wt, wm, cc -> csinv wd, wm, ws, !cc
// (then slot: operands swap, condition inverts). AL/NV, Rd = 31,
// both-slots (check_csel_self's shape) and width mismatches are
// excluded. Reported as "MVN + CSEL foldable to CSINV".
bool check_mvn_logic_fold(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out);

// Detect ADD Rt, Rs, #1 (immediate, no shift, non-S) immediately
// followed by a CSEL reading Rt: CSINC's else-branch is an increment
// (Rd = cond ? Rn : Rm + 1), so the pair folds -- the exact mirror
// of the NEG -> CSNEG and MVN -> CSINV consumers:
//   add wt, ws, #1 ; csel wd, wn, wt, cc -> csinc wd, wn, ws, cc
//   add wt, ws, #1 ; csel wd, wt, wm, cc -> csinc wd, wm, ws, !cc
// (then slot: operands swap, condition inverts). The rewrite reads
// the same NZCV the CSEL did and reads Rs, which still holds its
// original value at the consumer once the ADD is deleted, even
// in-place. AL/NV, Rd = 31 (discarded select), both-slots
// (check_csel_self's shape) and width mismatches are excluded.
// Register 31 in ADD-immediate means SP for both Rd and Rn, while
// CSINC's slots are ZR-flavoured, so SP source/destination never
// open. A destination overwriting Rt reports immediately; a fresh
// destination defers through the forward register-liveness scan.
// Reported as "ADD #1 + CSEL foldable to CSINC".
bool check_add_one_csel_fold(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out);

// Extend-analogue of the shift fold. Detect a standalone extend
// (UXTB/UXTH (W-form), SXTB/SXTH (W or X), SXTW (X)) immediately
// followed by an ADD/SUB (shifted-register, LSL #0) that consumes its
// destination. The pair folds into the consumer's extended-register
// form, where the extend rides on the consumer's Rm:
//   sxtw x0, w1 ; add x0, x3, x0 -> add x0, x3, w1, sxtw
//   uxtb w0, w1 ; sub w0, w3, w0 -> sub w0, w3, w1, uxtb
// ADD/ADDS commute, so the extend result may be in Rn or Rm; SUB/SUBS
// need it in Rm. The extended operand is always rendered as a W
// register (these extends source 32 bits or fewer).
//
// Soundness (mirrors the shift fold): the rewrite deletes the extend,
// so its destination must be dead afterward -- a consumer that
// overwrites it reports immediately, one writing a fresh register
// defers through the forward register-liveness scan. The other source
// operand must not also be the extend's Rd -- nor register 31, which
// the shifted-register consumer read as ZR but the extended-register
// rewrite would read as SP. Rd = 31 consumers are excluded for the
// same reason, and more sharply: the shifted-register consumer's
// Rd = 31 is a discarded ZR write, but the extended-register
// rewrite's Rd = 31 is SP -- the fold would turn dead code into a
// stack-pointer update. The producer form (W vs X) must match the
// consumer's, with one relaxation: a W-form zero-extend (UXTB/UXTH)
// also folds into an X-form consumer, because the W write zeroed bits
// 63..32 and that is exactly what the X-form extended-register
// UXTB/UXTH option computes. The W-form sign-extends do not get the
// relaxation (they too zero the high half, where the X-form SXT
// option would replicate the sign). Extend of/into ZR is excluded.
// The standalone 32->64 zero-extend (UXTW, normally a W MOV) is not
// matched as a producer.
bool check_extend_add_sub_fold(armlint_state *state, const cs_insn *insn,
                               size_t offset, armlint_finding *out);

// Detect an X-form ADD (shifted-register, LSL #s, non-S-variant)
// immediately followed by an unsigned-offset LDR or STR with
// imm12 = 0 whose base register equals Rd of the ADD. The pair folds
// to a single register-offset access:
//   add xt, xn, xm           ; ldr xt, [xt]   -> ldr xt, [xn, xm]
//   add xt, xn, xm, lsl #s   ; ldr xt, [xt]   -> ldr xt, [xn, xm, lsl #s]
//   add xt, xn, xm           ; str x0, [xt]   -> str x0, [xn, xm]
// The load's destination width may be W or X (same register number
// as Xt): writing Wt zeros bits 63..32 of Xt, overwriting the
// address regardless of size.
//
// The sign-extending loads (LDRSB/LDRSH, Wt or Xt; LDRSW) fold
// identically -- they too overwrite the full X register named by Rt
// and have register-offset forms -- as do the STRB/STRH/STR stores.
// PRFM, which shares the encoding family but whose Rt is a prefetch
// operation, is excluded: the address register can never be proven
// dead through it structurally, and prefetch-driving code keeps it
// live.
//
// Shift constraint: the register-offset forms accept only LSL #0 or
// LSL #log2(access_size). access_size in bytes: 1 for B, 2 for H,
// 4 for W/LDRSW, 8 for X.
//
// Soundness: the rewrite deletes the ADD, so its Rd must be dead
// afterward. A load whose Rt equals the ADD's Rd proves that
// structurally (the write to Wt/Xt destroys the address value) and
// reports immediately. Every other consumer -- a store, or a load
// into a different register -- defers through the forward
// register-liveness scan and reports only once a later instruction
// overwrites the address register before any read or control
// transfer. A store whose data register is the ADD's Rd never folds:
// the rewritten store would read the deleted sum. Store findings are
// reported under the separate name "ADD + STR foldable to
// register-offset STR".
//
// The ADD's Rn = 31 case is excluded because Rn = 31 in
// shifted-register ADD means XZR, but Rn = 31 in the register-offset
// addressing form means SP -- the semantic mismatch would make
// the rewrite incorrect. Rm = 31 (XZR) in the ADD makes the ADD a
// MOV-and-rename, an unusual pattern excluded for cleanliness.
bool check_add_ldr_register_offset(armlint_state *state,
                                   const cs_insn *insn,
                                   size_t offset, armlint_finding *out);

// Detect SXTW Xt, Ws immediately followed by a register-offset LDR
// or STR whose index register equals Xt. The pair folds the
// sign-extension into the access's addressing mode:
//   sxtw xt, ws ; ldr xt, [xn, xt]          -> ldr xt, [xn, ws, sxtw]
//   sxtw xt, ws ; ldr xt, [xn, xt, lsl #s]  -> ldr xt, [xn, ws, sxtw #s]
//   sxtw xt, ws ; str x0, [xn, xt]          -> str x0, [xn, ws, sxtw]
// This is the array-indexing idiom (a 32-bit signed index into a 64-bit
// base). All four zero-extending sizes (LDRB/LDRH/LDR W/LDR X), the
// sign-extending loads (LDRSB/LDRSH, Wt or Xt; LDRSW), and the
// STRB/STRH/STR stores are handled; the scale bit carries over
// unchanged.
//
// Soundness (mirrors check_add_ldr_register_offset): the consumer
// must use the LSL/UXTX index option (a full 64-bit register offset,
// equivalent to the SXTW's result) with Rm == Xt. The rewrite
// deletes the SXTW, so Xt must be dead afterward: a load whose
// Rt == Xt proves that structurally and reports immediately; a
// store, or a load into a different register, defers through the
// forward register-liveness scan and reports only once Xt is
// provably overwritten before any read or control transfer. A store
// whose data register is Xt never folds (the rewritten store would
// read the deleted extend), and PRFM is excluded (its Rt is a
// prefetch operation, not a destination). The base Rn must NOT be
// Xt: with the SXTW folded away the base would read its pre-SXTW
// value, changing the address. SXTW into ZR is excluded. Only SXTW
// is matched (the load index extend is word-width; a standalone
// 32->64 zero-extend is normally a W-register MOV, not a literal
// UXTW). Store findings are reported under the separate name "SXTW +
// register-offset STR foldable into the store".
bool check_sxtw_ldr_fold(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out);

// Detect an unsigned-offset load immediately followed by an in-place
// sign-extend (SXTB/SXTH/SXTW) of the loaded register; the pair folds
// to the matching sign-extending load. Two producer families:
//
// Zero-extending loads (LDRB/LDRH/LDR Wt), where the consumer's sign
// threshold must EQUAL the load's access width (W- or X-form
// consumer):
//   ldrb wt, [xn]     ; sxtb wt, wt -> ldrsb wt, [xn]
//   ldrb wt, [xn]     ; sxtb xt, wt -> ldrsb xt, [xn]
//   ldrh wt, [xn, #2] ; sxth wt, wt -> ldrsh wt, [xn, #2]
//   ldr  wt, [xn, #4] ; sxtw xt, wt -> ldrsw xt, [xn, #4]
//
// W-form sign-extending loads (LDRSB/LDRSH Wt), re-widened to 64 bits
// by an X-form consumer whose threshold is AT OR ABOVE the access
// width -- every bit from the width up is a copy of the loaded sign,
// so SXTB, SXTH and SXTW all reproduce exactly the X-form load:
//   ldrsb wt, [xn]     ; sxtb xt, wt -> ldrsb xt, [xn]
//   ldrsb wt, [xn]     ; sxtw xt, wt -> ldrsb xt, [xn]
//   ldrsh wt, [xn, #2] ; sxth xt, wt -> ldrsh xt, [xn, #2]
//
// Soundness (structural): the consumer reads and overwrites the
// load's Rt, so the intermediate is dead, and the rewrite performs
// the identical memory access (same address, same size) with the
// extension moved into the load. A threshold below the access width
// is NOT folded for either family -- the LDRS rewrite would shrink
// the memory access (not architecturally identical), and below-width
// bits of a wider load are data, not its sign. A threshold above the
// width of a ZERO-extending load sign-extends from a bit the load
// provably zeroed (a no-op, but not this rewrite); the W-form
// consumer after a SIGN-extending load is likewise a no-op -- both
// belong to the redundant-extension checks, as do all re-extensions
// of the X-form sign-extending loads (already extended through bit
// 63). Rt = 31 (load discarded) is excluded. v1 matches the
// unsigned-offset addressing form only, like the other load-rewriting
// folds; the unscaled, pre-/post-indexed and register-offset forms
// have LDRS equivalents and could fold the same way.
bool check_ldr_sext_fold(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out);

// Detect an X-form ADD-immediate (non-S-variant) immediately followed
// by an unsigned-offset LDR or STR whose base register equals Rd of
// the ADD. The pair folds to a single immediate-offset access,
// summing the two displacements:
//   add xt, xn, #a  ; ldr xt, [xt]      -> ldr xt, [xn, #a]
//   add xt, sp, #a  ; ldr xt, [xt]      -> ldr xt, [sp, #a]
//   add xt, xn, #a  ; ldr xt, [xt, #b]  -> ldr xt, [xn, #(a+b)]
//   add xt, sp, #a  ; str x0, [xt]      -> str x0, [sp, #a]
// The load's destination width may be W or X (same register number as
// Xt): writing Wt zeros bits 63..32 of Xt, overwriting the address
// regardless of size. LDRB/LDRH, the sign-extending
// LDRSB/LDRSH/LDRSW, and the STRB/STRH/STR store consumers fold the
// same way (PRFM is excluded: its Rt is a prefetch operation, not a
// destination).
//
// Encoding constraint: the combined byte offset must be a multiple of
// the access size and its scaled value must fit in 12 bits. The
// access's own imm12 is already a multiple of access_size, so
// alignment is determined solely by the ADD's byte immediate. The
// ADD's sh=1 form (imm12 << 12) is supported.
//
// Soundness: the rewrite deletes the ADD, so its Rd must be dead
// afterward. A load whose Rt equals the ADD's Rd proves that
// structurally (the write to Wt/Xt destroys the address value) and
// reports immediately. Every other consumer -- a store, or a load
// into a different register -- defers through the forward
// register-liveness scan and reports only once a later instruction
// overwrites the address register before any read or control
// transfer. A store whose data register is the ADD's Rd never folds:
// the rewritten store would read the deleted sum. Store findings are
// reported under the separate name "ADD + STR foldable to
// immediate-offset STR".
//
// Rn = 31 in the ADD-immediate form means SP (not XZR), and Rn = 31
// in the LDR unsigned-offset form also means SP -- so this is the
// canonical stack-relative load pattern (`add xt, sp, #imm; ldr xt,
// [xt]`) and is intentionally flagged. That includes imm = 0, the
// MOV-from-SP alias: `mov xt, sp; ldr xt, [xt]` -> `ldr xt, [sp]`.
// Rd = 31 in ADD-immediate also means SP; folding would write a
// discarded LDR (Rt=XZR), losing the SP update, so Rd = 31 is
// excluded. imm = 0 with a GPR source is the redundant ADD that
// check_add_sub_zero owns and is excluded here.
bool check_add_ldr_imm_offset(armlint_state *state,
                              const cs_insn *insn,
                              size_t offset, armlint_finding *out);

// Detect a zero-offset load/store -- an unsigned-offset LDR/STR or a
// signed-offset LDP/STP/LDPSW pair -- immediately followed by an
// X-form ADD-immediate that self-updates the base register. The two
// fold into a single post-indexed form with the ADD's byte immediate
// moved into the post-index slot:
//   ldr xt, [xn]        ; add xn, xn, #imm -> ldr xt, [xn], #imm
//   str xt, [xn]        ; add xn, xn, #imm -> str xt, [xn], #imm
//   ldr xt, [sp]        ; add sp, sp, #imm -> ldr xt, [sp], #imm
//   ldr xt, [xn]        ; sub xn, xn, #imm -> ldr xt, [xn], #-imm
//   ldp xt, xu, [sp]    ; add sp, sp, #imm -> ldp xt, xu, [sp], #imm
//     (the canonical frame epilogue)
// All four integer access sizes (B/H/W/X) and every SIMD&FP size
// (B/H/S/D/Q) are supported for singles; pairs cover W/X, LDPSW, and
// the SIMD&FP S/D/Q forms. An FP Rt never aliases the integer base,
// so the Rt == Rn writeback restriction is integer-only.
//
// Encoding constraint: single post-index uses a 9-bit signed byte
// immediate (-256..255): an ADD-imm self-update with imm in 1..255
// folds to a positive writeback, a SUB-imm self-update with imm in
// 1..256 to a negative one (-256 is the signed-9-bit minimum). Pair
// post-index uses a scaled signed 7-bit immediate: the ADD/SUB amount
// must be a multiple of the per-register transfer size (4/8/16) with
// quotient 1..63 for ADD or 1..64 for SUB. The sh=1 ADD form
// (imm >= 4096) is out of every slot's range and rejected.
//
// Soundness: ADD's Rd and Rn must both equal the access's Rn so that
// the base receives a self-update (the only form expressible as
// post-index). Rt == Rn writeback is UNPREDICTABLE for loads and
// CONSTRAINED UNPREDICTABLE for stores -- for pairs that applies to
// either data register -- so those are rejected, except when
// Rn == 31: 31 means SP for the base and XZR for a data register, so
// the two encode distinct registers and no conflict arises. A load
// pair with Rt == Rt2 is CONSTRAINED UNPREDICTABLE even without
// writeback and is never opened; a store pair with a repeated source
// (stp xzr, xzr) is well-defined and folds. LDR with Rt = 31 (load
// to XZR) is allowed for symmetry with STR of XZR. The access's
// offset must be 0; a non-zero offset combined with a post-index
// update has no single-instruction rewrite (that pattern matches
// pre-index, not post-index).
bool check_ldr_str_add_post_indexed(armlint_state *state,
                                    const cs_insn *insn,
                                    size_t offset, armlint_finding *out);

// Detect an X-form ADD-immediate self-update (Rd == Rn) immediately
// followed by a zero-offset LDR/STR or LDP/STP/LDPSW whose base
// register equals the ADD's Rd. The two fold into a single
// pre-indexed form with the ADD's byte immediate moved into the
// pre-index slot:
//   add xn, xn, #imm  ; ldr xt, [xn]      -> ldr xt, [xn, #imm]!
//   add xn, xn, #imm  ; str xt, [xn]      -> str xt, [xn, #imm]!
//   add sp, sp, #imm  ; ldr xt, [sp]      -> ldr xt, [sp, #imm]!
//   sub xn, xn, #imm  ; ldr xt, [xn]      -> ldr xt, [xn, #-imm]!
//   sub sp, sp, #imm  ; stp xt, xu, [sp]  -> stp xt, xu, [sp, #-imm]!
//     (the canonical frame prologue)
// All four integer access sizes (B/H/W/X) and every SIMD&FP size
// (B/H/S/D/Q) are supported for singles; pairs cover W/X, LDPSW, and
// the SIMD&FP S/D/Q forms. An FP Rt never aliases the integer base,
// so the Rt == Rn writeback restriction is integer-only.
//
// Encoding constraint: same slots as post-index -- 9-bit signed bytes
// for singles (ADD imm in 1..255 / SUB imm in 1..256), scaled signed
// 7-bit for pairs (a multiple of the 4/8/16-byte transfer size with
// quotient 1..63 for ADD / 1..64 for SUB). The pending ADD/SUB is
// admitted up to the largest pair writeback (1008/1024) and the
// consumer's actual range is re-checked at close.
//
// Soundness: overlaps check_add_ldr_imm_offset, which catches the
// same ADD + access shape and folds to the unsigned-offset form with
// no writeback. When Rt == Rd, only that check fires -- pre-index is
// rejected here because Rt == Rn writeback is UNPREDICTABLE
// (CONSTRAINED for stores); for pairs that applies to either data
// register, and a load pair with Rt == Rt2 (CONSTRAINED
// UNPREDICTABLE on its own) is never folded. When Rt != Rd both can
// fire: pre-index reports immediately, and the immediate-offset fold
// additionally reports once the forward scan proves the updated base
// dead -- there the writeback is pointless and its no-writeback
// rewrite is strictly better, so the two findings offer alternative
// outcomes, like the CMP-drop/CBZ-fold overlap. The Rn == 31 case is
// allowed: Rn means SP and Rt means XZR, so the two encode distinct
// registers. The access's offset must be 0; a non-zero offset
// combined with a base bump has no pre-index expression that
// preserves both the access address and the final base value. Same
// code-size/decode-slot win as post-index; no backend throughput
// change on most OoO cores.
bool check_add_ldr_str_pre_indexed(armlint_state *state,
                                   const cs_insn *insn,
                                   size_t offset, armlint_finding *out);

// Detect two adjacent unsigned-offset LDR/STR (both W or both X, or
// both the same SIMD&FP size S/D/Q -- the FP B and H sizes have no
// pair form -- same direction, same base, consecutive offsets)
// foldable into a single LDP/STP; also two adjacent unsigned-offset
// LDRSW pairs foldable into a single LDPSW (always Xt destinations,
// 4-byte transfer, load-only). The integer base-clobber guard (first
// load's Rt != Rn) does not apply to SIMD&FP pairs: an FP Rt can
// never alias the integer base. v1 supports only the unsigned-offset
// form,
// which guarantees natural alignment by construction (imm12 is
// scaled); LDUR / pre- and post-indexed forms are deferred to avoid
// the implementation-defined behaviour around unaligned LDP/STP.
// A pending LDR/STR will not pair with an LDRSW (different opcode).
//
// A repeated register pairs only for STORES: STP Rt, Rt simply
// stores the value twice (str x5, [sp] ; str x5, [sp, #8] ->
// stp x5, x5, [sp]), while LDP/LDPSW with Rt1 == Rt2 is CONSTRAINED
// UNPREDICTABLE and never folds. The W-form zero-register store pair
// keeps its narrower rewrite (STR XZR covers the same eight bytes);
// the X-form pair folds to STP XZR, XZR like any repeated source.
bool check_ldp_stp_coalesce(armlint_state *state, const cs_insn *insn,
                            size_t offset, armlint_finding *out);

// STP WZR, WZR (W-form, signed offset, no writeback) zeroes the same
// eight bytes as a single STR XZR. Report the wider single store. Only
// the 32-bit pair collapses; the 64-bit STP XZR, XZR is already the
// canonical 16-byte zero store. Writeback and STNP forms are excluded.
bool check_stp_wzr_to_str_xzr(armlint_state *state, const cs_insn *insn,
                              size_t offset, armlint_finding *out);

// A zeroing MOVI (all-zero vector) feeding an adjacent SIMD compare in
// register form folds into the compare-with-#0 form, dropping the MOVI.
// Matched compares are the signed integer CMEQ/CMGE/CMGT and the FP
// FCMEQ/FCMGE/FCMGT; the compare must overwrite the zero register
// (Vd == the MOVI's destination), which proves the zero is dead. A zero
// left operand flips the ordered sense (0 >= X => X <= 0, etc.).
bool check_simd_cmp_zero(armlint_state *state, const cs_insn *insn,
                         size_t offset, armlint_finding *out);

// Advance any deferred CMP+B.cond / TST+B.cond finding's flag-liveness
// scan by one instruction. Returns true and fills *out when a stopper
// makes prior NZCV state unobservable (or false on a flag read / unsafe
// terminator / window expiry, suppressing the pending finding). Call
// once per instruction BEFORE running the per-instruction checks; if
// it were called after, a check setting a new pending in its step (1)
// would be immediately advanced against the same instruction and
// likely suppressed. The offset parameter exists for compatibility
// with the shared armlint_check_fn signature; it is unused.
bool armlint_advance_pending(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out);

// Detect an S-variant ALU (ADDS/SUBS/ANDS/BICS/ADCS/SBCS) writing Rd,
// followed immediately by a CMP/CMN/TST zero test of Rd (any of the
// decode_zero_test spellings), followed immediately by B.EQ/B.NE. All
// S-variants set Z = (Rd == 0), so the zero test is recomputing the
// same Z bit. The zero test is flagged redundant once the same
// downstream NZCV-liveness scan as check_cmp_zero_branch confirms
// dropping it is sound (no N/C/V observation downstream).
// Combines with the existing CMP+B.cond -> CBZ check: both fire for
// the matching pattern, presenting alternative rewrites.
bool check_redundant_cmp_after_s_variant(armlint_state *state,
                                         const cs_insn *insn,
                                         size_t offset,
                                         armlint_finding *out);

// Mirror of check_redundant_cmp_after_s_variant one S bit over: a
// NON-flag-setting ALU whose S-variant twin exists -- ADD/SUB
// (immediate, shifted-register, extended-register) or AND/BIC --
// writing Rd, followed immediately by a CMP/CMN/TST zero test of Rd,
// followed immediately by B.EQ/B.NE. Converting the ALU to its
// S-variant makes the zero test droppable:
//   add w0, w1, w2 ; cmp w0, #0 ; b.eq L -> adds w0, w1, w2 ; b.eq L
// Z is bit-identical (Rd == 0 either way) and so is N (the sign of
// Rd under every zero-test spelling), but C and V differ: CMP pins
// C = 1, V = 0 and CMN/TST pin C = 0, V = 0, while the arithmetic
// S-variants compute the operation's real carry and overflow. The
// B.EQ/B.NE itself reads only Z; emission defers through a dedicated
// NZCV-liveness scan slot (armlint_advance_pending_zs) until any
// later N/C/V read is ruled out -- conservative for N, which
// actually agrees. (The logical S-forms pin C = V = 0, so ANDS/BICS
// after TST is flag-exact; the scan is a uniform superset.)
//
// The S-variant spelling is the producer's mnemonic plus "s" for
// every member, including the NEG alias (SUB from ZR), whose twin is
// NEGS. Rd = 31 producers are excluded (SP for the immediate and
// extended forms, a dead ZR write for the shifted ones), as is
// ADD/SUB immediate with imm == 0 (check_add_sub_zero's shape, whose
// MOV-from-SP alias must not gain an "s"). ADC/SBC are left out of
// v1. Combines with the CMP+B.cond -> CBZ check: both fire,
// presenting alternative rewrites. Reported as "ADD/SUB/AND/BIC +
// zero-CMP foldable to S-variant"; the shape is common in
// hand-written assembly and naive codegen, which compute a value and
// then test it in two steps.
bool check_zero_cmp_to_s_variant(armlint_state *state,
                                 const cs_insn *insn,
                                 size_t offset,
                                 armlint_finding *out);

// Detect a non-S ADD/SUB and its compare twin of the same two
// operands adjacent in either order; the pair folds to a single
// S-variant:
//   sub wd, wn, wm ; cmp wn, wm -> subs wd, wn, wm
//   cmp wn, wm ; sub wd, wn, wm -> subs wd, wn, wm
//   add wd, wn, wm ; cmn wn, wm -> adds wd, wn, wm
// CMP Rn, Rm is SUBS ZR, Rn, Rm and CMN Rn, Rm is ADDS ZR, Rn, Rm --
// the identical computation -- and NZCV is a function of the
// operands only, never Rd, so the folded S-variant's flags are
// bit-identical to the compare's in all four bits. No flag-liveness
// scan is needed: downstream may read any condition. This is the
// rare fully flag-exact rewrite, unlike the zero-CMP fold above,
// whose C/V diverge.
//
// The operand match is by encoding: the compare must be exactly the
// ALU's word with the S bit set and Rd = 31, which covers the
// immediate, shifted-register and extended-register forms, forces
// equal widths, shift types/amounts and extend options, and pairs
// the families automatically (an ADD's compare spelling is CMN, a
// SUB's is CMP; ADD + CMP never matches). ADD commutes, so the
// swapped-operand CMN (cmn x2, x1 against add x0, x1, x2) also
// folds for the plain unshifted register form -- it sums the same
// values, so all four NZCV bits match. Only that form swaps: a
// nonzero shift amount breaks the symmetry, the immediate form has
// no second register, the extended form extends Rm only, and
// subtraction does not commute (the reversed cmp wm, wn never
// matches).
//
// In the ALU-first order the compare runs after the ALU wrote Rd, so
// Rd must not be one of the compared registers (the compare read the
// result there, and the folded S-variant would use pre-ALU values);
// the compare-first order writes nothing before the ALU and needs no
// such restriction. Rd = 31 producers are excluded: SP for the
// immediate and extended forms -- the S-variant's Rd = 31 is ZR, so
// the fold would drop an observable SP update -- and a dead ZR write
// for the shifted form. An immediate of 0 is excluded across the
// family (degenerate pairs; the ADD side's MOV-from-SP alias
// spelling must not gain an "s"). The S spelling is the ALU's
// mnemonic plus "s" (NEGS for the NEG alias). Reported per family as
// "SUB + CMP of identical operands foldable to SUBS" / "ADD + CMN of
// identical operands foldable to ADDS"; the shape appears when code
// computes a sum or difference and separately compares the same
// operands (hand-written bounds checks, naive codegen).
bool check_sub_cmp_fold(armlint_state *state, const cs_insn *insn,
                        size_t offset, armlint_finding *out);

// Detect a flag-setting ADD/SUB (ADDS/SUBS in any of the three
// forms, including the CMP/CMN aliases) immediately followed by a
// compare of its OWN operands:
//   subs x0, x1, x2 ; cmp x1, x2   -> drop the cmp
//   adds x0, x1, x2 ; cmn x1, x2   -> drop the cmn
// The producer already computed exactly these flags, so the compare
// recomputes the same NZCV and is simply dropped -- nothing else is
// rewritten (unlike the non-S sibling check_sub_cmp_fold, no
// mnemonic gains an "s", so even the imm = 0 spellings need no
// exclusion). The swapped-operand CMN also matches for the plain
// unshifted ADDS (commutative sum, same guard rules as the sibling),
// and a producer with Rd = 31 is itself a compare, making the pair
// an adjacent duplicate compare -- equally droppable.
//
// The compare must not read the producer's destination (Rd among
// the compared registers reads the result, not the original
// operand). Distinct from check_redundant_cmp_after_s_variant,
// which flags the compare of the RESULT against zero; this check
// flags the compare of the operands. Reported per family as
// "SUBS + CMP of identical operands: redundant compare" /
// "ADDS + CMN of identical operands: redundant compare".
bool check_subs_cmp_redundant(armlint_state *state, const cs_insn *insn,
                              size_t offset, armlint_finding *out);

// Advance the deferred "redundant CMP after S-variant" finding's
// flag-liveness scan by one instruction. Parallel to
// armlint_advance_pending; call before per-instruction checks each
// step. The offset parameter exists for compatibility with the shared
// armlint_check_fn signature; it is unused.
bool armlint_advance_pending_sv(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Advance the deferred "ALU + zero-CMP -> S-variant" finding's
// flag-liveness scan by one instruction (see
// check_zero_cmp_to_s_variant). Parallel to armlint_advance_pending;
// call before per-instruction checks each step. The offset parameter
// exists for compatibility with the shared armlint_check_fn
// signature; it is unused.
bool armlint_advance_pending_zs(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Advance the shared dead-register deferral's forward register-liveness
// scan by one instruction. This slot gates every fold whose rewrite
// deletes the producer of a register that no consumer overwrite proves
// dead: the MOV-chain folds (MOV #0 -> ZR, the strength reductions,
// the immediate/offset/FMOV folds), the BFXIL/BFI synthesis, the CSET
// inversion folds, the address folds' store and fresh-destination
// load consumers, and the producer folds' (shift, funnel, extend,
// MUL/SMULL, NEG, MVN) fresh-destination consumers. Parallel to
// armlint_advance_pending; call before per-instruction checks each
// step. The offset parameter exists for compatibility with the shared
// armlint_check_fn signature; it is unused.
bool armlint_advance_pending_mz(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Advance the deferred single-bit-test TBZ/TBNZ finding's two-edge
// register-liveness scan by one instruction (see check_single_bit_cbz).
// Emits the stashed finding when an instruction overwrites the masked
// temp before any read or control transfer AND the folded branch's
// target lies within the clean scanned span, so the taken edge shares
// the proof. Unlike the other advancers this one uses its offset
// parameter -- the containment gate compares the kill's offset against
// the branch target's.
bool armlint_advance_pending_tb(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Close any open sequence at end-of-region. Returns true and fills *out
// if the closed sequence is reportable.
bool armlint_flush(armlint_state *state, armlint_finding *out);

// Tallies optimization opportunities by type (finding name) across one
// or more check_instructions runs, so the driver can print a
// by-prevalence summary. Opaque; created/destroyed by the caller.
typedef struct armlint_summary armlint_summary;

armlint_summary *armlint_summary_create(void);
void armlint_summary_destroy(armlint_summary *summary);

// Print the accumulated counts as "Optimization opportunities by type",
// one line per finding name sorted by descending count (ties broken by
// name). Emits a trailing blank line; a no-op when empty.
void armlint_summary_print(const armlint_summary *summary);

// Total instructions decoded across the check_instructions runs tallied
// into this summary (data-in-text slots are not counted). Returns 0 for
// a NULL summary.
size_t armlint_summary_instructions(const armlint_summary *summary);

// Top-level driver: disassemble inst[0..len) at base_addr, run all
// checks, and return the number of findings (or -1 on a decoding
// error). In verbose mode each finding is printed -- its one-line
// summary followed by the offending instructions (indented). Otherwise
// nothing is printed per finding (a large binary may have tens of
// thousands); the caller's by-type summary is the whole report. If
// summary is non-NULL, every finding is tallied into it by type and the
// decoded-instruction total is accumulated, regardless of verbosity.
int check_instructions(csh handle, const uint8_t *inst, size_t len,
                       uint64_t base_addr, bool verbose,
                       armlint_summary *summary, unsigned features);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
