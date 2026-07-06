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
// logical shifted-register op that consumes the shift's destination,
// with the consumer overwriting that register. The pair can be
// replaced by a single shifted-register form (the shift rides on the
// consumer's Rm). ROR folds only into the logical consumers: the
// arithmetic shifted-register encoding reserves shift type 11.
//
// The shift result may sit in the consumer's Rm slot (any consumer) or
// its Rn slot (commutative consumers only -- ADD/ADDS/AND/ANDS/ORR/EOR
// and EON, which is XNOR; the fold swaps the two sources so the shifted
// value lands on Rm). The other ("independent") source operand must not
// also be the shift destination: with both sources equal to it (e.g.
// `lsl wt,ws,#k ; add wt,wt,wt`) the rewrite would read a stale
// pre-shift value, so that case is rejected.
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
// collide with the other field). Like check_lsl_fold, only flags when the
// consumer overwrites the shift's destination, proving the intermediate is
// dead; the inline-shifted source must be a different register so the shift
// does not clobber it.
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

// Detect a MOV chain that materialises the constant 0, immediately
// followed by an instruction that reads that register. The read can
// be replaced by XZR/WZR (the architectural zero register), making
// the MOV dead. Three consumer families are covered:
//   - STR (B/H/W/X, unsigned-offset) with Rt == mov_rd
//       -> str <wzr/xzr>, [...]
//   - ADD/SUB/ADDS/SUBS (shifted-register, LSL #0) with Rn or Rm ==
//     mov_rd  -> the same op with that operand replaced by ZR. CMP /
//     CMN aliases (S-variant + Rd == ZR) are rendered as the alias.
//   - AND/ORR/EOR/ANDS (shifted-register, LSL #0, N == 0) with Rn or
//     Rm == mov_rd -> the same op with that operand replaced by ZR.
//     TST alias (ANDS + Rd == ZR) is rendered as the alias.
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
// Soundness (conservative):
//   - Rd of the ADD/SUB must equal Rt, so the MUL's destination is
//     overwritten by the ADD/SUB and its intermediate value is dead.
//     This is the textbook array-indexing pattern: the MUL result
//     fed once into the ADD/SUB and not reused.
//   - The "accumulator" operand (the one that is not Rt) must NOT
//     equal Rt -- otherwise the ADD/SUB reads the MUL's result
//     twice while the MADD rewrite reads pre-MUL values, diverging.
// Widths must match: both W or both X. MUL writing to ZR is excluded
// (the pending slot is not opened for MUL Xd=XZR since the result
// is discarded). The degenerate SUB case `sub xt, xzr, xt` (i.e.
// NEG xt, xt) folds to the MSUB-with-ZR alias MNEG and is reported as
// such ("MUL + NEG foldable to MNEG").
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
// Soundness (conservative): identical to check_mul_add_sub_fold -- Rd
// of the ADD/SUB must equal Xt (so the product is overwritten and
// dead), and the accumulator operand must not equal Xt. S-variants
// (ADDS/SUBS) are skipped because the long MAC has no flag-setting
// form. SMULL/UMULL writing to ZR is excluded (result discarded). The
// degenerate SUB case `sub xt, xzr, xt` (NEG) folds to the long
// MSUB-with-ZR alias SMNEGL / UMNEGL and is reported as such.
bool check_widening_mul_add_sub_fold(armlint_state *state,
                                     const cs_insn *insn,
                                     size_t offset, armlint_finding *out);

// Detect NEG Rt, Rs (the SUB Rt, XZR, Rs alias, no shift, non-S)
// immediately followed by an ADD/SUB (shifted-register, LSL #0,
// non-S-variant) that consumes Rt. The pair folds to a single
// instruction by absorbing the negation into the consumer's sign:
//   neg xt, xs ; add xd, xt, xc -> sub xd, xc, xs  (ADD commutative)
//   neg xt, xs ; add xd, xc, xt -> sub xd, xc, xs
//   neg xt, xs ; sub xd, xc, xt -> add xd, xc, xs
// The form `sub xd, xt, xc` is NOT foldable: there is no single
// AArch64 instruction computing `-xs - xc`. S-variants (ADDS/SUBS)
// are skipped because the fold changes the flag-set definition
// (V/C in particular). NEGS is similarly excluded as a producer.
//
// Soundness (conservative):
//   - Rd of the ADD/SUB must equal Rt, so the NEG's destination is
//     overwritten and the intermediate -xs value is dead.
//   - The "accumulator" operand (the one that is not Rt) must NOT
//     equal Rt -- otherwise both ADD/SUB sources are -xs, computing
//     -2*xs or 0 instead of the additive identity the fold assumes.
// Widths must match: both W or both X. NEG writing to ZR is excluded
// (the result is discarded), as is NEG of ZR (which computes 0 --
// a different idiom, not strength reduction).
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
// Soundness (conservative, mirrors check_neg_add_sub_fold): Rd of the
// consumer must equal Rt (so the MVN's destination is overwritten and
// the ~Rs value is dead), and the independent operand must not also be
// Rt (the both-equal case is a self-op, handled by check_self_op). The
// shifted MVN form is not handled -- the consumer would shift the
// complemented value, not Rs. MVN writing ZR, and MVN of ZR (the
// all-ones constant), are excluded.
bool check_mvn_logic_fold(armlint_state *state, const cs_insn *insn,
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
// Soundness (conservative, mirrors the shift fold): Rd of the consumer
// must equal the extend's Rd (so the extended value is dead), and the
// other source operand must not also be it -- nor register 31, which
// the shifted-register consumer read as ZR but the extended-register
// rewrite would read as SP. The producer form (W vs X) must match the
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
// immediately followed by an unsigned-offset LDR with imm12 = 0
// whose base register and destination register both equal Rd of the
// ADD. The pair folds to a single register-offset LDR:
//   add xt, xn, xm           ; ldr xt, [xt]   -> ldr xt, [xn, xm]
//   add xt, xn, xm, lsl #s   ; ldr xt, [xt]   -> ldr xt, [xn, xm, lsl #s]
// The LDR's destination width may be W or X (same register number
// as Xt): writing Wt zeros bits 63..32 of Xt, overwriting the
// address regardless of size.
//
// The sign-extending loads (LDRSB/LDRSH, Wt or Xt; LDRSW) fold
// identically -- they too overwrite the full X register named by Rt
// and have register-offset forms. PRFM, which shares the encoding
// family but whose Rt is a prefetch operation, is excluded.
//
// Shift constraint: LDR (register, unsigned-offset variant) accepts
// only LSL #0 or LSL #log2(access_size). access_size in bytes:
// 1 for LDRB/LDRSB, 2 for LDRH/LDRSH, 4 for LDR W/LDRSW, 8 for LDR X.
//
// Soundness (conservative): Rd of the ADD must equal Rt of the LDR
// (the loaded register). The LDR's write to Wt/Xt destroys the
// pre-LDR address value of Xt, so Xt is dead immediately after the
// LDR -- the ADD's only consumer was the LDR's base, which is now
// folded into the LDR's addressing mode. STR is not flagged here
// because there is no analogous Rd == Rt overwrite to prove Xt dead.
//
// The ADD's Rn = 31 case is excluded because Rn = 31 in
// shifted-register ADD means XZR, but Rn = 31 in the LDR
// register-offset form means SP -- the semantic mismatch would make
// the rewrite incorrect. Rm = 31 (XZR) in the ADD makes the ADD a
// MOV-and-rename, an unusual pattern excluded for cleanliness.
bool check_add_ldr_register_offset(armlint_state *state,
                                   const cs_insn *insn,
                                   size_t offset, armlint_finding *out);

// Detect SXTW Xt, Ws immediately followed by a register-offset LDR
// whose index register and destination both equal Xt. The pair folds
// the sign-extension into the load's addressing mode:
//   sxtw xt, ws ; ldr xt, [xn, xt]          -> ldr xt, [xn, ws, sxtw]
//   sxtw xt, ws ; ldr xt, [xn, xt, lsl #s]  -> ldr xt, [xn, ws, sxtw #s]
// This is the array-indexing idiom (a 32-bit signed index into a 64-bit
// base). All four zero-extending sizes (LDRB/LDRH/LDR W/LDR X) and the
// sign-extending loads (LDRSB/LDRSH, Wt or Xt; LDRSW) are handled; the
// scale bit carries over unchanged.
//
// Soundness (conservative, mirrors check_add_ldr_register_offset): the
// consumer must be an integer load (not STR, which has no Rt overwrite,
// nor PRFM, whose Rt is a prefetch operation, not a destination) using
// the LSL/UXTX index option (a full 64-bit
// register offset, equivalent to the SXTW's result), with Rt == Rm == Xt
// so the load overwrites the index and the extended value is dead. The
// base Rn must NOT be Xt: with the SXTW folded away the base would read
// its pre-SXTW value, changing the address. SXTW into ZR is excluded.
// Only SXTW is matched (the load index extend is word-width; a standalone
// 32->64 zero-extend is normally a W-register MOV, not a literal UXTW).
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
// by an unsigned-offset LDR whose base register and destination
// register both equal Rd of the ADD. The pair folds to a single
// immediate-offset LDR, summing the two displacements:
//   add xt, xn, #a  ; ldr xt, [xt]      -> ldr xt, [xn, #a]
//   add xt, sp, #a  ; ldr xt, [xt]      -> ldr xt, [sp, #a]
//   add xt, xn, #a  ; ldr xt, [xt, #b]  -> ldr xt, [xn, #(a+b)]
// The LDR's destination width may be W or X (same register number as
// Xt): writing Wt zeros bits 63..32 of Xt, overwriting the address
// regardless of size. LDRB/LDRH and the sign-extending
// LDRSB/LDRSH/LDRSW consumers fold the same way (PRFM is excluded:
// its Rt is a prefetch operation, not a destination).
//
// Encoding constraint: the combined byte offset must be a multiple of
// the LDR's access size and its scaled value must fit in 12 bits. The
// LDR's own imm12 is already a multiple of access_size, so alignment
// is determined solely by the ADD's byte immediate. The ADD's sh=1
// form (imm12 << 12) is supported.
//
// Soundness (conservative): Rd of the ADD must equal Rt of the LDR
// (the loaded register), so the LDR's write to Wt/Xt destroys the
// pre-LDR address value of Xt and the ADD's only consumer was the
// LDR's base. STR is not flagged here because there is no analogous
// Rd == Rt overwrite to prove Xt dead.
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
// Soundness: distinct from check_add_ldr_imm_offset, which catches
// the related pattern where the LDR's Rt also equals the ADD's Rd
// (folding to the unsigned-offset form with no writeback). When
// Rt == Rd, that earlier check fires and pre-index is rejected here
// because Rt == Rn writeback is UNPREDICTABLE (CONSTRAINED for
// stores); for pairs that applies to either data register, and a
// load pair with Rt == Rt2 (CONSTRAINED UNPREDICTABLE on its own) is
// never folded. The Rn == 31 case is allowed: Rn means SP and Rt
// means XZR, so the two encode distinct registers. The access's
// offset must be 0; a non-zero offset combined with a base bump has
// no pre-index expression that preserves both the access address and
// the final base value. Same code-size/decode-slot win as
// post-index; no backend throughput change on most OoO cores.
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

// Advance the deferred "redundant CMP after S-variant" finding's
// flag-liveness scan by one instruction. Parallel to
// armlint_advance_pending; call before per-instruction checks each
// step. The offset parameter exists for compatibility with the shared
// armlint_check_fn signature; it is unused.
bool armlint_advance_pending_sv(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Advance the deferred "MOV #0 + use foldable to ZR" finding's forward
// register-liveness scan by one instruction. Parallel to
// armlint_advance_pending; call before per-instruction checks each step. The
// offset parameter exists for compatibility with the shared armlint_check_fn
// signature; it is unused.
bool armlint_advance_pending_mz(armlint_state *state, const cs_insn *insn,
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
                       armlint_summary *summary);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
