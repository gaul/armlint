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

// Pure predicate: true iff imm is encodable as an AArch64 logical
// (bitmask) immediate at the given register width (32 or 64).
//
// Exposed for direct testing. The encoding excludes 0 and the
// all-ones value at the given width.
bool is_bitmask_immediate(uint64_t imm, unsigned reg_width);

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

// Examine insn (already decoded by Capstone) in the context of recent
// instructions. Returns true if a finding is produced (in *out); false
// otherwise. May produce a finding when a non-matching instruction
// closes a previously open sequence, so callers must invoke
// armlint_flush after the last instruction of a region to catch a
// trailing sequence.
bool check_movz_movk_bitmask(armlint_state *state, const cs_insn *insn,
                             size_t offset, armlint_finding *out);

// Detect an LSL (immediate) immediately followed by an arithmetic or
// logical shifted-register op that consumes the LSL's destination as
// its Rm, with the consumer overwriting that register. The pair can be
// replaced by a single shifted-register form.
bool check_lsl_fold(armlint_state *state, const cs_insn *insn,
                    size_t offset, armlint_finding *out);

// Detect CMP Rn, #0 (SUBS XZR, Rn, #0) immediately followed by B.EQ or
// B.NE; the pair is replaceable by CBZ Rn / CBNZ Rn with the same
// branch target. Emission is deferred via the pending-finding mechanism
// so the rewrite is only suggested when downstream code provably does
// not observe the dropped NZCV state -- see armlint_advance_pending.
bool check_cmp_zero_branch(armlint_state *state, const cs_insn *insn,
                           size_t offset, armlint_finding *out);

// Detect TST Rn, #(1<<k) (ANDS XZR, Rn, #imm) immediately followed by
// B.EQ or B.NE; the pair is replaceable by TBZ Rn, #k or TBNZ Rn, #k
// when the branch target fits in TBZ's shorter (14-bit signed) range.
// Like check_cmp_zero_branch, emission is deferred until the forward
// liveness scan confirms NZCV is dead.
bool check_tst_branch(armlint_state *state, const cs_insn *insn,
                      size_t offset, armlint_finding *out);

// Detect a W-form ALU/move/bitfield instruction whose result Rd is
// immediately consumed by UXTW Xd, Wd or AND Xd, Xd, #0xffffffff with
// the same Rd. The X-form zero-extension is redundant because the
// W-form write already zeroed bits 63..32 of the X register.
bool check_redundant_zext(armlint_state *state, const cs_insn *insn,
                          size_t offset, armlint_finding *out);

// Detect a sign-extending producer (LDRSB / LDRSH / LDRSW or SXTB /
// SXTH / SXTW) immediately followed by an SXTB / SXTH / SXTW consumer
// whose destination width matches the producer's and whose sign
// threshold is at least the producer's. The consumer is redundant: the
// producer already replicated the sign bit through the same upper bits.
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
// MOV destination. ZR as Rd or as the "other" operand is excluded.
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
bool check_mneg_strength_reduce(armlint_state *state, const cs_insn *insn,
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
// excluded (it makes the ADD/SUB degenerate).
//
// Runs alongside check_mul_strength_reduce / check_mneg_strength_reduce
// before check_movz_movk_bitmask so the MOV chain state is still
// active when the consumer is examined.
bool check_mov_add_sub_imm_fold(armlint_state *state, const cs_insn *insn,
                                size_t offset, armlint_finding *out);

// Detect AND/ORR/EOR/ANDS (shifted-register, LSL #0, N = 0) where one
// operand is set by an immediately preceding MOV chain to a constant
// C that is a valid AArch64 bitmask immediate at the consumer's width.
// The pair folds to the immediate form:
//   mov xc, #C ; and  xd, xn, xc -> and  xd, xn, #C
//   mov xc, #C ; orr  xd, xn, xc -> orr  xd, xn, #C
//   mov xc, #C ; eor  xd, xn, xc -> eor  xd, xn, #C
//   mov xc, #C ; ands xd, xn, xc -> ands xd, xn, #C   (TST when Rd=ZR)
// is_bitmask_immediate is used as the encodability predicate; values
// 0 and the all-ones-at-width are not bitmask immediates, so the
// trivial-constant cases naturally skip.
//
// The N = 1 family (BIC/ORN/EON/BICS) has no immediate-form
// equivalent in AArch64 and is not folded. AND/ORR/EOR/ANDS are all
// commutative, so either Rn or Rm may be the MOV destination. ZR as
// the non-MOV operand is excluded (degenerate).
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
// Rn = 31 in addressing means SP (not ZR), so the STR base register
// is intentionally not considered a fold candidate -- only the Rt
// data slot. For arithmetic/logical shifted-register forms,
// Rn = Rm = 31 both denote ZR, so either operand is foldable.
bool check_mov_zero_to_xzr(armlint_state *state, const cs_insn *insn,
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
// is discarded).
bool check_mul_add_sub_fold(armlint_state *state, const cs_insn *insn,
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
// Shift constraint: LDR (register, unsigned-offset variant) accepts
// only LSL #0 or LSL #log2(access_size). access_size in bytes:
// 1 for LDRB, 2 for LDRH, 4 for LDR W, 8 for LDR X.
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

// Detect two adjacent unsigned-offset LDR/STR (both W or both X,
// same direction, same base, consecutive offsets) foldable into a
// single LDP/STP; also two adjacent unsigned-offset LDRSW pairs
// foldable into a single LDPSW (always Xt destinations, 4-byte
// transfer, load-only). v1 supports only the unsigned-offset form,
// which guarantees natural alignment by construction (imm12 is
// scaled); LDUR / pre- and post-indexed forms are deferred to avoid
// the implementation-defined behaviour around unaligned LDP/STP.
// A pending LDR/STR will not pair with an LDRSW (different opcode).
bool check_ldp_stp_coalesce(armlint_state *state, const cs_insn *insn,
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
// followed immediately by CMP/TST-zero of Rd, followed immediately by
// B.EQ/B.NE. All S-variants set Z = (Rd == 0), so the CMP/TST is
// recomputing the same Z bit. The CMP/TST is flagged redundant once
// the same downstream NZCV-liveness scan as check_cmp_zero_branch
// confirms dropping it is sound (no N/C/V observation downstream).
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

// Close any open sequence at end-of-region. Returns true and fills *out
// if the closed sequence is reportable.
bool armlint_flush(armlint_state *state, armlint_finding *out);

// Top-level driver: disassemble inst[0..len) at base_addr, run all
// checks, print findings to stdout, return the number of findings (or
// -1 on a decoding error).
int check_instructions(csh handle, const uint8_t *inst, size_t len,
                       uint64_t base_addr);

#endif
