# armlint analyses

Full reference for every analysis armlint implements -- mechanics,
soundness, and what each rewrite saves. See the
[README](README.md) for an at-a-glance table and the project's
design and soundness model.

Throughout, `datasize` is the operand width in bits: 32 for the W-form,
64 for the X-form.

## suboptimal MOVZ/MOVK sequence

* `movz w0, #0x6666 ; movk w0, #0x6666, lsl #16` instead of
  `mov w0, #0x66666666` (single bitmask-immediate ORR)
* More generally, any MOVZ/MOVN + MOVK chain longer than the minimal
  move-wide sequence for its final value. The minimal length is one
  instruction per non-zero halfword for a MOVZ-based chain, one per
  non-0xFFFF halfword for a MOVN-based chain (each with a floor of
  one), whichever is smaller. So the four-instruction
  `movz x0, #0x5678 ; movk x0, #0x1234, lsl #16 ;
  movk x0, #0xffff, lsl #32 ; movk x0, #0xffff, lsl #48`
  (0xFFFFFFFF12345678) flags with the two-instruction rewrite
  `movn x0, #0xa987 ; movk x0, #0x1234, lsl #16`, and a MOVK that
  rewrites a halfword the base instruction already set (`movk #0`
  over MOVZ, `movk #0xffff` over MOVN) flags as plainly redundant.
* The chain is accumulated per register -- a MOVZ or MOVN opens it,
  same-register same-width MOVKs extend it -- and the final value is
  judged when the chain closes (any other instruction, or end of
  region). Judging the net value catches chains whose individual
  steps look necessary but whose result is cheap.
* Soundness: the rewrite materializes the same constant in the same
  register; no flags or memory are involved. Like every multi-
  instruction fold, it assumes control flow does not enter the middle
  of the chain.
* What it saves: one to three instructions per constant (4 bytes and
  a decode slot each). Hybrid constructions (a bitmask-immediate ORR
  or MOV followed by MOVKs), which beat both pure move-wide forms for
  some values, are not yet modeled -- the reported minimum is an
  upper bound on the true one.

## shift foldable into shifted-register form

* `lsl w0, w1, #3 ; add w0, w2, w0` instead of
  `add w0, w2, w1, lsl #3`. Same for SUB, AND, ORR, EOR (and
  flag-setting variants), and for the other shift producers: LSR and
  ASR fold the same way with the consumer carrying their shift type
  (`lsr x0, x1, #4 ; add x0, x2, x0` -> `add x0, x2, x1, lsr #4`),
  and a ROR -- the same-register `EXTR Rd, Rs, Rs, #n` alias -- folds
  into the logical consumers only, because the arithmetic
  shifted-register encoding reserves shift type 11. An EXTR with
  distinct sources is a funnel shift and does not fold. The rewrite
  deletes the shift, so its destination must be dead afterward: a
  consumer that overwrites it proves that on the spot, and a consumer
  writing a fresh register (`lsl w8, w1, #3 ; add w9, w2, w8`) defers
  through the forward register-liveness scan and reports only once
  `w8` is provably overwritten before any read or control transfer.
  `Rd = 31` consumers are excluded -- the non-S forms are dead writes,
  the S forms the `CMP`/`CMN`/`TST` aliases.
* Why the fuse helps -- shared by the "producer into its consumer"
  folds (this one; the bitfield-`UBFX`/`UBFIZ` shift/mask pairs;
  `MUL`/`SMULL` + `ADD` -> `MADD`/`SMADDL`; `NEG` + `ADD`/`SUB`;
  `MVN` + logical; and the extend fold below): one fewer instruction
  (4 bytes, a decode/issue slot, I-cache), and the folded-away producer
  op no longer executes as a separate dependent instruction on the
  critical path -- it rides in the consumer's ALU operand instead. The
  scratch register that held the intermediate is freed too.
* The shifted-register form carries the shift on `Rm` only. When the
  shift result is the consumer's `Rm`, any consumer folds. When it is the
  consumer's `Rn`, only a commutative consumer folds, by swapping the
  two sources so the shifted value moves to `Rm`: `lsl w0, w1, #3 ;
  add w0, w0, w2` -> `add w0, w2, w1, lsl #3`. The commutative set is
  `ADD`/`ADDS`, `AND`/`ANDS`, `ORR`, `EOR`, and `EON` (bitwise XNOR,
  so `a ^ ~b == b ^ ~a`); `SUB`/`SUBS`, `BIC`/`BICS` and `ORN` are not
  symmetric in their two sources and so do not fold from the `Rn` slot.
* The "independent" source (the one that is not the shift result, which
  becomes the new `Rn`) must not itself be the shift destination. The
  degenerate `lsl wt, ws, #k ; add wt, wt, wt` -- both consumer sources
  equal to the shift destination -- is therefore not flagged: it doubles
  the shifted value (`ws << (k+1)`), which the single shifted-register
  form cannot express, and a naive rewrite would read a stale pre-shift
  value for the second operand. An XZR independent operand is likewise
  not flagged: such consumers are shifted register copies (`ORR` from
  ZR is the `MOV` alias) or constants, not ops the shift rides into.

## funnel shift foldable into EXTR or ROR

* `lsr x2, x1, #56 ; orr x2, x2, x3, lsl #8` instead of
  `extr x2, x3, x1, #56`. An immediate `LSL`/`LSR` feeding an `ORR`,
  `EOR` or `ADD` whose `Rm` carries the complementary shift (opposite
  direction, amounts summing to the register width) reassembles a funnel
  shift: the `LSR`'d source supplies the low half, the `LSL`'d source the
  high half, and a single `EXTR Rd, Rhi, Rlo, #lsb` (with `lsb` the
  right-shift amount) produces the same bits. When both halves are the
  same register the funnel is a rotate and folds to `ROR Rd, Rs, #lsb`
  (the same-register `EXTR` alias) instead.
* This is the inverse of the
  [shift-fold check](#shift-foldable-into-shifted-register-form) above,
  which absorbs a shift whose consumer has *no* shift of its own. Here the
  consumer already carries a second, complementary shift, so the pair is a
  two-register funnel that the shifted-register form cannot express but
  `EXTR` can.
* Only `ORR`, `EOR` and `ADD` qualify. With complementary amounts the two
  shifted fields are bit-disjoint -- the high field occupies bits
  `[hi, datasize-1]` and the low field `[0, hi-1]`, no overlap -- so OR,
  XOR and ADD all agree bit-for-bit with `EXTR` (ADD carries nothing
  across the gap). `SUB` (borrows), `AND`/`BIC` (disjoint fields AND to
  zero) and the flag-setting `ADDS` (an `EXTR` drops `NZCV`) are not
  funnels and are rejected.
* The consumer's shift must be logical (`LSL`/`LSR`), never `ASR`: an
  arithmetic right shift fills the vacated high bits with the sign, which
  would collide with the other field instead of leaving the zeroes a
  funnel needs. The pending producer is likewise only `LSL`/`LSR`.
* Soundness: like the shift-fold check, the rewrite deletes the
  producer shift, so its destination must be dead afterward. A consumer
  that overwrites it (`Rd == Rt`) proves that on the spot; a consumer
  that writes a fresh register defers through the forward
  register-liveness scan and reports only once the shift result is
  provably overwritten before any read or control transfer (`Rd = 31`,
  a dead write, is excluded). The inline-shifted source must be a
  different register than the shift destination, else the funnel would
  read the shifted value rather than the original register. Shifting or
  writing `XZR` is rejected as degenerate.
* What it saves: one instruction (4 bytes, a decode/issue slot), and the
  producer shift no longer runs as a separate dependent op on the critical
  path -- the whole funnel is one `EXTR`. Compilers that recognize the
  idiom emit this already (Go's SSA backend, for one, lowers
  `(x >> (64-c)) | (y << c)` straight to `EXTR`), so on well-optimized
  output the check is silent; it catches the residual cases from
  hand-written assembly and weaker code generators.

## extend foldable into shifted/extended-register form

* The extend counterpart of the shift fold: where that absorbs a shift,
  this absorbs an extension. A standalone `UXTB`/`UXTH` (W-form),
  `SXTB`/`SXTH` (W or X), or `SXTW` (X) feeding an `ADD`/`SUB` folds
  into the consumer's extended-register form, where the extend (and an
  optional shift) ride on the consumer's Rm:
  * `sxtw x0, w1 ; add x0, x3, x0` -> `add x0, x3, w1, sxtw`
  * `uxtb w0, w1 ; sub w0, w3, w0` -> `sub w0, w3, w1, uxtb`
  The extended operand is always rendered as a `W` register, since
  these extends source 32 bits or fewer.
* What you actually save: one instruction (4 bytes, a decode slot,
  I-cache), and -- unlike the pre-/post-index LDR/STR folds, which are
  backend-neutral -- usually a cycle of latency. The extended-register
  ADD/SUB performs the extension in the ALU's operand path, so two
  *dependent* ops (extend, then add) collapse to one, shortening the
  dependency chain. (A few cores route extended/shifted ADD to a
  slightly slower pipe, but the single op is still no slower than the
  original pair.) It also frees the scratch register that held the
  extended value.
* `ADD`/`ADDS` commute, so the extend result may be in the consumer's
  Rn or Rm slot (it is swapped to Rm); `SUB`/`SUBS` only fold when it
  is already Rm.
* Soundness (mirrors the shift fold): the rewrite deletes the extend,
  so its destination must be dead afterward -- a consumer that
  overwrites it reports immediately, and one writing a fresh register
  defers through the forward register-liveness scan. The other source
  operand must not be the extend's destination -- nor register 31,
  which the shifted-register consumer read as ZR but the
  extended-register rewrite would read as SP. `Rd = 31` consumers are
  excluded for the same reason, and more sharply: the shifted-register
  consumer's `Rd = 31` is a discarded ZR write, but the
  extended-register rewrite's `Rd = 31` is SP -- the fold would turn
  dead code into a stack-pointer update. The producer form (W vs
  X) must match the consumer's, with one relaxation: a W-form
  zero-extend (`UXTB`/`UXTH`) also folds into an X-form consumer
  (`uxtb w0, w1 ; add x0, x2, x0` -> `add x0, x2, w1, uxtb`), because
  the W write zeroed bits 63..32 and that is exactly what the X-form
  extended-register option computes. The W-form sign-extends do not
  get the relaxation: they too zero the high half, where the X-form
  `SXT` option would replicate the sign. Extend of, or
  into, ZR is excluded. The standalone 32->64 zero-extend `UXTW` is not
  matched as a producer: it is normally a `W`-register `MOV` (a `W`
  write already zeros the upper half), not a literal instruction.

## compare-zero branch foldable into CBZ/CBNZ

* `cmp w0, #0 ; b.eq target` instead of `cbz w0, target`. Same for
  `b.ne` -> `cbnz`. Also matches the equivalent zero-test idioms
  `cmp Rn, xzr` (SUBS XZR, Rn, XZR), `cmn Rn, #0` / `cmn Rn, xzr`
  (the ADDS-based spellings -- adding zero leaves the same N and Z),
  and `tst Rn, Rn` (ANDS XZR, Rn, Rn): all five set `Z=1` iff
  `Rn==0` and so fold identically.
* The unsigned conditions fold too, for the SUBS-based forms only:
  subtracting zero never borrows, so `C == 1` and `b.hi` (`C && !Z`)
  reduces to `b.ne` -> `cbnz`, `b.ls` (`!C || Z`) to `b.eq` -> `cbz`.
  `tst Rn, Rn` and the `cmn` spellings are excluded from this pair --
  ANDS clears C, and adding zero never carries, so after either HI is
  never taken and LS always taken, dead-branch territory rather than
  a register-test rewrite. (`b.hs`/`b.lo` after any zero test are
  likewise constant-valued and are not rewritten here.)
* Why it helps (shared by the `CMP`/`TST` -> `TBZ`/`TBNZ` folds below):
  one fewer instruction, and the branch no longer depends on a
  flag-writing `CMP`/`TST` -- `CBZ`/`CBNZ` reads the register directly,
  removing the NZCV def-use and the scheduling constraint it imposes.
* Soundness: `CBZ`/`CBNZ` does not write NZCV, but `CMP Rn, #0`
  writes all four flags. Folding is unsound if subsequent code
  reads N, C, or V (e.g. `ADCS`, `CSEL`, `B.LT`, `CCMP`). armlint
  runs a forward NZCV-liveness scan on the fall-through path: the
  finding is emitted only after seeing an instruction that
  overwrites NZCV without reading them (ADDS/SUBS/ANDS/BICS/FCMP, or
  a well-formed FEAT_MOPS prologue CPYFP*/CPYP*/SETP*/SETGP*, which
  unconditionally rewrites all four flags -- overlapped-register or
  reg == 31 forms are CONSTRAINED UNPREDICTABLE or UNDEFINED and do
  not count) or a terminator that makes prior flags unobservable
  (RET, BL, BLR). The scan suppresses on any flag-reader (including
  the FEAT_MOPS main/epilogue stages, which consume the algorithm
  state their prologue left in NZCV), an unsafe
  terminator (B unconditional, BR, or a conditional CBZ/CBNZ/TBZ/TBNZ
  whose taken target may still observe the flags), or after a
  16-instruction window with no decision. The branch-target path is
  not scanned; full soundness would require basic-block analysis.

## compare-zero signed-branch foldable into TBZ/TBNZ

* `cmp wn, #0 ; b.lt target` (or `b.ge`/`b.mi`/`b.pl`) folds to
  `tbnz wn, #(datasize-1), target` (or `tbz`). After any of the
  zero-test spellings -- `CMP Rn, #0` / `CMP Rn, ZR` / `CMN Rn, #0` /
  `CMN Rn, ZR` / `TST Rn, Rn` -- `V == 0` and `N = sign(Rn)`, so
  `B.LT` (N != V) reduces to "N == 1" -- exactly a test of the sign
  bit. `B.MI` directly tests `N`; `B.GE`/`B.PL` are the inverse.
* Range: `TBZ`/`TBNZ` use a 14-bit signed offset (~32 KB reach),
  vs. `B.cond`'s 19-bit (~1 MB). The fold is suggested only when
  the target fits in the TBZ encoding.
* Soundness: same NZCV-liveness scan as the CMP-branch check
  above. The rewrite drops the CMP/TST, so downstream code that
  observes N/C/V before they're overwritten would see different
  values; the scan suppresses on any flag-reader. Shares the
  existing CMP/TST pending slot, which is sufficient because the
  sign-only and EQ/NE conditions are mutually exclusive at the
  same B.cond.
* Same win as the CMP -> CBZ fold: one fewer instruction, and the
  branch no longer carries an NZCV dependency.

## TST single-bit + B.EQ/NE foldable into TBZ/TBNZ

* `tst w0, #(1<<5) ; b.eq target` instead of `tbz w0, #5, target`.
  Same for `b.ne` -> `tbnz`. Only the immediate-form `TST` is
  matched (`ANDS XZR, Rn, #imm`) and only when the immediate is a
  single power-of-two bit.
* Range: `TBZ`/`TBNZ` use a 14-bit signed offset (~32 KB reach),
  much shorter than `B.cond`'s 19-bit (~1 MB). The fold is
  suggested only when the target fits in the TBZ encoding.
* Soundness: same NZCV-liveness scan as the CMP-branch check.
* Same win as the CMP -> CBZ fold: one fewer instruction, and the
  branch no longer carries an NZCV dependency.

## TST single-bit + CSET/CSETM foldable into UBFX/SBFX

* The materialising sibling of the check above: the bit feeds a bool
  instead of a branch. `tst w0, #0x10 ; cset w8, ne` computes
  `(w0 >> 4) & 1`, which is `ubfx w8, w0, #4, #1` -- one flag-free
  instruction. `CSETM` (0 or all-ones) is the sign-extending extract,
  `sbfx w8, w0, #4, #1`.
* Conditions: `NE` folds directly (Z clear exactly when the masked
  bit is set). `MI` is accepted as its synonym when the isolated bit
  is the producer's sign bit -- N *is* that bit -- and is
  constant-false for any lower bit. `EQ`/`PL` would need an inverted
  extract, which has no single-instruction form (`ubfx` + `eor #1` is
  back to two), and every other condition is constant after `TST`
  (which clears C and V). Constant-condition shapes are left alone.
* Widths: `CSET`'s 0/1 result zero-extends identically at either
  width, so all W/X producer/consumer combinations fold; the extract
  renders at the consumer's width, bumped to X when the bit lives in
  the high half. `CSETM`'s all-ones must replicate at the CSETM's own
  width, so a W-form `CSETM` of a bit above 31 has no
  single-instruction form and is skipped. Cross-width register reads
  are exact -- bit k < 32 of `Xn` and `Wn` are the same bit.
* The rewrite deletes the `TST` and writes no flags, so all four
  flags it set disappear; emission defers through the same forward
  NZCV-liveness scan as the TBZ folds until the flags are provably
  dead (overwritten, or a safe terminator, before any reader).
* Win: two instructions to one, the scratch bool no longer rides on
  an NZCV dependency, and the flags stay free for the surrounding
  schedule. This shape is common in naive codegen materialising
  `(flags & F) != 0` into a register.

## single-bit test + CBZ/CBNZ foldable into TBZ/TBNZ

* The flag-free spelling of the check above: a producer that isolates
  one bit `k` of `Rs` into a scratch register, immediately followed by
  `cbz`/`cbnz` of the scratch. The scratch is zero iff `Rs[k]` is
  zero, so the pair is a single `tbz`/`tbnz Rs, #k` with the same
  target -- `and w8, w9, #0x10 ; cbz w8, L` -> `tbz w9, #4, L`.
  Recognised producers: a non-flag-setting AND with a one-bit mask,
  and the one-bit UBFM/SBFM extracts (`imms == immr`) --
  `ubfx/sbfx Rd, Rs, #k, #1` and the sign-bit aliases
  `lsr/asr Rd, Rs, #(datasize-1)` (the SBFM forms yield 0 or -1,
  still zero exactly when the bit is clear). No NZCV is involved on
  either side, so no flag-liveness scan is needed.
* What needs proving instead is register liveness: the rewrite
  deletes the producer, so the masked scratch must be dead afterward
  -- on BOTH edges of the branch. The forward register-liveness scan
  proves the fall-through path (the scratch is overwritten before any
  read or control transfer); the taken path is covered by
  containment: the finding is emitted only when the branch target
  lies within `[fall-through, kill]`, the span the scan just proved
  free of reads and control transfers, so the taken edge enters that
  clean span and runs to the same kill. This is the canonical
  skip-a-small-block shape --
  `and w8, w9, #0x10 ; cbz w8, 1f ; add x1, x2, x3 ; 1: mov w8, #0`
  folds because both edges reach the `mov` that kills `w8`. Backward
  targets and targets beyond the kill leave the taken edge unproven
  and are conservatively dropped. Unlike the NZCV checks, which
  assume flags are dead at branch targets (block-local by
  convention), no such assumption is made here: a general-purpose
  register is routinely live into a branch target.
* A W-form `cbz` after a producer isolating bit >= 32 is rejected:
  the zero-extended field sits wholly in the discarded high half,
  making the branch constant -- dead-branch territory, not this
  fold. `ANDS` producers are excluded (deleting one loses the NZCV
  write; the `Rd = ZR` spelling belongs to the TST check), as are ZR
  sources (constant branches) and ZR destinations. The TBZ
  displacement is range-checked against the signed 14-bit encoding,
  though the containment gate restricts it far more tightly in
  practice.
* Same win as the TST fold -- one fewer instruction -- plus the
  scratch register is freed.

## CSET + CBZ/CBNZ foldable into B.cond

* `cset w8, eq ; cbnz w8, L` instead of `b.eq L`. The CSET
  materialises a condition the flags already hold and the branch
  immediately re-tests it: `cbnz` branches exactly when the condition
  held, `cbz` exactly when it did not, so the pair is a single
  `b.<cond>` (`b.<inverse cond>` for `cbz`) with the same target --
  NZCV is untouched between the adjacent pair, so the `b.cond` reads
  the same flags the `cset` did. The temp is 0 or 1 zero-extended
  across the full X register, so W and X producers and branches fold
  in every combination. `cbz`/`cbnz`'s imm19 carries over into
  `b.cond`'s identical imm19 (the displacement grows by the deleted
  producer's slot, range-checked at the encoding's positive limit).
* Two sibling consumers fold the same producer without any branch:
  * `cset w8, eq ; eor w9, w8, #1` -> `cset w9, ne` -- EOR #1
    inverts the boolean, which is the inverted-condition CSET.
    Immediates other than 1 and `eor` writing SP (`Rd = 31` in a
    logical immediate) are excluded.
  * `cset w8, eq ; neg w9, w8` -> `csetm w9, eq` -- negation maps
    1 to all-ones, exactly CSETM, condition unchanged. Shifted and
    flag-setting (`negs`) forms are excluded.
  Both rewrites take the consumer's width (sound at any combination,
  by the same zero-extension argument).
* The rewrite deletes the CSET, so its temp must be dead afterward.
  For the branch consumer that means dead on BOTH edges, and emission
  defers through the same two-edge scan as the single-bit fold: the
  forward scan proves the fall-through path, containment in
  `[fall-through, kill]` covers the taken edge, and backward targets
  are dropped at the consumer. For EOR/NEG, a consumer that
  overwrites the temp itself kills it on the spot and emits
  immediately; otherwise emission defers through the plain forward
  register-liveness scan.
* Raw CSINC condition fields AL/NV are excluded when opening the
  producer: `ConditionHolds` treats both as always-true, so the
  "cset" is the constant 0, not a conditional. ZR destinations
  (discarded results) are excluded on both sides.
* The win is one instruction and a freed temp register, and the
  `b.cond` spelling is what compilers emit for the shape -- the
  `cset`+`cbnz` form appears when a boolean materialised for one
  purpose is then only branched on.

## `BR x30` foldable to RET

* An indirect branch through the link register is a spelled-out
  return: `br x30` and `ret` transfer to the same address, set no
  flags, and write no registers. The one bit of daylight is the
  branch-type hint, and the return-address predictor keys on it --
  RET pops the prediction stack that the matching BL pushed, while
  BR is predicted as an ordinary indirect branch, so a `br x30`
  return both mispredicts itself and desynchronizes the stack for
  the returns around it. The Neoverse software optimization guides
  and the Apple Silicon guide state the rule directly: returns use
  RET. ("BR x30 foldable to RET", `-> ret`.)
* A 1-for-1 canonicalization with nothing to prove: no flags, no
  liveness, and a single-instruction finding is sound from any
  entry. Under BTI the rewrite only relaxes the target's requirement
  (an indirect BR needs a landing pad; RET is exempt). On FEAT_GCS
  hardware (Armv9.4 shadow stacks) the two genuinely diverge -- RET
  pops and checks the guarded stack, BR x30 bypasses it -- which is
  an argument for the rewrite, not against: a genuine return must be
  RET there, and code bypassing the pop deliberately (context
  switchers, unusual trampolines) is exactly what a reviewer wants
  surfaced.
* Composition: applying the rewrite turns `autiasp ; br x30` into
  the split epilogue that the `-m pauth` fold then takes to `retaa`,
  and under `-a pac` the same word also appears in the
  unauthenticated-indirect audit. The authenticated BRAA/BRAAZ forms
  differ in encoding and never match.
* Where the shape lives: compilers emit `ret`, and none of the six
  reference binaries -- nor dyld or libobjc, both rich in hand
  assembly -- contain a single instance. The catch population is
  hand-written assembly, mechanical ports, and JIT emitters.

## branch to the next instruction is a no-op

* A direct branch whose target is the instruction immediately after
  it transfers control exactly where fallthrough would have: taken
  or not taken, execution arrives at the same place. B, B.cond and
  BC.cond, CBZ/CBNZ, and TBZ/TBNZ write no register and no flags,
  so the instruction is a pure no-op regardless of the condition's
  value -- deletable with no condition or liveness reasoning at all,
  while it costs fetch bandwidth, a predictor slot, and (for the
  conditional forms) a possible misprediction. ("branch to the next
  instruction is a no-op", `-> delete: control falls through either
  way`.)
* BL is the one deliberate exclusion: it writes x30 even over a
  zero-length span, and `bl .+4` is the classic get-the-PC idiom in
  old position-independent code -- deleting it would break its
  actual purpose. The distance test is exactly imm == 1 in
  instruction units; imm == 0 is branch-to-self, a spin loop with
  entirely different semantics. Deleting a branch that is itself a
  branch target is sound: the entering path falls through to the
  same successor.
* Composition: a degenerate `cbz`/`tbz` to the next instruction can
  simultaneously draw a fold suggestion from the branch-shape checks
  (a CBZ-to-next of a masked temp is still "foldable to TBZ") --
  both findings are individually true, and the deletion is the
  better rewrite for that shape.
* Unlike the BR x30 canonicalization, this shape is genuinely
  present in compiler output: 37 instances across five of the six
  reference binaries (10 in ssh, 9 in gh, 8 in libcapstone, 5 each
  in zsh and sshd; ls has none). Every ssh instance is an
  unconditional `b .+4` (raw word 0x14000001, each byte-verified) --
  empty-basic-block and merged-tail artifacts the compilers never
  cleaned up.

## bitfield op via two shifts foldable into UBFX/SBFX or UBFIZ/SBFIZ

* `lsl wd, ws, #a ; lsr wd, wd, #b` folds depending on the
  relationship between `a` and `b`:
  * `b >= a`: extraction. `ubfx wd, ws, #(b-a), #(datasize-b)`.
    With `asr` it folds to `sbfx` (sign-extending).
  * `b < a`: insertion. `ubfiz wd, ws, #(a-b), #(datasize-a)` --
    places `ws[datasize-a-1 .. 0]` at `wd[datasize-b-1 .. a-b]` with
    bits below `a-b` zeroed. With `asr` it folds to `sbfiz`
    (sign-extending the high bits from `ws[datasize-a-1]`).
  * Same for X-form.
* Currently requires the consumer's `Rd` and `Rn` to equal the LSL's `Rd`
  so the shift result is dead after the rewrite.
* Fuse win (see the shift fold): two shifts become one bitfield op --
  one fewer instruction, second shift off the critical path.

## shift-and-mask bitfield extraction foldable into UBFX

* `lsr wd, ws, #n ; and wd, wd, #((1<<w)-1)` extracts bits
  `ws[n+w-1 .. n]`; equivalent to `ubfx wd, ws, #n, #w` (capping
  `w` at `datasize-n` when the mask is wider than the LSR-fillable
  bits). Same for X-form.
* Mask must be a contiguous run of low bits with no rotation
  (`immr=0` and `(N, imms)` encoding `S+1=w` ones at the
  appropriate element size); rotated/non-contiguous masks like
  `#0x6` are correctly skipped.
* Fuse win (see the shift fold): shift + mask become one `UBFX` --
  one fewer instruction, the mask off the critical path.

## mask-and-shift bitfield extraction foldable into UBFX

* The opposite ("mask then shift-right") order from the check above.
  `and wd, ws, #mask ; lsr wd, wd, #n` where `mask` is a single
  contiguous run of 1s `[lo, hi]`; the LSR reads and writes the AND's
  destination. The surviving bits are `ws[hi .. n]`, so the pair is
  equivalent to a single `ubfx wd, ws, #n, #(hi+1-n)`. Same for
  X-form. Examples: `and w0, w1, #0xff0 ; lsr w0, w0, #4`
  -> `ubfx w0, w1, #4, #8`; `and x0, x1, #0xffff00 ; lsr x0, x0, #8`
  -> `ubfx x0, x1, #8, #16`.
* Foldable only when `lo <= n <= hi`. `lo > n` would leave the field
  above bit 0 (e.g. `and w0,w1,#0xff00 ; lsr w0,w0,#4` keeps
  `w1[15:8]` at bits `[11:4]`, which has no single-UBFX form), and
  `n > hi` shifts the whole run out (a degenerate zero result). When
  `lo < n` the mask's low bits below the shift are simply dropped by
  the LSR, and the fold still holds (the extracted field is
  `ws[hi .. n]`).
* The mask is decoded to its concrete value (the AArch64
  `DecodeBitMasks` reconstruction) and accepted only as a single
  contiguous, non-wrapping run: replicated patterns (`esize < datasize`,
  e.g. `0x0f0f0f0f`) and rotated masks that wrap the top of the
  register leave a gap and are skipped. `ANDS` (flag-setting) is
  excluded -- dropping it would lose the NZCV write.
* Fuse win (see the shift fold): mask + shift become one `UBFX` --
  one fewer instruction, the shift off the critical path.

## mask-and-shift-left foldable into UBFIZ, or shift round-trip into a clearing AND

* The left-shift mirror of the two checks above (an `LSL`, rather than
  an `LSR`/`AND`, is the consumer):
  * `and wd, ws, #((1<<w)-1) ; lsl wd, wd, #n` keeps the low `w` bits
    and shifts them up by `n`; equivalent to `ubfiz wd, ws, #n, #w`
    (capping the width at `datasize-n` when `n+w` would overflow, since
    the high bits shift out). Example: `and w0, w1, #0xff ;
    lsl w0, w0, #4` -> `ubfiz w0, w1, #4, #8`.
  * A *zero-extension* keeps the same low field as that `AND`, so it
    folds identically (reported as "zero-extend + LSL foldable into
    UBFIZ"). The recognised producers are `uxtb`/`uxth`/`uxtw` (the
    UBFM aliases, `w` = 8/16/32) and the W-form `mov wd, ws`
    (`orr wd, wzr, ws`, which zero-extends the low 32 bits, `w` = 32).
    `uxtw` and the W-form `mov` establish a 32-bit field consumed by a
    *64-bit* `lsl`, so they fold into an `X`-form `ubfiz`; `uxtb`/`uxth`
    keep a 32-bit-register field consumed by a `W`-form `lsl`. Example:
    `mov w0, w0 ; lsl x0, x0, #2` -> `ubfiz x0, x0, #2, #32` (the
    .NET 7 idiom). The producer's result width must match the `lsl`
    and the emitted `ubfiz`, so a cross-width pair such as
    `uxtb w0, w1 ; lsl x0, x0, #4` is conservatively left unflagged.
  * `lsr wd, ws, #a ; lsl wd, wd, #a` (equal shifts) is a round-trip
    that clears the low `a` bits; equivalent to `and wd, ws, #~((1<<a)-1)`
    (the high mask is always a valid bitmask immediate). Example:
    `lsr w0, w1, #4 ; lsl w0, w0, #4` -> `and w0, w1, #0xfffffff0`.
* `LSR` + `LSL` with *unequal* shifts is not folded: the surviving
  field is neither low-aligned nor zero-aligned, so it has no single
  `UBFM`/`AND` form (the `LSL` + `LSR` order, by contrast, always folds
  -- see the two-shift check above). The `LSL` must read and write the
  producer's destination, and `ANDS` (flag-setting) is excluded by the
  low-mask decoder.
* Fuse win (see the shift fold): two instructions become one, with the
  shift/mask off the critical path.

## redundant zero-extension after a producer that already zeroed those bits

* Generalises the previous "redundant UXTW after W-form ALU" rule
  to size-aware producer/consumer pairs. The check tracks the
  threshold `P` at which the producer guarantees `Rt[63:P] == 0`;
  a consumer that clears bits above `C` is redundant when `P <= C`.
* Baseline thresholds: any W-form data-processing write gives
  `P = 32` (the W write zeros `X[63:32]` -- the producer set covers
  `ADD/SUB` immediate/shifted/extended, logical immediate,
  `MOVZ/MOVN/MOVK`, bitfield `SBFM/BFM/UBFM`, `EXTR`, logical
  shifted register, `ADC/SBC`, conditional select, DP-3/2/1-source),
  and the W-form integer loads (any addressing mode) give their
  access width: 8 for `LDRB Wt`, 16 for `LDRH Wt`, 32 for `LDR Wt` /
  `LDRSB Wt` / `LDRSH Wt`.
* Value-derived thresholds pin `P` tighter -- and, since they bound
  the whole 64-bit result, qualify X-form producers too:
  * `UBFM` (both forms), from the field geometry: an extraction
    (`imms >= immr` -- the `UBFX`/`LSR`/`UXTB`/`UXTH` shapes) leaves
    a field of `imms-immr+1` low bits, so `P` is that width
    (`lsr w8, w9, #24` gives `P = 8`); an insertion (`imms < immr`
    -- the `UBFIZ`/`LSL` shapes) tops out at
    `P = datasize-immr+imms+1`, so an `LSL` gets no sharpening
    (`P = datasize`).
  * `AND`/`ANDS` immediate (both forms): the result is a subset of
    the mask, so `P` = the mask's top set bit + 1
    (`and x0, x1, #0xff` gives `P = 8`). `ORR`/`EOR` propagate
    `Rn`'s high bits and keep only the generic W-form threshold.
  * `MOVZ` (both forms): the value is fully known, so `P` = its bit
    count (`movz w0, #0x12` gives `P = 5`).
  * `CSINC Rd, ZR, ZR, cond` (the `CSET` family): the result is 0
    or 1 regardless of the condition, so `P = 1`.
  An X-form producer whose computed `P` is 64 guarantees nothing
  and is skipped.
* Recognised consumers, each requiring `Rd == Rn == producer.Rd` so
  the consumer is purely dead:
  * an in-place `UBFM` with `immr = 0` of any width `C = imms+1` --
    the `UXTB`/`UXTH`/`UXTW` aliases and the general
    `UBFX Rd, Rd, #0, #C`; the full-width copies (`MOV Wd, Wn`
    at `imms = 31`, and the X-form no-op at `imms = 63`) clear
    nothing and are excluded;
  * an AND-imm whose mask is a contiguous run of `C` low bits (any
    width, e.g. `#0x1f` for `C = 5`), in W or X register variants;
  * `MOV Wd, Wd` (`ORR Wd, WZR, Wd` with `Rm = Rd`; the W-form
    register MOV writes back through the W register and so clears
    X[63:32], giving `C = 32`).
* Example flags: `add w0,w1,w2 ; uxtw x0,w0`; `ldrb w8,[x9] ; and
  w8,w8,#0xff`; `lsr w8,w9,#24 ; and w8,w8,#0xff` (`P = 8`);
  `ubfx w8,w9,#3,#4 ; uxtb w8,w8` (`P = 4`); `and x0,x1,#0xff ;
  uxtb w0,w0` (X-form producer); `cset w8,eq ; and w8,w8,#1`
  (`P = 1`). Counter-examples (not flagged): `ldr w0,[x1] ; uxth
  w0,w0` -- LDR W loads 32 valid bits, so UXTH would actually clear
  bits 31..16; `orr w0,w1,#0xf ; uxtb w0,w0` -- ORR can propagate
  high bits of `w1`.
* A sharpened threshold can make this check and a bitfield fold
  fire on the same pair: `lsr w8, w9, #24 ; and w8, w8, #0xff` is
  also the [`LSR+AND -> UBFX`](#shift-and-mask-bitfield-extraction-foldable-into-ubfx)
  shape with the width capped. The two findings offer equivalent
  one-instruction outcomes -- drop the dead AND, or fuse the pair
  -- and both are reported, like the CMP-drop/CBZ-fold overlap.

## `MOV Xd, Xd` is a literal no-op

* The X-form register MOV alias (`ORR Xd, XZR, Xm, LSL #0`) with
  `Rm = Rd` reads `Xd` and writes the same 64 bits back; the
  instruction has no architectural effect and can be removed. It shows
  up occasionally in hand-written assembly and in legacy object code.
* The W-form `MOV Wd, Wd` is NOT a no-op: writing through `Wd`
  clears `X[63:32]`. It is handled instead as a consumer of the
  redundant-zero-extension check above, where it fires only when a
  preceding producer already zeroed those bits.

## redundant sign-extension after a producer that already replicated the sign

* Mirror of the zero-extension framework above. The check tracks two
  thresholds `(S, W)`: the producer guarantees `Rd[W-1:S] =
  sign(Rd[S-1])`. A consumer `SXTB / SXTH / SXTW` with thresholds
  `(S_c, W_c)` is redundant iff `S_p <= S_c` AND `W_p == W_c` AND
  `Rd == Rn == producer.Rd`.
* Recognised producers: the sign-extending integer loads
  `LDRSB / LDRSH / LDRSW` in any addressing mode, and any `SBFM`,
  with `S` from the field geometry: an extraction (`imms >= immr`)
  leaves a field of `imms-immr+1` low bits and replicates its sign
  upward, so `S` is that width -- this covers the `SXTB`/`SXTH`/
  `SXTW` aliases (`immr = 0`, `S` = 8/16/32), `ASR Rd, Rn, #k`
  (`imms = datasize-1`, so `S = datasize-k`), and the general
  `SBFX Rd, Rn, #lsb, #w` (`S = w`); an insertion (`imms < immr`,
  the `SBFIZ` shape) places the field with its top at bit
  `datasize-immr+imms` and replicates from there, so `S` is one
  above that (`sbfiz w0, w1, #8, #8` gives `S = 16`). `S ==
  datasize` -- the full-width copy, or an `SBFIZ` whose field
  reaches the top bit -- leaves no sign-replicated region and is
  not a producer. `W = datasize` throughout. (S, W) maps for the
  canonical SXT* pairs: `LDRSB Wt` / `SXTB Wd,Wn` -> (8, 32);
  `LDRSH Wt` / `SXTH Wd,Wn` -> (16, 32); `LDRSB Xt` /
  `SXTB Xd,Wn` -> (8, 64); `LDRSH Xt` / `SXTH Xd,Wn` -> (16, 64);
  `LDRSW Xt` / `SXTW Xd,Wn` -> (32, 64). Example flagged pairs:
  `asr w0, w1, #24 ; sxtb w0, w0` (S_p=8 = S_c=8); `asr x0, x1,
  #48 ; sxth x0, w0`; `sbfx w0, w1, #4, #8 ; sxtb w0, w0` (the
  extracted byte's sign is already replicated).
* `W_p == W_c` (not `<=`) because a W-form consumer writes back
  through `Wd` and zeros `X[63:32]`, which differs from an X-form
  producer's sign-extended upper half. Example flagged: `ldrsb w0,
  [x1] ; sxtb w0, w0`; `ldrsh x0, [x1] ; sxth x0, w0`; `ldrsb w0,
  [x1] ; sxth w0, w0` (S_p=8 subsumes S_c=16 within W=32).
  Counter-example: `ldrsb w0, [x1] ; sxtb x0, w0` -- producer left
  `X[63:32] = 0`, consumer would set those bits to sign of byte;
  not redundant.
* Same producer state also feeds a "dead sign-extension" path: if
  the next instruction is a zero-ext consumer (`UXTB`/`UXTH`/`UXTW`
  or general in-place `UBFX #0`, `AND` with low-mask, or
  `MOV Wd, Wd`) that clears bits `>= C_c` with `C_c <= S_p`, the
  consumer overwrites every sign-extended bit and the producer can
  be deleted outright. No width-matching constraint is needed --
  when widths mismatch, the W-form auto-zero of `X[63:32]` covers
  the upper half. Example flagged: `sxtb w0, w0 ; uxtb w0, w0`
  (drop the `sxtb`); `sbfx w0, w0, #0, #5 ; and w0, w0, #0x1f`
  (drop the `sbfx`).
* The dead path only fires for an *in-place* sign-extension -- an
  `SBFM` with `immr = 0` (so the data stays in the low bits) and
  `Rn == Rd` (so the low bits are `Rd`'s own). Every other producer
  writes fresh data into the bits the consumer keeps, so deleting
  it would change the result:
  * `ASR`, `SBFX` with `lsb > 0`, and `SBFIZ` relocate the field --
    e.g. `asr w0, w1, #24 ; uxtb w0, w0` keeps `w1[31:24]`, whereas
    dropping the `ASR` would keep `w1[7:0]`.
  * An extend with `Rn != Rd` copies from `Rn`: `sxtb w0, w1 ;
    uxtb w0, w0` needs the re-sourcing rewrite `uxtb w0, w1`, not a
    deletion.
  * The sign-extending loads bring the value in from memory:
    `ldrsb w0, [x1] ; uxtb w0, w0` would need `ldrb w0, [x1]` --
    dropping the load loses the access.
  The last two shapes have valid one-instruction rewrites that
  re-source the consumer rather than delete the producer; armlint
  conservatively reports neither, and stays silent on all of these.

## self-op identities (`AND/ORR/EOR/SUB/BIC/ORN/EON Rd, Rs, Rs`)

* `AND Rd, Rs, Rs` and `ORR Rd, Rs, Rs` collapse to `MOV Rd, Rs`
  (identity). `EOR Rd, Rs, Rs`, `SUB Rd, Rs, Rs`, and `BIC Rd, Rs,
  Rs` (= `Rs AND NOT Rs`) collapse to `MOV Rd, XZR` (zero). `ORN
  Rd, Rs, Rs` (= `Rs OR NOT Rs`) and `EON Rd, Rs, Rs` (= `Rs XOR
  NOT Rs`) collapse to `MOV Rd, #-1` / `MOVN Rd, #0` (all-ones).
  Both W- and X-form.
* The flag-setting variants `ANDS Rd, Rs, Rs`, `SUBS Rd, Rs, Rs`,
  and `BICS Rd, Rs, Rs` are deliberately NOT flagged: writing `Rd`
  while setting flags is the user's intent (combined zero-test +
  register copy or register zero).
* `Rd = 31` (result discarded) and `Rn = 31` (`ZR` source, not a
  real self-op) are excluded.
* On uarches with move elimination, `MOV Rd, Rs` is zero-cycle
  while `AND/ORR Rd, Rs, Rs` goes through the ALU. `EOR Rd, Rs, Rs`
  is the canonical x86 zero idiom; the canonical AArch64 form is
  `MOV Rd, XZR`.

## vector self-op identity (`AND/ORR/EOR/SUB/BIC Vd, Vn, Vn`)

* The vector twin of the scalar self-op check above, on the ASIMD
  three-same forms whose two source registers are the same:

  ```
  eor v26.16b, v26.16b, v26.16b  ->  movi v26.2d, #0
  and v0.16b,  v1.16b,  v1.16b   ->  mov  v0.16b, v1.16b
  orr v0.16b,  v0.16b,  v0.16b   ->  delete
  ```

* `EOR`, `BIC` and `SUB` collapse to zero; `AND` and `ORR` give the
  operand back. `ORN` gives all-ones, which needs a different rewrite
  (a `MOVI` with a 0xFF immediate) and does not occur in the corpus, so
  it is decoded and declined rather than mis-reported. `BSL`/`BIT`/`BIF`
  share `EOR`'s U bit, separated by size, but read the destination as a
  third source -- a different shape.
* **One member must never be flagged.** `orr Vd, Vn, Vn` with
  `Rd != Rn` *is* the canonical spelling of the vector `MOV`: the
  assembler emits it for every `mov vd.16b, vn.16b`. Only its in-place
  form, writing a register its own value, is a finding. Counting the
  copies inflated a first pass over this shape from 353 to **2,158**,
  a 6x overcount.
* The `MOVI` rewrite uses a `2D` arrangement whatever the source's was.
  That is right for a `D`-form self-op too: every AArch64 SIMD
  instruction with a 64-bit arrangement zeroes the upper half of its
  destination, so the two are the same value.
* No liveness argument, and no side-entry question. The rewrite is
  1-for-1 into the same destination with the same value; nothing is
  deleted except in the in-place identity case, and no flags, memory or
  FP exceptions are involved. A branch landing on the instruction is
  harmless because the semantics do not change.
* **What it saves is issue, not size.** `MOVI` with a zero immediate is
  on Neoverse V2's "Zero Latency MOVs" list (SWOG section 4.12, whose
  members "do not utilize the scheduling and execution resources of the
  machine") and on Apple Firestorm's rename-eliminated set. The self-op
  is on neither: V2's tables charge the ASIMD logical group latency 2,
  throughput 4 on the V pipe, the same as a general `MOVI`, and the
  zero form is carved out of that cost while `eor Vn, Vn` is not. Every
  site in the corpus is in place, so the self-op also carries a false
  dependency on the register's own previous value. Neoverse N1's guide
  documents no such elimination at all -- its section 4 has no
  zero-latency list -- so this is "cheaper on newer cores, neutral on
  older", the same shape as
  [the low-32 fold](#low-32-zero-extension-foldable-to-mov-wd-wn).
* Corpus: **353** findings across 28.4M instructions (315 libcrypto, 28
  go, 10 dyld) -- exactly the swept population, because this candidate
  has neither an encodability condition nor a deadness gate to lose
  sites to. 351 are `eor Vd, Vd, Vd` and 2 are in-place `orr`; no
  `sub` or `and` self-op occurs. 315 of the 353 are in one function,
  OpenSSL's `_asm_aescbc_sha1_hmac`, where they zero accumulators four
  at a time inside the stitched AES-CBC + SHA1-HMAC loop.

## ZR-operand ALU spelling (`AND/ORR/EOR/BIC/ORN/EON/ADD/SUB/MUL Rd, Rn, ZR`)

* An ALU instruction whose **Rm** operand is the zero register
  collapses, because one input is a known constant:

  ```
  orr w0, w1, wzr  ->  mov w0, w1        add / sub / eor / bic likewise
  and w0, w1, wzr  ->  mov w0, wzr       mul likewise
  orn w0, w1, wzr  ->  mov w0, #-1
  eon w0, w1, wzr  ->  mvn w0, w1
  ```

* **Rm is the deliberate side, and it is what keeps the alias table
  out.** Every canonical degenerate spelling puts ZR in *Rn*: `mov Rd,
  Rm` is `orr Rd, ZR, Rm`, `neg Rd, Rm` is `sub Rd, ZR, Rm`, `mvn Rd,
  Rm` is `orn Rd, ZR, Rm`. Those are the assembler's own output for
  three of the most common instructions in any binary, and reporting
  them would be nonsense. Requiring `Rm = 31` with `Rn != 31` excludes
  all of them without enumerating a single alias.
* `Rd = 31` is excluded too: that instruction writes nothing and
  belongs to the dead-ZR-destination candidate, which the corpus
  measures at zero.
* The **S-variants are excluded** (`ANDS`/`BICS`/`ADDS`/`SUBS`). Their
  flag write is a second result the rewrite would drop, which is the
  dead-flag candidate's question, not this one. The first version of
  the ADD/SUB mask left the S bit free and reported three `adds` in go,
  taking the corpus figure to 95 against a swept 90 -- the discrepancy
  is what found the bug.
* Only the unshifted forms are matched. A shifted ZR is still zero, so
  `orr w0, w1, wzr, lsl #3` would fold identically; admitting it would
  make the reported figure diverge from the swept population for no
  new shape. Recorded rather than done.
* No liveness argument and no side entry, like the two self-op checks:
  1-for-1 into the same destination with the same value, no flags, no
  memory.
* Corpus: **90** findings across 28.4M instructions, every one in
  librustc_driver -- exactly the swept population. By operation: 67
  `orr`, 14 `and`, 7 `add`, 2 `sub`. No `mul`, `bic`, `orn` or `eon`
  site occurs, so four of the nine decoded members are carried on the
  strength of the encoding rather than of the corpus.

## adjacent LDR/STR foldable into LDP/STP

* Two `LDR Wt, [Rn, #imm]` (or X-form) to consecutive offsets fold
  into a single `LDP Wt1, Wt2, [Rn, #imm7*4]`. Analogous for stores ->
  `STP`. Both W- and X-form supported, and the SIMD&FP S/D/Q sizes
  (scales 4/8/16) coalesce the same way into their own `LDP`/`STP`
  forms -- the FP B and H sizes have no pair encoding and are not
  flagged. Load+load and store+store only; no mixing of direction,
  size, or register file.
* Why it helps: one paired access replaces two single ones -- halving
  the load/store instruction count (decode/issue slots, code size) and,
  on most cores, the number of memory micro-ops. This is the inverse of
  the LDP-with-writeback caveat noted for the post-index fold: the plain
  pair forms are a win, whereas pairing *with* writeback can cost extra
  micro-ops on Apple cores.
* Both spellings of the addressing mode are decoded: the
  unsigned-offset form (`LDR`, imm12 scaled by the access size) and
  the unscaled one (`LDUR`, a signed 9-bit byte count). Assemblers
  choose per instruction -- JSC's arm64 MacroAssembler, for one, emits
  `LDUR` for every displacement under 256 -- so a single run of
  accesses routinely comes out as a mix, and matching only the scaled
  form misses both the all-unscaled runs and the mixed pairs. Offsets
  are therefore normalized to signed bytes before comparison, and a
  pair fires whichever way each half is spelled.
* Because the unscaled form can express displacements the pair form
  cannot, the imm7 test is explicit rather than implied by the
  encoding: the lower of the two byte offsets must divide evenly by
  the transfer size and lie within -64..63 of them. The alignment half
  of that is what the scaled imm12 used to guarantee for free, and it
  is what keeps the rewrite off addresses where `LDP`/`STP` has
  implementation-defined behaviour on AArch64 (some cores fault even
  where a single `LDR`/`STR` works under `SCTLR_EL1.A = 0`).
* Pre- and post-indexed forms remain deferred: they write back to the
  base, so they are not interchangeable with a plain pair.
* Constraints checked: same base register `Rn`; same access size
  (both W, both X, or the same S/D/Q); same direction (load/load or
  store/store); consecutive offsets (`imm12_2 = imm12_1 + 1` in
  scaled units); `Rt1 != Rt2` for LOADS only -- `LDP`/`LDPSW` with
  `Rt1 == Rt2` is CONSTRAINED UNPREDICTABLE, but stores have no such
  restriction, so a repeated source pairs fine
  (`str x5, [sp] ; str x5, [sp, #8]` -> `stp x5, x5, [sp]`); for
  integer loads, the first instruction's
  `Rt != Rn` (else the first load clobbers the base before the
  second load reads it) -- a SIMD&FP `Rt` can never alias the
  integer base, so that guard does not apply to FP pairs. The LOWER
  of the two byte offsets must also be a multiple of the transfer size
  and fit LDP's signed 7-bit imm7 in units of it.
* Reverse-order pairs (`ldr Rt2, [Rn, #imm+1] ; ldr Rt1, [Rn,
  #imm]` -- higher offset first) are also coalesced, into a
  `ldp Rt1, Rt2, [Rn, #imm]` with the Rt operands ordered by
  ascending address. The load-aliasing concern is about source
  order, not address order, so the constraint is on the FIRST
  instruction in source order regardless of which offset it
  targets.
* Four consecutive LDR/STRs fold into TWO non-overlapping
  LDP/STPs (after firing, the state resets so the second LDR
  isn't also used as the first of a new pair).
* Atomicity caveat: a single LDP is NOT atomic across its two
  halves (AArch64 doesn't guarantee single-copy atomicity for
  pairs), but neither are two separate LDRs. So the rewrite
  doesn't change ordering or atomicity guarantees -- acquire /
  release variants use different opcodes.
* Adjacent `LDRSW Xt, [Rn, #imm]` pairs (`LDURSW` included) fold
  analogously into a single `LDPSW Xt1, Xt2, [Rn, #imm7*4]`. Same
  constraints (same base, consecutive offsets, distinct Rts, first
  `Rt != Rn`, lower offset within a 4-byte-scaled imm7), with the
  added requirement that
  the kind matches: a pending `LDR` does not pair with an `LDRSW`
  (different opcode, different sign-extension semantics). LDPSW is
  always 64-bit destination, load-only, 4-byte transfer.

## adjacent zero stores foldable into STR xzr

* Two consecutive W-form stores of the zero register --
  `STR WZR, [Rn, #imm12*4] ; STR WZR, [Rn, #(imm12+1)*4]` -- write the
  same eight bytes as a single `STR XZR`. This is a refinement of the
  LDP/STP coalescer above: rather than the `STP WZR, WZR` a generic
  pair fold would emit, both sources being the zero register let one
  wider store replace the pair outright.
* Why it helps: a single 8-byte store replaces two 4-byte stores --
  one fewer instruction (decode/issue slot, code size) and one fewer
  store micro-op.
* When the combined 8-byte offset is a non-negative multiple of 8 the
  rewrite is the scaled `STR XZR, [Rn, #off]`; an odd 4-byte slot
  (`off % 8 == 4`) is not encodable in the scaled form and is reported
  as the unscaled `STUR XZR, [Rn, #off]`. The source offsets are bounded
  by the coalescer's imm7 gate (lower imm12 <= 63), so the byte offset
  is in [0, 252] -- in range for whichever form applies.
* Only the W-form collapses. Two X-form zero stores span sixteen bytes,
  which has no single-GPR-store equivalent (`STP XZR, XZR` is already
  the canonical 16-byte zero store); they are left to the ordinary pair
  logic. Reverse order (higher offset first) folds the same way.
* A mixed pair, where only one source is the zero register, is not a
  candidate for the single store and coalesces into an ordinary `STP`
  -- now with the zero operand correctly rendered as `wzr` rather than
  the non-assemblable `w31`.

## STP wzr, wzr foldable into STR xzr

* A standalone `STP WZR, WZR, [Rn, #imm7*4]` (W-form, signed offset, no
  writeback) zeroes eight contiguous bytes -- exactly what a single
  `STR XZR` does -- but as a store-pair operation. Replacing it with the
  single store drops a micro-op on cores that crack the pair, with no
  change in architectural effect.
* Like the two-store consolidation above, the rewrite is the scaled
  `STR XZR` when the byte offset is a non-negative multiple of 8 and the
  unscaled `STUR XZR` otherwise (an odd 4-byte slot or a negative
  offset). The W-form imm7 yields byte offsets in [-256, 252], all in
  range for whichever form applies.
* Only the 32-bit pair collapses. `STP XZR, XZR` zeroes sixteen bytes
  and has no single-GPR-store form; it is the canonical 16-byte zero
  store and is left alone.
* Soundness: the match is by encoding, requiring `opc = 00` (W-form),
  the signed-offset addressing mode (no writeback), and `L = 0` (store),
  with both transfer registers = 31. Pre- and post-indexed writeback
  forms additionally update `Rn`, so they are NOT equivalent to a plain
  `STR` and are excluded by the addressing-mode bits; `STNP`
  (non-temporal) and the load (`LDP`) likewise do not match.

## BFXIL and BFI bitfield-insert synthesis

* The "clear a field, isolate the same field from a source, OR the two
  together" idiom collapses to a single bitfield-insert. With the field
  at the low end it is `BFXIL`; at an arbitrary position `lsb` it is
  `BFI`:
  * `AND Rd, Rd, #~mask ; AND Rt, Rs, #mask ; ORR Rd, Rd, Rt`
    -> `BFXIL Rd, Rs, #0, #w` (with `mask = (1<<w)-1`)
  * `AND Rd, Rd, #~(mask<<lsb) ; UBFIZ Rt, Rs, #lsb, #w ; ORR Rd, Rd, Rt`
    -> `BFI Rd, Rs, #lsb, #w`
  The clear and isolate may appear in either order, and the ORR's
  second-and-third operands in either order. Both W- and X-form. The
  check detects the 3-instruction window with strict adjacency.
* The clear is an in-place AND (`Rd == Rn`) whose mask, reconstructed to
  its concrete value, zeros a single contiguous run of `w` bits at
  position `lsb`; rotated or split masks have no single-field form and
  are rejected. The isolate is either a low-mask `AND Rt, Rs, #mask`
  (`lsb == 0`) or a `UBFIZ Rt, Rs, #lsb, #w` (`lsb > 0`); when the field
  reaches the top of the register the UBFIZ encodes identically to `LSL`
  and is matched the same way. The ORR is logical-shifted-register with
  LSL #0.
* Clear and isolate are told apart by whether the AND writes in place: a
  clear is always `AND Rd, Rd, ...`, while a sound isolate writes a
  separate temp. This matters because an in-place low-mask AND -- e.g.
  one clearing a field that reaches the top bit -- matches both shapes;
  `Rd == Rn` fixes the role.
* Aliasing constraints needed for the rewrite to be semantically
  equivalent: `Rt != clear.Rd` (else the isolate clobbers the cleared
  register in place), `Rt != Rs` (else the isolate modifies the source --
  the insert leaves `Rs` unchanged), and `Rs != clear.Rd` (the
  degenerate case where `Rs` is the just-cleared register yields the
  wrong result -- the original sequence zeros the field, but `BFI Rd, Rd,
  ...` would re-read it).
* Useful for hand-written assembly and legacy object code.

## Zeroing MOVI then vector compare foldable to compare-with-zero

* The AArch64 SIMD compares have a register form (`CMEQ`/`CMGE`/`CMGT Vd,
  Vn, Vm`, and the FP `FCMEQ`/`FCMGE`/`FCMGT`) and a compare-against-zero
  form (`CMEQ`/`CMGE`/`CMGT`/`CMLE`/`CMLT Vd, Vn, #0`, FP `... #0.0`). A
  `MOVI Vz, #0` that materializes an all-zero vector, immediately consumed
  by a register compare against `Vz`, is the zero form spelled in two
  instructions.
* The fold drops the `MOVI` and rewrites the compare to the `#0` form:
  * `movi v16.4s, #0 ; cmeq v16.4s, v16.4s, v0.4s` ->
    `cmeq v16.4s, v0.4s, #0`.
  * `CMEQ`/`FCMEQ` are symmetric, so the zero may sit in either source.
    The ordered compares are not: a zero *left* operand flips the sense,
    because `0 >= X` is `X <= 0` and `0 > X` is `X < 0`. So `cmge Vd, Vz,
    X` becomes `cmle Vd, X, #0` and `cmgt Vd, Vz, X` becomes `cmlt Vd, X,
    #0` (likewise `fcmle`/`fcmlt`); a zero *right* operand keeps the
    mnemonic (`cmge`/`cmgt`/`fcmge`/`fcmgt ..., #0`).
* Soundness rests on structural liveness: the fold fires only when the
  compare overwrites the zero register (`Vd == Vz`), proving the
  materialized zero is dead. The common compiler output -- a throwaway
  zero temp that the compare reuses as its destination -- has exactly this
  shape. A compare that writes a *different* register leaves the zero
  potentially live, so removing the `MOVI` would need a register-liveness
  pass; that case is left un-flagged.
* The producer's arrangement is irrelevant: any zeroing `MOVI` clears all
  128 bits (a 64-bit form zeros the upper half too), so `movi v3.8b, #0`
  feeds a `.16b` compare as well as a matching `.4s` zero does. Only a
  `MOVI` (including `MOVI Vd.2D`) with an all-zero immediate qualifies;
  `MVNI`, a non-zero immediate, and the MSL ones-filling `cmode`s yield
  non-zero vectors and are excluded.
* Not matched: the unsigned compares (`CMHI`/`CMHS`) and the bitwise
  `CMTST` have no direct compare-with-`#0` equivalent (e.g. `CMHI Vd, X,
  Z` is `X != 0`, which the `#0` forms cannot express), and the absolute
  FP compares (`FACGE`/`FACGT`) and the half-precision compares are
  likewise left alone.
* Saves an instruction and frees a register: the zero vector no longer
  needs to be materialized or to occupy a register.

## CSEL same-operand identity (`CSEL Rd, Rn, Rn, cond`)

* When the CSEL's `Rn == Rm`, both branches produce `Rn`, so the
  cond is irrelevant and the instruction is equivalent to `MOV Rd,
  Rn`. The CSEL also reads NZCV for no reason. Both W- and X-form.
* Only `CSEL` (op2 = 00) is flagged. The other members of the
  conditional-select family -- `CSINC`, `CSINV`, `CSNEG` -- have
  different "else" branches (Rn+1, ~Rn, -Rn) and are NOT identities
  when `Rn == Rm`. The decoder enforces `(op & 0x7FE00C00) ==
  0x1A800000`, which fixes op2 = 00.
* `Rd = 31` (result discarded) and `Rn = 31` (`ZR` source) are
  excluded for consistency with the other self-op identity check.

## FCSEL same-operand identity (`FCSEL Vd, Vn, Vn, cond`)

* The FP mirror of the check above: `FCSEL` is a pure bit-pattern
  select -- no arithmetic, no NaN processing -- so `Vn == Vm` makes
  the condition irrelevant and the instruction a register copy,
  `fmov Vd, Vn`. Both `FCSEL` and `FMOV (register)` zero the vector
  register above the written lane, so the rewrite is exact for the
  full 128 bits; the pointless NZCV read disappears too, freeing the
  select from its flags dependency.
* Single and double precision only; half precision (FEAT_FP16) is
  not matched, consistent with the other FP checks. FP registers
  have no ZR/SP encoding, so no operand exclusions apply -- even the
  fully self-referential `fcsel d0, d0, d0, cc` folds (to
  `fmov d0, d0`, which is not a no-op: both spellings rewrite the
  lane and zero above it).

## ADD/SUB #0 is redundant

* The non-flag-setting `ADD Rd, Rn, #0` or `SUB Rd, Rn, #0` is a
  no-op when `Rd == Rn` and is equivalent to `MOV Rd, Rn` when
  `Rd != Rn`. The explicit `ADD #0` shows up occasionally in real
  code, notably as a way to set up a function argument from a
  callee-saved register.
* The `ADDS`/`SUBS` flag-setting variants are not flagged: writing
  `Rd` and setting `Z = (Rn == 0)` may both be wanted. The SP
  encoding (`Rd = 31` or `Rn = 31`) is also excluded because that's
  the canonical `MOV (to/from SP)` alias and the only way to spell
  `MOV X0, SP` / `MOV SP, X0`.
* The `Rd == Rn` case is further suppressed when immediately
  preceded by `ADR`/`ADRP` with the same `Rd`: that's a
  page-relative addressing pair (`adrp x8, page ; add x8, x8,
  #pageoff`) where the linker happened to resolve `pageoff` to 0.
  Removing the `ADD` requires re-linking, not an assembler rewrite,
  so it's not actionable.

## ADD/SUB immediate chain foldable to one

* Two adjacent non-flag-setting `ADD`/`SUB` immediates adjusting the
  same register are one instruction's worth of arithmetic:
  * `add x11, sp, #0x130 ; add x11, x11, #0x81` -> `add x11, sp, #0x1b1`
  * `sub x8, x29, #0x100 ; add x8, x8, #0x30` -> `sub x8, x29, #0xd0`
  ("ADD/SUB immediate chain foldable to one"). The kinds mix freely:
  each instruction contributes a signed amount, and the fold renders
  whichever of `ADD`/`SUB` carries the sum -- or `MOV` when the two
  cancel exactly.
* **The sum must encode.** `ADD`/`SUB` immediate is a 12-bit unsigned
  field, optionally shifted left by 12; the two ranges do not overlap
  above 4095, since the shifted form reaches only multiples of 4096.
  That single gate is also what keeps the compiler's own split of a
  wide constant unflagged, with no special case for it: `add x8, x8,
  #0x1, lsl #12 ; add x8, x8, #0x20` sums to 0x1020, which is neither
  an imm12 nor a multiple of 4096, so the already-minimal pair fails
  the test.
* **Widths must agree.** A W-form producer zero-extends its 32-bit sum
  into the full register before an X-form consumer reads it, which
  64-bit arithmetic on the original source does not reproduce.
* **Both instructions must be non-flag-setting.** An `ADDS`/`SUBS`
  producer cannot be deleted without losing its NZCV write. An
  `ADDS`/`SUBS` *consumer* is excluded for a subtler reason: the
  folded instruction computes the same result but not the same flags,
  because C and V depend on the intermediate the fold erases. With
  `x9 = -1`, `add x8, x9, #1 ; adds x0, x8, #1` leaves C = 0 where
  `adds x0, x9, #2` leaves C = 1.
* Soundness otherwise: the rewrite deletes the producer, so its
  destination must be dead afterward. A consumer writing that same
  register kills it structurally and emits on the spot -- the dominant
  shape; a fresh destination defers through the forward
  register-liveness scan. A producer whose destination is SP (`Rd` =
  31 in this encoding) never opens: the stack pointer is never dead,
  because an asynchronous signal delivered between the two
  instructions observes the intermediate value. A zero adjustment on
  either side is not a chain but a redundant instruction, left to
  [`ADD/SUB #0 is redundant`](#addsub-0-is-redundant) so no window is
  reported twice.
* **Where the shape comes from.** Two unrelated LLVM behaviours
  produce it in roughly equal measure. Classifying librustc_driver's
  26,929 findings by what feeds the opening instruction: 13,607
  (50.6%) are global-address arithmetic, where the open is the `add`
  of an `adrp`/`add` page pair; 12,875 (47.8%) are stack-address
  arithmetic, where the open is `sp`- or frame-pointer-relative; 447
  (1.6%) are neither.
* **The stack half is instruction selection.** A bare `ISD::FrameIndex`
  is selected to `ADDXri <FI>, 0` with a hardcoded zero immediate (the
  `ISD::FrameIndex` case in `AArch64DAGToDAGISel::Select`), so an
  interior pointer into an alloca that escapes becomes two
  instructions before frame layout is even considered:

      %0:gpr64sp = ADDXri %stack.0.a, 0, 0
      %1:gpr64sp = nuw ADDXri killed %0, 8, 0

  which resolves to `add x8, sp, #0x320 ; add x8, x8, #0x8`. The
  offset was never expensive: `rewriteAArch64FrameIndex()` already
  adds whatever immediate an `ADDXri` carries to the resolved frame
  offset, so selection could have put the constant there and simply
  did not. Memory operands escape the shape because
  `SelectAddrModeIndexed` folds `FrameIndex + offset` into the
  addressing mode -- the same address used by a load is one
  `ldr x0, [sp, #0x328]` -- which is why the shape marks *escaping*
  interior pointers specifically. Nothing downstream repairs it:
  `LocalStackSlotAllocation` leaves the pair untouched, and
  `AArch64MIPeepholeOpt` coalesces `ADDXrr` but not `ADDXri` chains.
* **The global half is a declined relocation fold.**
  `performGlobalAddressCombine` in `AArch64ISelLowering.cpp` normally
  folds a constant offset into the symbol's relocation addend, giving
  `adrp x8, sym@PAGE+16 ; add x8, x8, sym@PAGEOFF+16`. It declines in
  three cases, and each declined fold leaves a third instruction
  behind: when the offset runs past the object's size
  (`Offset > getTypeAllocSize`), the dominant shape here; when the
  same global is also used at a smaller offset, which trips its
  "require that the new offset is larger" guard; and when the offset
  is negative, which it skips with the comment that those "aren't
  really common enough to matter" -- borne out here, where only 50 of
  the 13,607 global chains close with a `sub`.
* **The two halves are not equally actionable.** The stack half is a
  plain missed optimization -- the constant is available at selection
  and the frame-index rewrite already accepts it. Folding it there
  removes 3,893 of 3,893 chains from the 25 largest translation units
  of an LLVM+clang build, and 0.35% of all instructions emitted, with
  no translation unit getting larger. That corpus is all stack family:
  measured on unlinked objects, where `add xN, xN, @PAGEOFF` still
  carries a zero immediate awaiting relocation, so the open half of a
  global chain does not yet exist. The global half is a *relink*-level
  observation, for the same reason as the `adrp`+`add` note under
  [`ADD/SUB #0 is redundant`](#addsub-0-is-redundant): armlint reads
  the linked image, where `pageoff` is resolved and it can check that
  `pageoff + K` still encodes, but the compiler emitting the
  relocation cannot prove that statically. Both halves are sound
  rewrites of the binary in hand, which is what the check reports.
* The stack half explains the distribution. The check reports 26,929
  findings in `librustc_driver` (26.0M instructions) against 37 in
  dyld, 11 in go, 11 in libcrypto, 5 in ssh and 4 in bash -- 1,037 per
  million instructions against 229, 44 and 34 for the C and C++
  binaries. rustc's frames are large and full of interior pointers --
  enum payloads, iterator and future state, `&mut` borrows into locals
  -- and every one that escapes to a call rather than being loaded
  through pays the extra `add`. The corpus has no large C program,
  though, so that ratio mixes language with program size. The second
  immediate is a field offset in both halves: median 16 bytes, 98.6%
  under 256.
* Verification: `tools/shapescan.py` independently identifies 46,115
  candidate chains in `librustc_driver`; armlint reports a strict
  subset of them, with no finding outside that set, the remainder
  suppressed by the side-entry gate or an unproven liveness scan. A
  random 400 of the reported folds were assembled and executed against
  their original pairs over 5,000 random register states each: every
  suggestion computes the identical value.

## redundant zero-CMP/TST after a flag-setting ALU

* `adds/subs/ands/bics/adcs/sbcs Rd, ... ; cmp Rd, #0 ; b.eq/b.ne L`
  -- the S-variant ALU already set `Z = (Rd == 0)`, so the `CMP/TST`
  is recomputing the same `Z`. The `B.EQ/B.NE` can read the
  S-variant's flags directly; the `CMP/TST` is dead.
* Currently requires the full three-instruction window: S-variant
  immediately followed by `CMP Rd, #0` / `CMP Rd, ZR` / `TST Rd, Rd`,
  immediately followed by `B.EQ`/`B.NE`. The same forward
  NZCV-liveness scan as the CMP+B.cond check confirms that
  downstream code does not observe N/C/V (which the S-variant sets
  differently from the `CMP`).
* Combines with the CMP+B.cond -> CBZ/CBNZ check above: both fire
  on the matching pattern, giving the user a choice between
  dropping the `CMP` (and keeping the `B.cond`) or folding the
  `CMP`+`B.cond` pair into a `CBZ`/`CBNZ`. Both rewrites have
  identical downstream behaviour.

## ADD/SUB/AND/BIC + zero-CMP foldable to S-variant

* The mirror of the check above, one S bit over: when the producer
  does NOT set flags but has a flag-setting twin, converting it makes
  the zero test droppable --
  `add w0, w1, w2 ; cmp w0, #0 ; b.eq L` ->
  `adds w0, w1, w2 ; b.eq L`. Producers: `ADD`/`SUB` (immediate,
  shifted-register, extended-register) and `AND`/`BIC` (immediate for
  `AND`, shifted-register for both) -- every form spells its
  S-variant as the mnemonic plus "s", including the `NEG` alias
  (`SUB` from ZR), whose twin is `NEGS`. `ORR`/`EOR` have no S-forms
  and never match.
* Flag argument: `Z` is bit-identical (`Rd == 0` computed either
  way), and so is `N` (the sign of `Rd` under every zero-test
  spelling). `C` and `V` differ -- `CMP Rd, #0` pins `C = 1`,
  `V = 0`, the `CMN`/`TST` spellings pin `C = 0`, `V = 0`, while the
  arithmetic S-variants compute the operation's real carry and
  overflow. The `B.EQ`/`B.NE` itself reads only `Z`; emission defers
  through the same forward NZCV-liveness scan as the sibling check
  (in a dedicated pending slot) until any later N/C/V read is ruled
  out -- conservative for `N`, which actually agrees. The logical
  S-forms pin `C = V = 0` exactly like `TST`, so `ANDS`/`BICS` after
  a `TST` consumer is flag-exact; the scan is applied uniformly
  anyway.
* Exclusions: `Rd = 31` producers (SP for the immediate and extended
  forms -- an observable write the S-variant would redirect to ZR --
  and a dead ZR write for the shifted ones); `ADD`/`SUB` immediate
  with `imm == 0` (the redundant-ADD/`MOV`-from-SP shapes owned by
  the ADD/SUB #0 check, whose `mov` alias spelling must not gain an
  "s"); and `ADC`/`SBC`, whose S twins exist but which read the very
  carry the surrounding code is testing -- left to a future
  extension. Width (W vs X) of the zero test must match the
  producer's.
* Same three-instruction window as the sibling, and the same
  interplay: the CMP+B.cond -> CBZ/CBNZ fold also fires on the
  matching pair, so the user chooses between converting the ALU (and
  dropping the `CMP`) or folding `CMP`+`B.cond` into a `CBZ`/`CBNZ`.
* What it saves: one instruction -- the zero test -- and its NZCV
  def-use disappears into the ALU op the code already executes. The
  shape is common in hand-written assembly and naive codegen, which
  compute a value and then test it in two steps.

## SUB + CMP of identical operands foldable to SUBS

* `sub wd, wn, wm ; cmp wn, wm` -> `subs wd, wn, wm`, and the same
  with the pair in the other order (`cmp wn, wm ; sub wd, wn, wm`).
  `CMP Rn, Rm` is `SUBS ZR, Rn, Rm` -- the identical subtraction --
  and NZCV is a function of the operands only, never Rd, so the
  folded `SUBS`'s flags are bit-identical to the `CMP`'s in all four
  bits. Unlike the zero-CMP fold above, whose C/V diverge, no
  flag-liveness scan is needed: downstream may read any condition,
  and the finding emits at the pair.
* The operand match is by encoding: the `CMP` must be exactly the
  `SUB`'s word with the S bit set and `Rd = 31`. One comparison
  therefore covers the immediate, shifted-register and
  extended-register forms and enforces equal widths, shift
  types/amounts and extend options; the reversed compare
  (`cmp wm, wn`) never matches, since subtraction is not symmetric.
* In the SUB-first order the `CMP` runs after the `SUB` wrote `Rd`,
  so `Rd` must not be one of the compared registers -- there the
  `CMP` read the difference, and the folded `SUBS` would compare
  pre-`SUB` values. The CMP-first order writes nothing before the
  `SUB` and needs no such restriction (`cmp x1, x2 ; sub x1, x1, x2`
  folds). `Rd = 31` producers are excluded: SP for the immediate and
  extended forms -- `SUBS`'s `Rd = 31` is ZR, so the fold would drop
  an observable SP update -- and a dead ZR write for the shifted
  form. An immediate of 0 is excluded across the family: the pair is
  degenerate (the ADD/SUB #0 check's shapes), and the `ADD` side's
  MOV-from-SP alias spelling must not gain an "s". The S-variant
  spelling is the ALU's mnemonic plus "s" (`NEGS` for the `NEG`
  alias). A compare that closes an ALU-first pair still opens a
  compare-first pending, so `sub ; cmp ; sub` chains report both
  folds.
* The `ADD` + `CMN` family folds by the identical argument -- `CMN
  Rn, Rm` is `ADDS ZR, Rn, Rm`, the same addition -- and is reported
  as "ADD + CMN of identical operands foldable to ADDS":
  `add x0, x1, x2 ; cmn x1, x2` -> `adds x0, x1, x2`, either order.
  The word match pairs families automatically (an `ADD`'s compare
  spelling is `CMN`, a `SUB`'s is `CMP`; `ADD` + `CMP` never
  matches). `ADD` commutes, so a *swapped* compare
  (`add x0, x1, x2 ; cmn x2, x1`, in either order) also folds for the
  plain unshifted register form: the CMN sums the same values, so all
  four NZCV bits match. Only that form swaps -- a nonzero shift
  amount breaks the symmetry (`Rn + (Rm << s) != Rm + (Rn << s)`),
  the immediate form has no second register, the extended form
  applies its extension to Rm only, and subtraction does not commute
  at all (`cmp x2, x1` after `sub x0, x1, x2` never folds).
* What it saves: one instruction -- the compare -- with zero flag
  risk. The shape appears when code computes a difference and
  separately compares the same operands: hand-written bounds checks
  and naive codegen; optimizing compilers emit the `SUBS` directly.

## SUBS/ADDS + CMP/CMN of identical operands: redundant compare

* The S-producer sibling of the fold above: when the ALU is ALREADY
  flag-setting, the adjacent compare of its own operands recomputes
  the NZCV the producer just set --
  `subs x0, x1, x2 ; cmp x1, x2` -> drop the `cmp` (same for
  `ADDS` + `CMN`, including the swapped-operand `CMN` for the plain
  unshifted form, by the same commutativity argument). Nothing else
  is rewritten -- no mnemonic gains an "s" -- so even the `imm = 0`
  spellings need no exclusion here.
* A producer with `Rd = 31` is itself a compare, so adjacent
  duplicate compares (`cmp x3, x4 ; cmp x3, x4`) report under the
  same check. Chains report per pair: a compare that just closed one
  pair opens the next.
* The compare must not read the producer's destination (`Rd` among
  the compared registers reads the result, not the original
  operand). Distinct from the
  [redundant `CMP` after S-variant](#redundant-cmp-after-s-variant)
  check, which flags the compare of the RESULT against zero; this
  one flags the compare of the operands, and it needs no NZCV scan:
  the flags after the drop are bit-identical, unconditionally.

## compare whose flags are overwritten unread

* A compare writes no register: `CMP`/`CMN` are `ADDS`/`SUBS`
  discarding into the zero register, `TST` is `ANDS` doing the same,
  and `CCMP`/`CCMN` have no destination field at all. So a compare
  whose NZCV nothing reads before some later instruction rewrites all
  four flags has no effect whatever, and the rewrite is a deletion:
  `cmp w9, #8 ; cmp w9, #6` -> drop the first.
* This is the one member of the dead-flag family worth reporting.
  Dropping the `s` off an `adds`/`subs`/`ands` whose destination is
  still live is the same instruction count, the same encoding size and
  the same latency and port on every AArch64 core -- the flag write
  itself is a byproduct of the adder and costs a rename slot, not a
  cycle. Deleting a compare returns a whole instruction slot: a fetch
  slot, a decode slot, a ROB entry. The energy is in the instruction,
  not in the flags it wrote.
* The deadness proof accepts exactly one stopper, a later full write
  of NZCV (`LIV_OVERWRITE`). The shared advancer
  (`armlint_advance_pending`) would also accept a call or a return,
  because the PCS leaves the condition flags undefined across both --
  LLVM states that rule in as many words, and its machine outliner
  leans on it, outlining only ranges where NZCV is dead, which is why
  the tail of an `_OUTLINED_FUNCTION_*` is a place these turn up. But
  that is an argument about a callee rather than about code in front
  of the scanner, and hand-written assembly is free to ignore it: a
  context restore ending `msr nzcv, x8 ; ret` reads perfectly dead to
  a PCS-trusting scan. Deleting an instruction is not where that
  argument gets spent, so `armlint_advance_pending_dc` refuses both
  terminators. The corpus figures below are for the overwrite arm
  alone.
* No side-entry gate, despite the window spanning several
  instructions. Only the head is deleted and nothing else in the
  window changes, so a path entering in the middle never executed the
  compare and cannot observe flags it did not write. The finding is
  one instruction wide and is reported that way. This is why armlint
  reports more sites than the standalone survey that motivated the
  check: that survey abandoned a candidate whenever a branch target
  fell inside the window, a caution the deletion does not need.
* `FCMP`/`FCMPE` and `FCCMP`/`FCCMPE` are excluded even though they
  are equally destination-free. They also set the FPSR cumulative
  exception bits, and with the matching FPCR trap enabled may trap on
  a NaN, so deleting one drops architectural state an NZCV scan cannot
  see. They still count as killers -- an `fcmp` does overwrite all
  four flags -- just never as the deleted instruction. `ADCS`/`SBCS`
  into the zero register are omitted for population rather than
  soundness: the corpus has none.
* Overlaps [`SUBS`/`ADDS` + `CMP`/`CMN` of identical
  operands](#subsadds--cmpcmn-of-identical-operands-redundant-compare)
  on exactly one shape, an adjacent pair of identical compares, where
  that check calls the second redundant and this one calls the first
  dead. Both rewrites are correct and both fire; the corpus contains
  no such pair.
* **Corpus: 315 sites** across the 28.5M-instruction sweep -- 306 in
  `librustc_driver`, 9 in `go`, and zero in `libcrypto`, `dyld`,
  `bash`, `ssh` and `zsh`. The shape is overwhelmingly one compare
  followed by another within a handful of instructions (`cmp` + `cmp`
  accounts for nearly all of it), which is why the strict-adjacency
  discipline the rest of the flag checks use would find only about a
  third of them: the surveyed distance histogram runs +1: 57, +2: 59,
  +3: 26, +4: 25, +5..7: 8.
* Where the shape comes from: the same late-pipeline restructuring
  that leaves the other flag residue behind. Tail merging and the
  machine outliner move code across block boundaries after the
  compare's consumer has already been rewritten or dropped, and
  nothing re-runs dead-code elimination on the flags afterwards. A
  representative `librustc_driver` site interleaves three of armlint's
  findings at once -- `cmp w9, #8 ; cmp w9, #6 ; csel x10, x8, x8, eq
  ; cmp w9, #4 ; mov x8, x8 ; cmp w9, #5` -- two dead compares, a
  [same-operand CSEL](#csel-same-operand-identity-csel-rd-rn-rn-cond)
  and a [literal no-op `mov`](#mov-xd-xd-is-a-literal-no-op).
* The other half of the dead-flag family -- an `adds`/`subs`/`ands`
  with a live destination whose flags are equally dead -- is measured
  and deliberately unimplemented; see
  [TODO.md](TODO.md#flag-fold-leftovers).

## ADD #1 + CSEL foldable to CSINC

* `add wt, ws, #1 ; csel wd, wn, wt, cc` instead of
  `csinc wd, wn, ws, cc`: CSINC's else-branch is an increment
  (`Rd = cond ? Rn : Rm + 1`), the exact mirror of the
  [`NEG` -> `CSNEG`](#neg--addsubcsel-foldable-to-negated-operand-form)
  and `MVN` -> `CSINV` consumers. The else slot carries the
  condition over; the then slot swaps operands and inverts it
  (`csel wd, wt, wm, cc` -> `csinc wd, wm, ws, !cc`).
* The rewrite reads the same NZCV the `CSEL` did (the non-S `ADD`
  writes no flags) and reads `ws`, which still holds its original
  value at the consumer once the `ADD` is deleted -- even for the
  in-place `add wt, wt, #1`. AL/NV are excluded (the select is
  unconditional and the then-slot inversion would still be
  always-taken); `Rd = 31` discards the select; both slots reading
  `wt` is the [CSEL identity](#csel-same-operand-identity-csel-rd-rn-rn-cond)'s
  shape; widths must match. Register 31 in ADD-immediate means SP
  for both `Rd` and `Rn`, while CSINC's slots are ZR-flavoured, so
  SP source/destination never open.
* A destination overwriting `wt` reports immediately; a fresh
  destination defers through the forward register-liveness scan.

## compare-zero sign CSET/CSETM foldable into LSR/ASR

* `cmp x1, #0 ; cset x0, lt` instead of `lsr x0, x1, #63`, and
  `cmp x1, #0 ; csetm x0, lt` instead of `asr x0, x1, #63` (`#31`
  for the W forms; `mi` works the same way). Materializing "is
  negative" is just moving the sign bit down: subtracting zero can
  neither borrow nor overflow, so the compare leaves `N = sign(Rn)`,
  `Z = (Rn == 0)`, `C = 1`, `V = 0`, and both LT (`N != V`) and MI
  (`N`) reduce to the bare sign bit. `CSET` writes it as 0/1 --
  exactly the logical shift (the `UBFM` alias) -- and `CSETM` writes
  it replicated as 0/all-ones -- exactly the arithmetic shift (the
  `SBFM` alias). This is the value-materializing twin of the
  [compare-zero signed-branch fold](#compare-zero-signed-branch-foldable-into-tbztbnz).
* The rewrite deletes the compare and sets no flags, so emission
  defers until NZCV is provably dead (any later flag reader -- even
  `b.eq` -- discards), the same rule as the CSSC MAX/MIN/ABS folds.
* The GE/PL complements are matched by neither: `cset x0, ge` needs
  `lsr` + `eor #1` and `csetm x0, ge` needs `mvn` + `asr` -- two
  instructions for two, no win to report.
* The widths must agree. The instructive counterexample is the X
  `CSETM` after a W compare: it writes a 64-bit 0/all-ones mask,
  which no single W-form shift produces (`asr w, w, #31`
  zero-extends its 32-bit mask) -- the sound-but-fiddly mixed `CSET`
  combinations are gated with it for uniformity. `Rn = 31` compares
  SP, which the shift cannot name; AL/NV condition fields (a
  constant, not a conditional) and ZR destinations (dead code) never
  match.
* Only the `CMP Rn, #0` producer opens. `tst x1, x1` and
  `cmn x1, #0` pin the same `N`/`V` and would fold identically, but
  those zero-test spellings are left for a later pass.
* Provenance: this is precisely the rewrite Go's ARM64 compiler
  backend adopted in
  [CL 801282](https://go-review.googlesource.com/c/go/+/801282)
  ("use right shift to compute >= 0 and < 0", 2026) -- binaries from
  older compilers and hand-written assembly still carry the
  two-instruction shape.

## MUL by constant foldable to shift/add

* `mov xc, #(1<<N) ; mul xd, xa, xc` instead of `lsl xd, xa, #N`
  (power-of-2 multiplier). Same for W-form.
* `mov xc, #(2^N + 1) ; mul xd, xa, xc` instead of
  `add xd, xa, xa, lsl #N`.
* Why it helps: the multiply runs on a dedicated, multi-cycle,
  limited-throughput pipe (~3-4 cycle latency), whereas `LSL`/`ADD` are
  single-cycle on any ALU pipe -- lower latency, and the multiplier is
  left free for other work.
* Reuses the MOVZ/MOVK chain state, so wide constants assembled
  via `MOVZ + MOVK` (e.g. `2^16 + 1`) are caught too. The MOV's
  width must match the MUL's. MUL is the canonical alias for
  `MADD Rd, Rn, Rm, ZR`; explicit `MADD` with a non-zero
  accumulator is the
  [MOV + MADD/MSUB check](#mov--maddmsub-foldable-to-shifted-addsub)'s
  shape.
* The `2^N - 1` case is intentionally not folded. AArch64 has no
  single shifted-register form that computes `x*(2^N - 1)`:
  `SUB Xd, Xn, Xn, LSL #N` gives `x*(1 - 2^N)`, the negation, so
  the rewrite would be two instructions (`LSL+SUB` or `SUB+NEG`)
  at parity with `MOV+MUL` in count.
* Dead-constant verification (shared by every MOV-chain fold --
  `MNEG`, `UDIV`, `MOV + ADD/SUB`, `MOV + AND/ORR/EOR`, `MOV + CCMP`,
  `MOV + FMOV/SCVTF/UCVTF`, `MOV #0 + use`, the register-offset fold,
  and the MOVI zeroing fold's `MOV #0` form): the reported saving
  assumes the constant register was materialised solely to feed this
  one consumer, and armlint verifies that before reporting. When the
  consumer itself overwrites the constant register, the chain is dead
  on the spot and the finding emits immediately; otherwise it is
  deferred through a bounded forward register-liveness scan and
  emitted only once a later instruction overwrites the register
  before any read or control transfer. A read, branch, call, return,
  or window expiry discards the finding -- the MOV must stay, so
  there is nothing worth reporting (the consumer rewrite itself --
  the `lsl`/`add #imm`/etc. -- would remain valid either way).
  One shape is suppressed outright across the family: the consumer's
  surviving operand being the constant register itself
  (`mul xd, xc, xc`, `udiv xd, xc, xc`, `add xd, xc, xc`, ...). There
  the rewrite would still read `xc`, so the MOV could never be
  deleted even if nothing else uses it -- and an op whose every input
  is a known constant folds to another constant anyway, which is the
  rewrite a reader actually wants.

## MNEG by constant foldable to NEG/SUB

* Direct symmetric counterpart to the MUL strength reduction.
  `MNEG Rd, Rn, Rm` is the canonical alias for
  `MSUB Rd, Rn, Rm, ZR`; same MOV-chain plumbing applies, including
  the dead-constant caveat and the multiplier-avoidance win noted under
  the MUL check.
* `mov xc, #1 ; mneg xd, xa, xc` -> `neg xd, xa`
* `mov xc, #(1<<N) ; mneg xd, xa, xc` -> `neg xd, xa, lsl #N`
* `mov xc, #(2^N - 1) ; mneg xd, xa, xc` -> `sub xd, xa, xa, lsl #N`
  The elegant case: `SUB Xd, Xn, Xn, LSL #N` computes
  `x*(1 - 2^N) = -x*(2^N - 1)`, exactly what MNEG needs --
  swapping the sign that prevented MUL from folding `2^N - 1`
  in one instruction lets MNEG fold it cleanly.
* `2^N + 1` is not folded for MNEG: the rewrite is two
  instructions (`ADD-shifted` then `NEG`), at parity with
  `MOV+MNEG`.

## MOV + MADD/MSUB foldable to shifted ADD/SUB

* The non-ZR-accumulator complement of the MUL/MNEG strength
  reductions: `Ra = 31` is the `MUL`/`MNEG` alias and stays with
  those checks; an explicit accumulator rides the fold instead.
  * `mov x8, #8 ; madd xd, xn, x8, xa` -> `add xd, xa, xn, lsl #3`
  * `mov x8, #8 ; msub xd, xn, x8, xa` -> `sub xd, xa, xn, lsl #3`
  A multiplier of 1 (`N = 0`) folds to the plain `ADD`/`SUB`. The
  multiply commutes, so the chain may sit in either multiply operand;
  the other survives as the shifted register.
* Same win as the MUL check, plus the accumulate: the whole MAC
  leaves the multiplier pipe (2-3 cycle latency, limited throughput)
  for a single-cycle shifted `ADD`/`SUB`, and the materialising MOV
  dies. (On cores where a shifted operand beyond `LSL #4` costs a
  second cycle the fold is still never slower than the MAC.)
* Reuses the MOVZ/MOVK chain state (and shares the MUL check's
  dead-constant caveat). Exclusions: `Rd = 31` (result discarded);
  an accumulator that is the constant register (the rewrite still
  reads it); a surviving multiply operand that is the constant (a
  constant-squared shape) or ZR (a zero product -- the pair is a
  register copy of the accumulator). The chain's width must match
  the MAC's. Only a power-of-two multiplier folds: `2^N +/- 1`
  shapes, which the `Ra = 31` checks handle via the doubled-operand
  trick, have no single-instruction form once a distinct accumulator
  occupies the addend slot.
* A MAC whose destination IS the constant register overwrites it at
  the consumer and reports immediately; otherwise emission defers
  through the forward register-liveness scan until the constant
  register is provably dead.

## UDIV by constant foldable to shift

* `mov xc, #(1<<N) ; udiv xd, xn, xc` -> `lsr xd, xn, #N`. Same
  MOV-chain plumbing as the MUL/MNEG checks, including the
  dead-constant caveat.
* Why it helps: integer division is one of the slowest A64 operations
  -- data-dependent and poorly pipelined (often ~10-20+ cycles, low
  throughput) -- whereas `LSR` is a single-cycle ALU op on any pipe.
  This is the largest per-hit win among the strength reductions.
* UDIV is not commutative, so only the divisor (Rm) coming from
  the MOV chain enables the fold; an Rn-from-MOV match would be a
  reciprocal-multiply problem, not a shift. Non-pow2 divisors have
  no single-instruction shift rewrite and are excluded.
* SDIV is intentionally not folded: SDIV by `2^N` is *not*
  equivalent to `ASR by N` on negative dividends (SDIV rounds
  toward zero; ASR rounds toward -inf), so the rewrite would be
  incorrect.
* `C == 0` and `C == 1` are excluded as degenerate/identity. Rd ==
  ZR (result discarded) and Rn == ZR (dividend always zero) are
  excluded as different idioms.

## remainder by power of two foldable to AND

* The three-instruction remainder idiom spelled through the divide:
  * `mov x8, #16 ; udiv x9, x1, x8 ; msub x9, x9, x8, x1`
    -> `and x9, x1, #0xf`
  `dividend - (dividend / 2^N) * 2^N` is `dividend mod 2^N`, and
  `UDIV`'s truncation is the flooring the identity needs for
  unsigned values, so a single `AND` with `2^N - 1` (always a valid
  bitmask immediate -- a run of `N` low ones) replaces all three
  instructions and retires one of the slowest A64 operations. The
  signed (`SDIV`) idiom does NOT fold: for negative dividends the
  flooring `AND` disagrees with `SDIV`'s truncation toward zero.
* The `MSUB`'s multiply commutes (quotient and constant in either
  operand); its accumulator must be the ORIGINAL dividend, which the
  adjacent pair provably left unmodified. At the `UDIV`, the
  quotient must be a fresh register -- overwriting the dividend
  clobbers what the `MSUB` re-reads, overwriting the constant
  clobbers the divisor -- and ZR operands and `N = 0` (dividing
  by 1, the identity) are excluded. All widths must match.
* Deadness: the rewrite deletes the MOV, the `UDIV` and the `MSUB`,
  leaving TWO temporaries -- the quotient and the constant. The
  `MSUB`'s own destination kills one structurally (compilers reuse
  the quotient register); the forward register-liveness scan gates
  the other. A fresh destination would need two proofs at once and
  is conservatively skipped.
* Composes cleanly with the
  [`UDIV` strength reduction](#udiv-by-constant-foldable-to-shift):
  on this shape its dead-constant scan sees the `MSUB` re-read the
  constant and discards, so the two checks never double-report --
  the pair-only `LSR` finding appears exactly when the quotient is
  the real product, and this finding when the remainder is.

## MOV + ADD/SUB foldable to immediate form

* `mov xc, #C ; add xd, xn, xc` instead of `add xd, xn, #C` when
  `C` fits the ADD/SUB immediate encoding (12-bit unsigned with
  optional `LSL #12`: `C` in `[1, 0xFFF]` or `C` a multiple of
  `0x1000` with `C/0x1000` in `[1, 0xFFF]`). Same for `SUB`,
  `ADDS`, `SUBS`, and the `CMP`/`CMN` aliases (S-variant with
  `Rd == ZR`).
* A NEGATIVE constant whose magnitude encodes folds *sign-crossed*
  into the opposite consumer -- `mov x8, #-5 ; add xd, xn, x8` ->
  `sub xd, xn, #5`, and symmetrically `sub` -> `add`, `adds` <->
  `subs`, `cmp` <-> `cmn` -- reported as "MOV + ADD/SUB foldable to
  sign-crossed immediate form". The crossing is exact for every
  flag, not just the result: `SUBS Rn, Rm` with `Rm = -C` computes
  `Rn + NOT(-C) + 1 = Rn + C`, the identical 65-bit sum as
  `ADDS Rn, #C`, so N, Z, C and V agree bit-for-bit (and
  symmetrically for `ADDS` of a negative). MOVN chains reach these
  values naturally.
* Reuses the MOVZ/MOVK chain state (and shares the MUL check's
  dead-constant caveat). ADD is commutative -- either operand may be
  the MOV destination. SUB is not: only `Rm == mov_rd` folds, since
  `Rn == mov_rd` would need a reverse-subtract that AArch64 lacks.
  Width of the MOV chain must match the consumer's.
* `C == 0` is excluded (the no-op / MOV-to-Rn case is covered by
  `check_add_sub_zero`); `ZR` as the non-MOV operand is excluded
  (degenerate MOV/NEG).

## MOV + AND/ORR/EOR/ANDS (or BIC/ORN/EON/BICS) foldable to bitmask immediate

* `mov xc, #C ; and xd, xn, xc` instead of `and xd, xn, #C` when
  `C` is a valid AArch64 bitmask immediate (a rotated run of
  consecutive 1s at one of esize=2/4/8/16/32/64). Same for
  `ORR`, `EOR`, and `ANDS` -- and the `TST` alias (`ANDS` with
  `Rd == ZR`).
* The N = 1 family has no immediate form itself, but computes
  `Rn op NOT(Rm)` -- so when the *inverted* operand is the
  constant, the NOT folds into it and the direct-form immediate
  applies: `mov xc, #C ; bic xd, xn, xc` -> `and xd, xn, #~C`
  when `~C` (at the operation width) is a bitmask immediate.
  Same for `ORN -> ORR`, `EON -> EOR`, `BICS -> ANDS` (NZCV
  matches exactly: A64 logical S-ops set N/Z from the result and
  C = V = 0 in both register and immediate forms), and the
  `TST #~C` alias for `BICS` with `Rd == ZR`. Reported under the
  separate name "MOV + BIC/ORN/EON foldable to bitmask
  immediate".
* Reuses `is_bitmask_immediate` as the encodability predicate; 0
  and the all-ones-at-width are not bitmask immediates, so those
  trivial constants naturally skip on either side of the
  complement.
* AND/ORR/EOR/ANDS are commutative; either Rn or Rm may be the
  MOV destination. BIC/ORN/EON/BICS invert Rm only, so the
  constant must be Rm: `bic xd, xc, xm` computes `C & ~xm`,
  which has no immediate form. Shares the MUL check's
  dead-constant caveat.
* The surviving operand must not be the MOV destination itself
  (`mov xc, #C ; and xd, xc, xc`): the suggested immediate form
  would still read `xc`, so the MOV could never be deleted and
  the rewrite saves nothing. Those shapes are left to the
  self-op identity check.

## MOV + CCMP/CCMN foldable to immediate form

* `mov x8, #5 ; ccmp x0, x8, #0, ne` instead of
  `ccmp x0, #5, #0, ne`. The conditional compares have a register and
  an immediate form; a materialized constant in `[0, 31]` -- the
  immediate form's unsigned `imm5` -- feeding the register form's `Rm`
  is the immediate form spelled in two instructions. Same for `CCMN`;
  the `#nzcv` literal and the condition carry over verbatim.
* Reuses the MOVZ/MOVK chain state, but unlike the strength
  reductions the consumer rewrite alone saves nothing (the register
  and immediate conditional compares cost the same), so the finding
  is emitted only after the same forward register-liveness scan as
  the [`MOV #0` fold](#mov-0--use-foldable-to-zr) proves the constant
  register dead. A conditional compare writes only NZCV -- it can
  never kill the constant itself -- so the finding always defers.
* Not commutative: only `Rm` (the subtrahend for `CCMP`, the addend
  for `CCMN`) has an immediate slot, so a chain feeding `Rn` is not
  folded -- the reversed compare has no encoding. The surviving `Rn`
  must not be the constant register (the rewrite would still read it)
  nor ZR (a degenerate compare-against-zero idiom). Width (W vs X) of
  the chain must match the compare's.
* A non-negative `C` outside `[0, 31]` has no immediate form and is
  skipped. A NEGATIVE constant whose magnitude fits imm5 folds
  *sign-crossed* into the opposite compare -- `mov x8, #-7 ;
  ccmp Rn, x8, #nzcv, cond` -> `ccmn Rn, #7, #nzcv, cond`, and
  symmetrically `ccmn` -> `ccmp` -- reported as "MOV + CCMP/CCMN
  foldable to sign-crossed immediate form". The NZCV agree exactly:
  when the condition holds, the compare of `-C` and the opposite
  compare of `#C` perform the identical 65-bit sum, and when it
  fails both set the carried-over `#nzcv` literal.

## MOV #1 + CSEL foldable to CSINC/CSET

* `mov w8, #1 ; csel wd, w8, wn, cc` instead of
  `csinc wd, wn, wzr, !cc`. `CSINC`'s else-branch is `Rm + 1`, so a
  materialised 1 in either `CSEL` operand is reproduced by
  incrementing ZR:
  * `mov w8, #1 ; csel wd, w8, wn, cc` -> `csinc wd, wn, wzr, !cc`
    (constant in the then slot: the condition inverts, since the 1
    moves to the incrementing else branch).
  * `mov w8, #1 ; csel wd, wn, w8, cc` -> `csinc wd, wn, wzr, cc`
    (constant in the else slot: the condition carries over).
  When the surviving operand is ZR the select is a boolean
  materialisation and the rewrite is the `CSET` alias
  (`cset wd, cc` / `cset wd, !cc` -- the condition under which the
  result is 1). That shape -- a bool built through a constant
  register instead of from the flags -- is the flagship catch.
* A materialised ALL-ONES folds the same way through `CSINV`, whose
  else-branch is `~Rm` (`mov w8, #-1 ; csel wd, wn, w8, cc` ->
  `csinv wd, wn, wzr, cc`; ZR surviving operand -> the `CSETM`
  alias), reported as "MOV #-1 + CSEL foldable to CSINV/CSETM".
  All-ones is width-dependent (`0xFFFFFFFF` for a W chain), unlike
  the zero fold's width-agnostic value, so the width gate does real
  work here: a W chain holding `0xFFFFFFFF` does not fold into an X
  select.
* Only `CSEL` proper (op2 = 00) matches; `CSINC`/`CSINV`/`CSNEG` have
  different else-branches. The rewrite reads the same NZCV the `CSEL`
  did (the MOV writes no flags), so no flag-liveness scan is needed.
  Reuses the MOVZ/MOVK chain state; the chain's value must be exactly
  1 (or all-ones) and its width (W vs X) must match the select's,
  consistent with the other integer MOV-chain folds.
* `AL`/`NV` conditions are excluded (`ConditionHolds` treats both as
  always-true, so the select is a plain `MOV` and the then-slot
  inversion, `AL` <-> `NV`, would still be always-taken), as are
  `Rd = 31` (a discarded select) and a `CSEL` reading the constant in
  both slots (the same-operand identity, which the CSEL identity
  check owns).
* The rewrite deletes the MOV. A select whose destination IS the
  constant register overwrites it at the consumer itself and reports
  immediately; otherwise the finding defers through the forward
  register-liveness scan until the constant register is provably
  dead (shares the MUL check's dead-constant caveat).
* What it saves: the materialising MOV (one instruction and the
  register that held the 1); the select itself neither gains nor
  loses -- `CSEL` and `CSINC` cost the same on current cores.

## MOV + variable shift foldable to immediate shift

* `mov w8, #5 ; lsl wd, wn, w8` instead of `lsl wd, wn, #5`. The
  variable shifts `LSLV`/`LSRV`/`ASRV`/`RORV` -- which assemblers
  spell `lsl`/`lsr`/`asr`/`ror` with a register amount -- each have
  an immediate-form twin (the `UBFM`/`SBFM` aliases; `EXTR` for
  `ROR`), so a materialised shift amount folds into it and the MOV
  dies.
* The register form shifts by `UInt(Rm) MOD datasize`, so the folded
  immediate is the chain's value reduced modulo 32/64: a chain of
  `#67` feeding a 64-bit shift folds to `#3`, and a MOVN chain's
  all-ones value folds to `#31`/`#63`. A residue of 0 shifts by
  nothing -- a register copy, not a shift -- and is left alone as
  degenerate.
* Reuses the MOVZ/MOVK chain state (and shares the MUL check's
  dead-constant caveat). The chain must feed the amount operand `Rm`;
  the shifted operand `Rn` must not be the constant register (the
  rewrite would still read it, so the MOV could never be deleted)
  nor ZR (shifting zero is a constant, a different idiom). `Rd = 31`
  (a discarded shift) is excluded, and the chain's width must match
  the shift's.
* The rewrite deletes the MOV; the immediate and register shift
  forms themselves cost the same on current cores. A shift whose
  destination IS the constant register overwrites it at the consumer
  and reports immediately; otherwise emission defers through the
  forward register-liveness scan until the constant register is
  provably dead.

## MOV + FMOV/SCVTF/UCVTF foldable to FMOV immediate

* `mov w8, #0x3f800000 ; fmov s0, w8` instead of `fmov s0, #1.0`.
  Materialising a floating-point constant through a general register
  costs the extra MOV (two or more instructions for a wide double
  pattern) plus a cross-register-file transfer, which runs several
  cycles of latency on most cores; `FMOV (scalar, immediate)` produces
  the value directly on the FP side. Conversions of pinned small
  integers are the same pattern one step removed:
  `mov w8, #5 ; scvtf d0, w8` -> `fmov d0, #5.0`, and `UCVTF`
  likewise.
* `FMOV`'s imm8 expands (`VFPExpandImm`) to `+/-(16..31)/16 x 2^n`
  for `n` in `[-3, 4]` -- 256 values from a sign, a 4-bit fraction
  and a 3-bit exponent. Every integer of magnitude 1..31 is included.
  Zero is NOT expressible, so zero materialisations never match
  (idiomatic FP zeroing is `MOVI`, a separate concern). NaNs,
  infinities and denormals fail the exponent shape; extra fraction
  bits fail outright. The test is an exact bit-pattern comparison --
  no floating-point arithmetic is involved in the FMOV direction.
* Consumers: `FMOV (general)` in the GPR->FPR direction only
  (`fmov Sd, Wn` / `fmov Dd, Xn`) and the scalar integer conversions
  `SCVTF`/`UCVTF` from either GPR width. A 64-bit source also accepts
  a W-form chain -- the W write zeroed `X[63:32]`, pinning the full
  64-bit read -- while a W source requires a W chain. Half-precision
  destinations (FEAT_FP16) are not matched.
* Folding a conversion is sound only when the conversion is exact:
  `SCVTF`/`UCVTF` round per the dynamic FPCR mode, and only exactness
  makes the result mode-independent (an exact conversion also raises
  no FP exceptions, preserving FPSR). Encodability already implies
  exactness -- an imm8 value's magnitude is at most 31.5, bounding the
  integer's by 31 -- but the check verifies the round-trip explicitly
  rather than lean on that argument. The write semantics agree too:
  the transfer, the conversion and `FMOV #imm` all zero the vector
  register above the written scalar lane.
* The consumer writes only an FP register and can never kill the
  constant GPR itself, so -- like the CCMP fold -- the finding always
  defers through the forward register-liveness scan until the
  constant register is provably dead.

## FP/vector zeroing via GPR foldable to MOVI

* `fmov s0, wzr` instead of `movi d0, #0`. FMOV's immediate cannot
  encode zero, so zeroing an FP or vector register is MOVI's job --
  and routing the zero through a general register instead costs a
  cross-register-file transfer (several cycles of latency on most
  cores) that MOVI performs on the FP side, where zero idioms are
  often free at rename. Three consumer families:
  * `FMOV (general)`, GPR->FPR: `fmov s0, wzr` / `fmov d0, xzr`.
  * `SCVTF`/`UCVTF` of zero: integer zero converts to `+0.0` -- the
    all-zeros pattern -- in every FPCR rounding mode (`FixedToFP`
    returns `FPZero` for a zero input outright, raising no
    exceptions), so `scvtf d0, wzr` is exactly `movi d0, #0`.
  * `DUP (general)` broadcasting ZR: `dup v0.4s, wzr` ->
    `movi v0.4s, #0`, keeping the arrangement.
  All three zero the vector register above what they write, exactly
  as MOVI does, so the final 128-bit state is bit-identical. Scalar
  consumers render the canonical 64-bit zeroing `movi dN, #0` (the
  whole register is zero regardless of the S/D destination width).
* The ZR-source forms are one-for-one rewrites with no deleted write
  and report immediately. The same consumers fed by a MOV-chain
  register pinned to zero (`mov w8, #0 ; fmov s0, w8`) additionally
  delete the MOV, and defer through the forward register-liveness
  scan until the constant register provably dies -- width admission
  as in the FMOV-immediate fold (a 64-bit source also accepts a
  W-form chain). These consumers are deliberately not in the
  [`MOV #0` fold](#mov-0--use-foldable-to-zr)'s set: substituting WZR
  would keep the cross-file transfer that MOVI eliminates.
* Nonzero DUP broadcasts that MOVI's expanded immediate could encode
  (`mov w8, #5 ; dup v0.4s, w8` -> `movi v0.4s, #5`) are a natural
  extension, deferred for now. Half-precision (FEAT_FP16) transfers
  are not matched, consistent with the FMOV-immediate fold.

## widening extend + SCVTF/UCVTF foldable to W-form conversion

* `sxtw x8, w0 ; scvtf d0, x8` instead of `scvtf d0, w0`. The
  conversions have both W- and X-source forms, and the W-source form
  performs the widening itself -- extending first through a scratch
  register spends an instruction and a register on work the
  conversion already does. Recognised extends: `SXTW Xd, Wn` (the
  SBFM alias) and the zero-extending `MOV Wd, Wm` (any W write zeroes
  the upper half; this ORR alias is the canonical uint32 -> 64
  widening).
* Signedness maps by value, not by spelling:
  * `sxtw` + `scvtf Xn` -> `scvtf Wn` (the sign-extended value is
    the signed 32-bit value).
  * `mov w, w` + `ucvtf Xn` -> `ucvtf Wn`.
  * `mov w, w` + `scvtf Xn` -> `ucvtf Wn` -- the zero-extended
    64-bit value IS the unsigned 32-bit value, so even the signed
    wide conversion becomes the unsigned narrow one.
  * `sxtw` + `ucvtf Xn` does NOT fold: the unsigned reading of
    `sext(negative)` is a huge value, not the 32-bit one.
  Both sides convert the same mathematical value, so the identity is
  exact in every FPCR rounding mode and raises identical exceptions
  -- no exactness argument is needed. ZR operands are excluded as
  degenerate (a constant-zero extend).
* The rewrite reads the extend's own source, which the adjacent pair
  leaves unchanged -- even in-place: `sxtw x0, w0` and `mov w0, w0`
  keep the low 32 bits of their destination equal to the source.
  Deleting the extend requires its destination dead; the conversion
  writes only an FP register and never kills it, so the finding
  always defers through the forward register-liveness scan until the
  extended register provably dies.

## load + SCVTF/UCVTF via GPR foldable to FP load + convert

* `ldr w8, [x1] ; scvtf s0, w8` instead of
  `ldr s0, [x1] ; scvtf s0, s0`. An int-to-FP conversion routed
  through a general register pays a cross-register-file transfer the
  FP-side spelling avoids: the GPR-source conversions crack into a
  several-cycle GPR -> FP move plus the convert (the move rides the
  load pipes on Apple's cores and the M0 pipe on Neoverse), while
  loading straight into the FP register and converting in-SIMD is
  two independent cheap ops. Apple's CPU optimization guide
  recommends exactly this rewrite (measuring 11 -> 7 cycles on
  M-series). The instruction count is unchanged; the win is the
  transfer, plus the freed GPR.
* Exactness: the rewrite performs the identical memory access (same
  address, same size), converts the same 32/64-bit integer value
  under the same FPCR rounding with the same FPSR exceptions, and
  both spellings zero the vector register above the written lane.
* Widths must match on both sides -- only int32 -> single and
  int64 -> double have in-SIMD twins; there is no cross-width scalar
  conversion -- so mixed pairs (`scvtf d0, w8`), the byte/halfword
  loads and the sign-extending loads never fold. Half precision
  (FEAT_FP16) is not matched, consistent with the FMOV folds.
  `Rt = 31` (a discarded load) does not open.
* The rewrite stops writing the GPR entirely, so the loaded register
  must be dead afterward; the conversion writes only an FP register
  and can never kill it, so the finding always defers through the
  forward register-liveness scan. v1 matches the unsigned-offset
  addressing form only, like the other load-rewriting folds.

## low-32 zero-extension foldable to MOV Wd, Wn

* `and x0, x1, #0xffffffff` -> `mov w0, w1`, and the bitfield spelling
  `ubfx x0, x1, #0, #32` -> `mov w0, w1`. Both compute
  `ZeroExtend(Xn[31:0], 64)`, which is exactly what a W-form register
  move already does: every W write zeroes the upper half of its X
  register. One instruction either way, nothing deleted, no flags or
  memory touched -- so like the lane-0 UMOV fold this needs no liveness
  argument.
* **What it saves is not size.** `MOV Wd, Wn` is an `ORR Wd, WZR, Wm`,
  which Neoverse cores resolve at register rename with no execution
  slot; the mask and the bitfield extract each occupy an ALU pipe.
  Neutral on cores that do not rename it away, so this is another
  "cheaper, not shorter" finding.
* Only the X form matters. The 32-bit `and w0, w1, #0xffffffff` is not
  even encodable -- the logical-immediate encoding excludes all-ones --
  and a W-form op has nothing above bit 31 left to clear.
* The width must be exactly 32 and the lsb exactly 0. A narrower mask
  is a real extraction, and the full-width spellings clear nothing:
  `ubfx xd, xn, #0, #64` is `UBFM Xd, Xn, #0, #63`, which the assembler
  renders as `lsr xd, xn, #0` and which belongs with the degenerate
  register-copy spellings, not here.
* **`Rd == Rn` is deliberately not reported**, though the rewrite is
  equally sound. It would read `-> mov w0, w0`, a shape whose obvious
  follow-on is to delete it -- and deleting it is a miscompile, since a
  W-form move of a register to itself still zeroes bits 63:32. For a
  tool whose worst failure is a false positive, advice one step away
  from a wrong edit is close enough to one. The in-place cases that
  genuinely are deletable, where an earlier instruction already cleared
  those bits, belong to
  [`redundant zero-extension`](#redundant-zero-extension-after-a-producer-that-already-zeroed-those-bits),
  which says "delete" rather than "respell". That exclusion costs 13 of
  the 56 corpus candidates and removes the whole overlap.
* Three operand traps, none of which the corpus happens to contain but
  all of which the encodings allow:
  * **AND-immediate's `Rd = 31` is SP, not ZR**, while the rewrite's
    `ORR Wd, WZR, Wm` reads `Rd = 31` as WZR. The two encodings
    disagree about register 31, so an SP destination can never fold.
    The assembler enforces this from the other side: `and xzr, x1, #imm`
    is rejected outright as an invalid operand.
  * `UBFM`'s `Rd = 31` really is ZR, so that result is discarded and
    the instruction is dead outright -- a deletion, not a respelling.
  * A ZR source turns either op into a zero materialization rather than
    a truncation; that belongs with the ZR-operand canonicalizations.
* Corpus: 40 findings of 56 candidates across 28.4M instructions (30
  librustc_driver, 6 libcrypto, 4 go). The 16 unreported are the 13
  in-place cases above and 3 ZR-source ones; dyld's 4 candidates are
  all in-place, which is why it contributes nothing.
* Overlap with the two-instruction folds that consume the same
  instruction -- the redundant zero-extension check, and the
  zero-extend + LSL fold that turns `uxtw x0, w1 ; lsl x0, x0, #2`
  into a `UBFIZ` -- is real in principle: the pair fold deletes the
  instruction outright, which beats respelling it. In practice not one
  of the 40 findings shares an offset with another check's, so no
  precedence machinery is warranted. The fixtures pin both directions.

## UMOV of lane 0 foldable to FMOV

* `umov w0, v1.s[0]` -> `fmov w0, s1`, and `umov x0, v1.d[0]` ->
  `fmov x0, d1`. `Sn` and `Dn` are not separate registers: they are the
  low 32 and 64 bits of `Vn`. For lane 0 the two instructions therefore
  move identical bits into an identical destination, zero-extending the
  same way, and the rewrite needs no conditions beyond the operand
  shape -- nothing is deleted, no flags or memory are involved, and the
  source is read exactly once either way. This is the one check in the
  file with no liveness argument at all.
* **What it saves is not size.** Both encodings are one instruction.
  `FMOV` uses a cheaper port than `UMOV` on Apple cores (Apple Silicon
  CPU Optimization Guide 4.5.2), so this is an execution-resource
  finding, in the same "cheaper, not shorter" class as the pair-offset
  residue. Worth knowing before acting on a large count of them.
* **Only lane 0.** `FMOV` (general) can address just the low element,
  which is the entire restriction. The lane index lives in `imm5` above
  the size bit -- `.s[i]` encodes as `i:100`, `.d[i]` as `i:1000` -- so
  "lane 0" is exactly "no bits set above the size bit", a single mask
  test. `umov w0, v1.s[2]` has no `FMOV` spelling whatsoever.
* **The B forms never fold** at any lane: there is no `FMOV Wd, Bn`.
* The halfword arm is feature-gated (`-m fp16`), reported under its own
  name `UMOV of lane 0 foldable to FMOV (FP16)`:
  `umov w0, v1.h[0]` -> `fmov w0, h1`. Both zero-extend `Vn[15:0]` into
  `Wd`, but `FMOV Wd, Hn` is FEAT_FP16, so the fold is silent unless
  the target is known to have it. It is where the volume is: 1,780
  sites across the corpus against 484 for the always-live arms, 1,775
  of them in librustc_driver.
* `Rd = 31` is excluded. That is ZR, so the transfer is discarded and
  the instruction is dead outright; respelling a dead instruction as a
  different dead instruction is not useful advice, and the deletion
  belongs to a different check.
* **Match on the encoding, not the mnemonic.** `MOV Wd, Vn.S[index]`
  and `MOV Xd, Vn.D[index]` are the *preferred* aliases for exactly
  the two always-live forms, so both the assembler and every
  disassembler print them as `mov`; only the `.b` and `.h` forms show
  up as `umov`. Grepping disassembly for "umov" finds none of the
  unconditionally foldable sites.
* Corpus: 484 always-live sites (464 libcrypto, 20 go) plus 1,780
  FP16-gated ones. The operand condition is what makes this a check
  rather than a blanket rewrite -- there are 7,150 `UMOV`s in the
  corpus and only 484 are lane-0 S or D, 6.8%. librustc_driver's 6,465
  are almost entirely halfword extraction and `.d[1]`, the *high*
  lane; libcrypto's are the reverse.

## CSSC synthesis (feature-gated: `-m cssc`)

* Armv8.9/9.4 Common Short Sequence Compression gives single
  instructions for idioms the base ISA spells in two. These checks
  suggest instructions the target must support, so they stay silent
  unless `-m cssc` is passed:
  * `cmp x1, x2 ; csel x0, x1, x2, gt` -> `smax x0, x1, x2`
    ("CMP + CSEL foldable to MAX/MIN (CSSC)"). GE/GT pick the larger
    -- the equal case selects equal values, so both conditions work
    -- LT/LE the smaller, HS/HI and LO/LS the unsigned twins, and
    swapped CSEL operands flip the direction. Only the plain
    shifted-register LSL #0 compare with distinct operands opens.
  * `cmp x1, #0 ; cneg x0, x1, mi` -> `abs x0, x1`
    ("CMP #0 + CNEG foldable to ABS (CSSC)"). The raw match is a
    CSNEG with both sources the compared register and a condition in
    {PL, GE, GT}: the condition holds exactly for `r >= 0` (GE
    because V = 0 after a zero compare), or `r > 0` where the r = 0
    else-branch still yields -0 = 0. Source-level `cneg` conditions
    MI/LT/LE, inverted by the alias.
  * `rbit x0, x1 ; clz x0, x0` -> `ctz x0, x1`
    ("RBIT + CLZ foldable to CTZ (CSSC)"): counting leading zeros of
    a bit reversal counts trailing zeros of the original.
* Soundness: the MAX/MIN and ABS rewrites DELETE the compare and set
  no flags at all, so they defer through an NZCV-death scan on a
  dedicated shared slot -- any later flag reader (even `b.eq`)
  discards, and only a full NZCV overwrite or safe terminator
  commits. CTZ involves no flags; the reversed value must be dead,
  with the usual structural kill (the CLZ overwrites it) or forward
  register-liveness deferral, and the RBIT's source still holds its
  original value at the consumer once the RBIT is deleted (even
  in-place).
* The NEON popcount round trip folds to the GPR `CNT`:
  `fmov d0, x1 ; cnt v0.8b, v0.8b ; addv b0, v0.8b ; fmov w0, s0` ->
  `cnt x0, x1` ("NEON popcount foldable to CNT (CSSC)"). All vector
  stages must run in place on one register with strict adjacency;
  the 8B and 16B `CNT`/`ADDV` forms both match (the opening `FMOV`
  zeroed the upper half), and the closing transfer may read the S or
  D view into any GPR -- the count fits every view and both
  spellings zero above it. The rewrite never writes the vector
  register and nothing in the chain can kill it structurally, so
  emission always defers through the
  FP/vector-register liveness scan. This retires four instructions,
  two of them cross-register-file transfers. One honest limit: a
  chain that runs straight into `ret` -- the canonical standalone
  `__builtin_popcountll` emission -- stays unreported, because v0 is
  the FP return-value register and the scan stops conservatively at
  every control transfer; the realistic catch is the inlined chain
  whose vector register is reused shortly after.

## compare-and-branch synthesis (feature-gated: `-m cmpbr`)

* Armv9.6's FEAT_CMPBR -- optional from Armv9.5, mandatory from 9.6 --
  adds `CB<cc>`, which does a comparison and a conditional branch in
  one instruction and writes no flags. The compare in front of a
  conditional branch then disappears:
  * `cmp x1, x2 ; b.gt L` -> `cbgt x1, x2, L`
  * `cmp w0, #10 ; b.ls L` -> `cbls w0, #0xa, L`
  ("CMP + B.cond foldable to compare-and-branch (CMPBR)"). The check
  is silent without `-m cmpbr`: a target that does not implement
  FEAT_CMPBR finds the encoding UNDEFINED.
* The condition maps across unchanged. `CB<cc>` spells its condition
  into the mnemonic, and the ten it can express -- `EQ`/`NE`, the
  signed `GT`/`GE`/`LT`/`LE`, and the unsigned `HI`/`HS`/`LO`/`LS` --
  are exactly the ten a `CMP`'s flags define as a comparison of the
  two operands (`HS` is `C`, `GE` is `N == V`, and so on), so each
  `b.<cc>` becomes `cb<cc>` of the same operands in the same order.
  `MI`/`PL` read a sign and `VS`/`VC` an overflow that no comparison
  of values reproduces; `AL`/`NV` are not conditions. None opens.
* Only the two compare spellings `CB` mirrors open: shifted-register
  with `LSL #0` (`cmp Rn, Rm`) and immediate with `sh = 0`
  (`cmp Rn, #imm12`). A shifted or extended-register compare has no
  `CB` operand for the shift; `CMN` compares against a negated operand
  and `TST` against a mask, neither of which `CB` expresses.
  `cmp Rn, XZR` is the register spelling of `cmp Rn, #0` and reports
  as the immediate form, so no suggestion has to name a zero register.
  `Rn = 31` never opens: it is SP in the immediate form, which `CB`
  cannot encode (its `Rt = 31` is the zero register), and a degenerate
  `XZR` compare in the register one.
* Two encoding windows gate the rewrite:
  * **The comparand.** `CB<cc>` (immediate) carries an unsigned 6-bit
    field. `EQ`/`NE`/`GT`/`LT`/`HI`/`LO` encode it directly and reach
    0..63. The other four are assembler pseudo-instructions that shift
    the stored value by one: `CBGE`/`CBHS` assemble as `CBGT`/`CBHI`
    of `imm-1` and so reach 1..64, `CBLE`/`CBLS` as `CBLT`/`CBLO` of
    `imm+1` and so stop at 62.
  * **The reach.** `CB`'s `imm9` spans -1024..1020 bytes where
    `B.cond`'s `imm19` spanned +-1MB. The `CB` sits at the compare's
    address, 4 bytes ahead of the branch, so the displacement it must
    encode is `imm19 + 1` words -- the same accounting the `TBZ` fold
    makes, and conservative by one word for a forward target, which
    deleting the compare pulls 4 bytes closer.
* A zero comparand is left to the baseline folds rather than reported
  twice. [`cmp Rn, #0` + `b.eq`/`b.ne`](#compare-zero-branch-foldable-into-cbzcbnz)
  is already `CBZ`/`CBNZ` (and `b.hi`/`b.ls` reduce to those once the
  compare pins `C = 1`), and
  [`b.lt`/`b.ge`](#compare-zero-signed-branch-foldable-into-tbztbnz)
  is already `TBZ`/`TBNZ` of the sign bit -- none of which needs an
  extension. `HS` and `LO` are not folds at all after a zero compare
  (`C = 1` makes `HS` always taken and `LO` never), and `CBHS #0` is
  outside `CBHS`'s window anyway. `GT` and `LE` are what remains, and
  they are genuinely new: no baseline instruction tests `> 0` or
  `<= 0` in one word.
* **Soundness: both edges of the branch are proven, not one.** The
  rewrite deletes the compare and `CB` writes no flags at all, so the
  old NZCV must go unread whichever way the branch goes. The
  fall-through half is the usual deferred scan. The taken half is the
  part that makes this check different from every other branch fold
  here: those assume NZCV is dead at the target -- fair for a
  zero-test producer, whose flags a compiler rarely reuses -- but this
  one's producer is a general two-register compare, which is exactly
  what a compiler *does* reuse across a branch. clang's three-way
  comparator is the shape, and `/bin/ls` is full of it:

  ```asm
  cmp   x10, x11
  b.le  L         ; L below re-reads N/Z/V from THIS compare
  mov   w0, #1
  ret
  L: b.ge ...
  ```

  Folding there would leave `L` reading undefined flags. So emission
  additionally requires a forward scan *starting at the branch
  target* to reach a flag overwrite -- or a call or return, past which
  the PCS makes the flags caller-clobbered -- before any reader, under
  the same bounded window and the same conservative classification as
  the fall-through scan. Anything short of that proof refuses: no
  scanned buffer, a target outside it, a reader, a control transfer
  whose own destination would have to be chased in turn, or a window
  that expires. On macOS 26's `/bin/ls` it refuses 16 of 52 candidate
  pairs, leaving 36 findings in 3817 instructions: six are the
  comparator shape above, where the target genuinely re-reads the
  deleted flags, and the other ten are conservative -- a `CBZ`/`CBNZ`
  or an unconditional `B` at the target ends the scan before it can
  reach a kill. What survives is not a trickle: arm64e `/usr/lib/dyld`
  reports 2550 pairs in 161738 instructions, spread across all ten
  conditions (`cbne` 1366, `cbeq` 658, then the unsigned four, with
  the signed `cbgt`/`cble`/`cblt`/`cbge` the tail at 64), and every
  one of them re-assembles as a real `CB<cc>` at its own
  displacement.
* Not implemented: `CBB<cc>` and `CBH<cc>`, the byte and halfword
  compares. They pay off only by deleting an explicit
  `UXTB`/`UXTH`/`SXTB`/`SXTH` ahead of the compare -- a 3-for-1 or
  4-for-1 fold with its own liveness argument -- since on already
  narrow values `CB` itself is the same one instruction. See
  [TODO.md](TODO.md).

## three-operand SHA3 logic synthesis (feature-gated: `-m sha3`)

* FEAT_SHA3 -- optional from Armv8.2, never mandatory -- carries four
  instructions that are general bit-mixing rather than Keccak-specific.
  Two of them collapse an adjacent pair:
  * `eor v0.16b, v1.16b, v2.16b ; eor v0.16b, v0.16b, v3.16b` ->
    `eor3 v0.16b, v1.16b, v2.16b, v3.16b`
    ("EOR + EOR foldable to EOR3 (SHA3)")
  * `bic v0.16b, v2.16b, v3.16b ; eor v0.16b, v1.16b, v0.16b` ->
    `bcax v0.16b, v1.16b, v2.16b, v3.16b`
    ("BIC + EOR foldable to BCAX (SHA3)")
* Soundness is as simple as it gets in this tool. `EOR3` is
  `Vn EOR Vm EOR Va` and `BCAX` is `Vn EOR (Vm AND NOT Va)`, which is
  exactly what the pairs compute -- pure bitwise identities over the
  same 128 bits, with no lane width, rounding, exception, or flag
  behavior to preserve. Both were checked by execution as well as by
  the pseudocode: 200,000 random vector triples through each spelling,
  bit-identical.
* Only the 16B forms open and close. Neither fused instruction has an
  8B form, and an 8B pair zeroes the destination's upper half where
  the fused one would write real data. The three-same logic ops share
  one encoding class and are separated only by U (bit 29) and size
  (bits 23..22), so `AND`/`ORR`/`ORN`/`BSL`/`BIT`/`BIF` are excluded by
  pinning both.
* The consumer must read the temp in exactly **one** source slot. With
  both sources equal to it the `EOR` cancels to zero, which no
  three-operand form reproduces. The producer's own sources may be the
  temp: deleting the producer leaves them holding the value it read
  itself, so the in-place `eor Vt, Vt, Vb ; eor Vt, Vt, Vc` spelling
  -- the one compilers actually emit -- folds like any other.
* The rewrite deletes the producer, so its destination must be dead
  afterward. A consumer writing that same register kills it
  structurally and emits on the spot; a fresh destination defers
  through the vector-register liveness scan
  (`armlint_advance_pending_fp`). In practice the structural path is
  the whole population: of OpenSSL 3.6.3 libcrypto's 106 adjacent
  dependent pairs of this shape, 71 have the in-place destination and
  35 do not -- and none of the 35 commit, because that scan treats a
  written vector operand as also read unless the writer is on the
  pure-overwrite whitelist (loads and scalar FP), so a following
  vector op merely fails to prove the temp dead. False negatives only.
* **The side-entry gate is load-bearing here, not a formality.** 19 of
  those 71 pairs are suppressed because the consumer is a direct
  branch target -- in libcrypto's AES loops, two `b` instructions land
  on the second `eor`:

  ```asm
  36f8: b        0x3704
  36fc: aesd.16b v1, v17
  3700: eor.16b  v1, v1, v18
  3704: eor.16b  v1, v1, v31   ; <- branched to from 36c8 and 36f8
  ```

  A path entering at `3704` never ran the producer, so the fused
  `eor3` would mix in `v18` where the original mixes in nothing. That
  leaves 52 reported findings, every one of which re-assembles as a
  real `EOR3` and, executed against its original pair over 20,000
  random register states, computes the identical result.
* Yield is narrow and concentrated: 52 in libcrypto (560349
  instructions), 10 in `go`, 0 in `dyld`, 0 in librustc_driver. This
  is a crypto-and-hashing fold, not a general one.
* Actionability caveat, the same one `-m pauth` carries: FEAT_SHA3 is
  never mandatory, so `-m sha3` is a real assertion about the target
  rather than an architecture-version floor. A library that dispatches
  on it at runtime keeps the two-instruction path on purpose -- and
  libcrypto is exactly that library, already shipping 65 `xar`
  instructions in a FEAT_SHA3 Keccak path alongside the portable code
  these findings come from.
* Not implemented: `XAR` (`(Vn EOR Vm)` rotated right per 64-bit lane)
  and `RAX1` (`Vn EOR ROL(Vm, 1)`). Both fold three or more
  instructions rather than two, since a NEON lane rotate is itself a
  shift pair; see [TODO.md](TODO.md).

## split pointer-authentication return foldable into RETAA/RETAB (feature-gated: `-m pauth`)

* A pac-ret epilogue restores the signed return address, authenticates
  it, and returns. The authenticate-and-return steps take two
  instructions in the portable spelling; Armv8.3's combined forms do
  both in one -- same key (IA/IB), same modifier (SP), same register
  (x30):
  * `autiasp ; ret` -> `retaa`
  * `autibsp ; ret` -> `retab`
  ("AUTIASP/AUTIBSP + RET foldable to RETAA/RETAB (PAuth)"). Both
  sides are fixed words, matched raw under strict adjacency.
* The split spelling exists for portability, which is why the check is
  opt-in on a general target: AUTIASP/AUTIBSP live in the hint space
  and execute as NOPs on pre-Armv8.3 cores, so one binary hardens
  where the keys exist and still runs everywhere -- while RETAA/RETAB
  are UNDEFINED there. `-m pauth` asserts the target guarantees v8.3.
  An arm64e slice does guarantee it -- FEAT_PAuth is the ABI's whole
  premise -- so the driver arms `-m pauth` automatically there (the
  same cpusubtype gate that auto-arms the PAC audit; see the PAC
  hygiene audit section and scan_macho). A plain arm64 slice keeps the
  flag opt-in, since it may target a pre-v8.3 core. Compilers already
  emit the combined forms at a guaranteed-v8.3 baseline (arm64e,
  `-march=armv8.3-a` and up); the check surfaces the residue, which is
  real: macOS 26's arm64e `/usr/bin/ssh` carries 42 adjacent
  `autibsp ; ret` pairs alongside its 762 `retab`s -- and now reports
  them with no flag.
* Soundness fine print: the combined forms do not write the
  authenticated address back to x30, so after the return the register
  holds the still-signed value where the split form left the raw one.
  AAPCS64 makes x30 a plain temporary once the call returns -- no
  conforming caller reads it -- the register twin of the
  BL-clobbers-NZCV argument the flag-liveness scan makes. On a forged
  return address both spellings deny the hijack; only the diagnosis
  point differs: FEAT_FPAC faults the standalone AUT precisely, the
  combined form faults given FEAT_FPACCOMBINE, and cores with neither
  branch to a poisoned address in both spellings.
* The side-entry gate is load-bearing here, not a formality. A shared
  epilogue whose RET is a direct-branch target is reached by paths
  that never signed x30 (shrink-wrapped fast paths), and the folded
  RETAA/RETAB would authenticate a raw pointer there -- a fault, not
  a slowdown. In that same `/usr/bin/ssh`, 18 of the 42 pairs are
  exactly this shape (each one confirmed branch-targeted at the RET)
  and are suppressed; the 24 clean pairs are reported.
* Exclusions: `ret x17` (the combined forms are x30-only); the
  zero-modifier AUTIAZ/AUTIBZ (no combined zero-modifier return
  exists); the general-encoding `autia x30, sp` spelling (identical
  semantics, unseen in compiler output); tail calls (`autibsp ; b
  target` has no combined form, and `autiasp` + `br x30` is left to a
  future `br x30` -> `ret` canonicalization).

## PAC hygiene audit (`-a pac`; auto-armed on arm64e)

* The `-a <audit>` class is different in kind from `-m`: `-m` asserts
  what the target supports so rewrites may use it, while `-a` opts
  into informational findings that flag missing hardening rather
  than a missed fold. `-a pac` audits a binary against the full
  pointer-authentication contract that arm64e code follows. Audit
  findings are review items, a benign residue is expected, and they
  ride the regular reporting machinery (so they are counted in the
  same opportunities summary; the "(PAC audit)" suffix marks their
  kind).
* The audit arms automatically on arm64e Mach-O slices. An arm64e
  slice is one whose cpusubtype is CPU_SUBTYPE_ARM64E -- the ABI in
  which every function signs its return address and routes indirect
  calls through the authenticated branches -- so the audit's central
  assumption (the binary opted into pac-ret) is exactly true there,
  and the driver enables it with no flag. The gate is deliberately
  narrow: a plain arm64 slice never opted in, so arming it would flag
  every function's spill (the gh figures below). The detection is one
  cpusubtype test in scan_macho; an explicit `-a pac` still forces
  the audit on any slice, e.g. a plain arm64 binary hand-built with
  `-mbranch-protection=pac-ret`.
* "LR spill without PACIASP/PACIBSP (PAC audit)": pac-ret exists
  because a return address spilled to the stack is the classic ROP
  target -- sign it before it leaves the register file and a stack
  overwrite faults at authentication instead of steering the return.
  The check flags any SP-based spill of x30 (STP pre-index or signed
  offset with either data register x30; STR unsigned offset or
  pre-index) with no PACIASP/PACIBSP in the same straight-line run: a
  16-instruction window reset by any control transfer, because real
  prologues sign first and never branch between the signing and the
  save (interposed callee-saved pairs sit comfortably inside the
  window). Leaf functions never spill x30, so they need no signing
  and produce no findings. Out of scope: non-SP bases (a jmp_buf in
  setjmp is a real PAC surface but a different shape) and STP
  post-index (not a prologue store).
* "unauthenticated BR/BLR (PAC audit)": in fully signed code,
  function-pointer transfers go through BRAA(Z)/BLRAA(Z), which
  authenticate the target register before branching; each raw BR/BLR
  is a JOP hazard. The dominant benign shape is compiler switch
  dispatch, and a jump-table classifier keeps it off the worklist:
  the clang idiom `adrp xB ; add xB,xB,#off ; ldrsw xE,[xB,xI,lsl #2]
  ; adr xA,#. ; add xT,xA,xE ; br xT` computes its target as a
  PC-relative base plus a signed offset read from a statically
  addressed (read-only) table -- not a corruptible pointer -- so a BR
  to exactly that `xT` is dismissed. The match is strict-adjacency and
  deliberately narrow: for an audit the dangerous error is hiding a
  real hazard, so only this exact five-producer shape is recognized.
  What still surfaces: every BLR (a call has no jump-table form),
  linker long-branch veneers (`adr`+`br`, no table load), the compact
  `ldrb`-scaled table variant (a different idiom, left for a future
  pass), and any genuinely unclassified branch. The authenticated
  variants and RET differ in encoding and never match.
* "zero-discriminator authenticated BR/BLR (PAC audit)": the next
  rung of the same ladder. BRAAZ/BLRAAZ (and the B-key BRABZ/BLRABZ)
  authenticate their target, but against the constant-zero modifier,
  so a passing check proves only "some pointer signed with this key
  and discriminator zero" -- and that class is enormous, because the
  arm64e C ABI signs every plain function pointer IA with
  discriminator zero. An attacker who can overwrite the slot swaps in
  any other IA+0-signed pointer in the process; PAC then
  authenticates the substitute happily. This is the weakest live PAC
  form: above raw BR/BLR (which prove nothing) and below the
  diversified BRAA/BLRAA `Xn, Xm` forms, whose modifier -- typically
  the pointer's storage address, `__ptrauth`-style address diversity,
  possibly blended with a constant discriminator -- narrows the
  substitution class to pointers signed for that one slot. The
  encodings differ in the Z bit (24) and the modifier field, so the
  diversified forms never match, including the `Xm = SP` spelling;
  RETAA/RETAB are SP-diversified by construction and are a different
  encoding entirely. Findings are worklist items, not errors: IA+0 is
  the ABI floor wherever C function pointers must stay
  interchangeable across translation units, so each site is a
  candidate for a `__ptrauth`-qualified upgrade rather than a bug --
  which is exactly the audit-class framing.
* Calibration on macOS 26 (Apple's arm64e system binaries): zero
  unsigned LR spills across ls, zsh, ssh, and sshd -- Apple's signing
  is complete, and the window produces no false positives over
  thousands of signed prologues. Every raw BR in these four is the
  clang jump-table idiom (ls 1, ssh 3, sshd 3, zsh 22, bash 18 --
  each of the 47 byte-verified against the disassembly, zero
  mismatches), so the classifier empties the raw-BR worklist
  entirely; what would remain on other binaries is veneers, the
  `ldrb` variant, or real hazards. Over a binary that never opted
  into pac-ret the LR-spill flag reports every function by design --
  the assertion is simply false there (Homebrew's plain-arm64 gh:
  31109 spills and 20129 raw BLRs, Go emitting neither signing nor
  authenticated calls; its jump-table BRs use a different idiom and
  stay flagged too). That gap is exactly why the auto-arm gates on
  cpusubtype rather than firing everywhere: the four system binaries
  above are arm64e and now surface their worklists with no flag,
  while gh and the other
  Homebrew arm64 binaries stay silent unless `-a pac` is asked for
  explicitly.
* Zero-discriminator census over the same corpus (August 2026,
  independently byte-verified with a mask scan): ssh 6 braaz + 103
  blraaz, sshd 5 + 34, zsh 17 + 426, ls 1 + 1, bash 10 + 75, dyld
  23 + 146; no B-key Z form anywhere. The sampled shapes are exactly
  the ABI floor: a loaded function pointer, a CBZ NULL check, then
  `blraaz x8` (a C callback invocation), and in zsh a fully signed
  epilogue -- `autibsp` plus the auth-failure `brk` trap -- ending in
  `braaz x2`, a tail call through a C function pointer. dyld is the
  calibration for the rung above: alongside its 169 zero-discriminator
  sites it makes 571 `blraa` + 79 `braa` diversified transfers, so
  the upgrade the finding suggests is standard practice in the one
  binary whose job is authenticated dispatch. libcapstone and gh
  (plain arm64) contain none of these encodings at all.

## exclusive-monitor retry loop foldable into an LSE atomic (feature-gated: `-m lse`)

* The Armv8.0 atomic read-modify-write is a retry loop around the
  exclusive monitor; Armv8.1 FEAT_LSE does the whole thing in one
  wait-free instruction. Three shapes match, under strict adjacency
  plus exact branch targets -- the first check in the tree that
  validates a cycle:
  * `ldxr x8, [x0] ; add x9, x8, x1 ; stxr w10, x9, [x0] ;
    cbnz w10, back` -> `ldadd x1, x8, [x0]`
  * `ldxr x8, [x0] ; stxr w10, x1, [x0] ; cbnz w10, back` ->
    `swp x1, x8, [x0]`
  * `ldxr x8, [x0] ; cmp x8, x1 ; b.ne end ; stxr w10, x2, [x0] ;
    cbnz w10, back ; end:` -> `mov x8, x1 ; cas x8, x2, [x0] ;
    cmp x8, x1`
  ("LDXR/STXR loop foldable to LSE atomic (LSE)").
* The middle op picks the atomic: ADD -> LDADD, ORR -> LDSET, EOR ->
  LDEOR, BIC -> LDCLR directly; AND -> MVN + LDCLR, SUB -> NEG +
  LDADD, and ADD/SUB #imm12 -> MOV #imm + LDADD, where the pre-op's
  scratch reuses the loop's computed-value register -- dead by the
  same proof that justifies the fold (and excluded in-place, where
  the scratch would collide with the atomic's own destination, a
  CONSTRAINED UNPREDICTABLE encoding). Commutative ops accept either
  operand order; SUB and BIC need the loaded value on the left. All
  four sizes match, and the exclusive pair's ordering carries over
  exactly: LDAXR contributes the A suffix, STLXR the L.
* Equivalence rests on the architecture's own terms: both forms are
  the two official compiler mappings of the same C11 atomic RMW (GCC
  and LLVM emit the loop at `-march=armv8-a` and the single atomic
  at armv8.1+), and the LSE form is wait-free where the loop can
  livelock under contention. What the rewrite does NOT produce are
  the loop's scratches -- the computed new value and the
  store-exclusive status -- so emission defers until BOTH are
  overwritten before any read or control transfer: the tree's first
  dual-register death scan (armlint_advance_pending_lse; the swap
  and CAS shapes watch only the status, since SWP and CAS themselves
  preserve the old value).
* Real spellings, from Go: the status test is often the X-form CBNZ
  (the store-exclusive's W write zero-extends, so the wide view
  reads the same 0-or-1), and an X-form ALU between W-size
  exclusives is routine (the store keeps only the low bits, where
  add/sub and the logicals agree between widths; the wider
  destination is in the death set regardless). Both are accepted;
  the converse W-op-feeding-X-exclusives truncates and never
  matches.
* The CAS shape has its own contract. CAS compares its first operand
  against memory, stores the second on a match, and returns the old
  value in the first either way -- so the three-instruction rewrite
  re-materializes the comparand into the loaded register with a MOV,
  lets CAS deposit the old value exactly where the loop left it, and
  recomputes the flags with a trailing CMP whose operand order
  mirrors the original (Z alone is order-blind, N/C/V are not).
  Unlike the fetch-op shape, the only loop output the rewrite does
  not produce is the store-exclusive status, so the swap-style
  single-register watch covers it -- including gc's spelling where
  the status register IS the loaded register (REGTMP serves as
  both), in which case that one register's death covers the
  divergence on the success path (status 0 vs old value).
* Two CAS-only gates. First, the early exit must be `b.ne` to
  exactly the instruction after the closing CBNZ -- the tree's first
  forward branch-target validation -- so the compare-fail and
  store-success paths converge and one death scan covers both; the
  diverging shape (LLVM parks a CLREX block out of line) never
  matches. The compare-fail path also leaves the exclusive monitor
  armed where CAS does not, which well-formed code cannot observe (a
  STXR without its paired LDXR is CONSTRAINED UNPREDICTABLE).
  Second, the CMP must be the shifted-register form at exactly the
  exclusives' width, and only word/doubleword sizes match: an X
  compare over W exclusives would let the comparand's high bits veto
  a store CAS would perform, and byte/half loops compare through a
  zero-extended 32-bit CMP that byte-wide CASB/CASH cannot express.
  ZR passes where it never does elsewhere in the check: gc spells
  zero-expected CAS as `cmp w27, wzr` and CAS-to-zero stores WZR
  (698 of gh's 857 loops carry one or the other).
* Register sanity throughout: the address and operand must be
  loop-invariant, ZR participates nowhere, SP is no base, and the
  status register must be fresh (an alias of the address, value, or
  operand would clobber the next iteration -- and Rs == Rn or
  Rs == Rt is CONSTRAINED UNPREDICTABLE for STXR anyway). A branch
  into the loop interior is suppressed by the central side-entry
  gate; entry at the LDXR itself is the loop's own back edge and is
  fine.
* On the reference corpus the check is a Go-binary instrument: the
  macOS system binaries are all-LSE already (Apple's baseline is
  v8.1), while Homebrew's gh -- Go still targeting Armv8.0 --
  carries 2,255 exclusive loads. 1,398 of them sit in matching
  fetch-op skeletons, and 16 survive the death scan: inlined
  fetch-adds whose scratches provably die, each byte-verified
  (`c85ffc03 8b020063 c81bfc03 b5ffffbb` at `__text+0x139ac` is an
  in-place `ldaxr x3 ; add x3, x3, x2 ; stlxr w27, x3 ; cbnz x27`,
  with x3 overwritten two instructions after the loop and w27
  shortly after). The conservative discard of the other ~1,380 is
  the design working: Go's standalone atomic functions return the
  loop's computed value, which the single LD-atomic does not
  produce.
* The CAS side of the same census: 857 converging CAS skeletons,
  every one gc's intrinsic shape (acquire+release exclusives, REGTMP
  as both loaded and status register, the X-form CBNZ; zero
  diverging exits, zero immediate-comparand or CBNZ-as-compare
  variants). One survives the death scan, byte-verified at
  `__text+0x9b3d34`: `885ffcbb 6b1f037f 54000061 881bfca6 b5ffff9b`
  is `ldaxr w27, [x5] ; cmp w27, wzr ; b.ne +3 ; stlxr w27, w6,
  [x5] ; cbnz x27, -4` -> `mov w27, wzr ; casal w27, w6, [x5] ;
  cmp w27, wzr`, committed because gc happens to recycle REGTMP for
  an `adrp x27` page-address materialization one instruction after
  the loop's CSET. The ~856 discards are again the conservatism
  working: the CSET itself is fine (it reads the flags the trailing
  CMP reproduces), but gc then branches on the bool (inline sites)
  or returns (the out-of-line `atomic.Cas` bodies end `cset ; mov ;
  ret`) before REGTMP is rewritten -- and Go's register ABI returns
  results in R0+, so assuming caller-saved death at RET would be
  unsound there.
* Deliberately out of scope, recorded in TODO.md: diverging-exit
  CAS loops (the CLREX tail needs a second suggested branch and a
  two-path death argument), immediate-form comparands and the
  CBNZ-as-compare zero-expected shape (zero of each in gh),
  byte/half CAS via the extended-register compare (`cmp w8, w1,
  uxtb`), the compare-and-select MIN/MAX loops (`ldsmax` family),
  ST-form suggestions for unused results, and bitmask-immediate
  logic operands (the complemented constant is not always one MOV).

## MOV + cage-base ORR foldable to ADD immediate (feature-gated: `-m v8cage`)

```asm
movz x16, #0x11
orr  x0, x28, x16
```

folds to

```asm
add  x0, x28, #0x11
```

V8 runs with pointer compression: heap pointers are stored as 32-bit
offsets and rebuilt by merging them with a "cage base" kept in x28.
The base is 4GB-aligned, so its low 32 bits are zero and `orr` and
`add` compute the same result for any 32-bit offset -- which is why
V8 uses `orr` for the merge in the first place. When the offset is a
compile-time constant that fits an ADD immediate (12 bits, optionally
`LSL #12`), the materialize-then-merge pair collapses to one `add`.
The shape dominates V8 JIT output because every load of a read-only
root (`undefined` = cage + 0x11, `null`, `true`, `false`, the empty
string) is exactly this sequence: a JetStream 3 JIT dump carried
276,922 adjacent pairs, all with imm12-encodable offsets, and the
check reports the 95,864 of them whose scratch provably dies on the
fall-through path.

The match requires a direct 64-bit `ORR Rd, Rn, Rm` with `LSL #0`,
one operand produced by the active MOV chain, and the other operand
x28 exactly (either order); the chain's value must be at most 32 bits
and ADD-immediate-encodable. Bitmask-immediate values are excluded --
the sound MOV + ORR fold already owns them. The deleted MOV goes
through the same deferred register-liveness proof as the other MOV
folds.

Unlike the `-m` ISA gates, `v8cage` asserts a *runtime invariant* of
the scanned code rather than a hardware capability: nothing in the
instruction stream proves x28's alignment, so for arbitrary code the
rewrite is unsound (a set low bit in x28 makes `orr` and `add`
disagree). The check therefore stays silent unless the caller asserts
the invariant. It exists because the pattern pointed at a real V8
bug: `MacroAssembler::DecompressTagged(Register, Tagged_t)` guarded
on `IsImmAddSub(immediate)` -- the ADD encodability test -- and then
emitted `Orr`, which needs a (rarely matching) logical immediate and
so quietly materialized through a scratch register instead.

## LDR literal foldable to MOV/FMOV immediate

* `ldr w0, <literal>` where the pooled word is `0x2a` instead of
  `mov w0, #0x2a`; `ldr d0, <literal>` holding 1.5 instead of
  `fmov d0, #1.5`. GPR values fold when they are MOVZ / MOVN /
  bitmask-immediate encodable (exactly the assembler's `mov Rd, #imm`
  forms); FP values when FMOV-imm8 encodable (VFPExpandImm in
  reverse). An `LDRSW` literal materialises the SIGN-EXTENDED value,
  folding when that 64-bit value is mov-encodable
  (`ldrsw x3, <literal 0xfffffff6>` -> `mov x3, #-10`). A Q literal
  folds when the 128-bit pattern has an integer `MOVI`/`MVNI`
  spelling (AdvSimdExpandImm in reverse): both 64-bit halves equal
  -- every MOVI form replicates -- and the half byte-replicated
  (`.16b`), halfword-replicated (`.8h`, `LSL #0/8`, MOVI or MVNI),
  word-replicated (`.4s`, `LSL #0/8/16/24` or the MSL "shifting
  ones", MOVI or MVNI), or a per-byte 00/FF mask (`.2d`). The
  smallest element wins the rendering; the FP-vector immediates
  (`FMOV Vd.4s/2d, #imm8`) are not attempted. `PRFM` is not a load
  and never folds.
* The first binary-aware check: the literal is PC-relative, so the
  check reads the pooled bytes out of the scanned buffer itself. A
  target outside the buffer (an out-of-section pool) is silently
  skipped. Inline pools are hand-written-assembly and JIT territory
  -- compilers on AArch64 place constants in data sections reached
  via `ADRP` -- which is precisely where a reviewer wants the hint.
* A one-for-one rewrite: same destination register, no other register
  or flag touched, and the loaded value is reproduced exactly, so the
  finding emits immediately with no liveness proof. What it saves:
  the memory access -- load-use latency and a cache line -- plus the
  pool slot when nothing else references it.
* V8 JIT dumps: `tools/v8dump2elf.py` keeps each code object's inline
  constant pool in the section, so this check can read the pooled
  values; scan that output with `-m v8pool`, which recognizes V8's
  self-describing pool marker (`LDR XZR, (literal)` whose imm19
  counts the data words that follow) and steps over the pools rather
  than decoding embedded constants as instructions. Like `v8cage`
  the bit asserts knowledge about the scanned stream, not an ISA
  capability: in arbitrary code a literal load to XZR is a legal
  discarded load followed by real instructions, so the skip stays
  off by default.

## ADR + single use of its target foldable to the direct form

* `adr x8, L ; ldr x8, [x8]` instead of `ldr x8, L`: the consumer
  has a direct PC-relative form of its own, so the address never
  needs to exist in a register. The load form covers every
  literal-capable width -- `LDR` W/X, `LDRSW`, and SIMD&FP S/D/Q
  (byte/halfword loads have no literal form) -- at zero offset, and
  performs the identical access. `adr x16, L ; br x16` folds to
  `b L`, dropping an indirect branch (BTB/indirect-predictor
  pressure and mispredict risk) for a fully static one.
* Encodability, load form: the literal's word-scaled imm19 anchors
  at the LOAD's PC, one instruction after the ADR's, so the target
  must be 4-byte aligned (ADR can name any byte) and the re-anchored
  displacement must still fit +/-1MB -- it can fall off the low edge
  when the ADR named exactly -1MB. Branch form: `B` reaches
  +/-128MB, strictly covering ADR's +/-1MB, so no range check at
  all. The target may lie outside the scanned buffer; the fold never
  reads the pointed-to data, so unlike the literal-constant check no
  buffer is required.
* Deadness: the rewrite deletes the ADR. A load destination that IS
  the address register kills it structurally; other load
  destinations (all FP ones included) defer through the forward
  register-liveness scan. `BR` never writes the address register and
  the linear scan cannot follow the branch, so v1 folds only
  x16/x17 (IP0/IP1): the ABI reserves them as veneer scratch, and
  code at the target is not entitled to receive values in them
  across exactly this shape -- the general-register case would need
  liveness at the TARGET, future work. `BLR` is excluded outright (a
  callee legitimately receives registers, x8 -- the indirect-result
  pointer -- in particular). ADRP does not open (page arithmetic);
  ADR to XZR is a dead write.
* Composes with the literal-constant fold: once the load is
  rewritten to `ldr x8, L`, that check may further fold it to a
  `mov`/`movi` when the pooled value is immediate-encodable.

## FMUL + FNEG foldable to FNMUL

* `fmul d0, d1, d2 ; fneg d0, d0` instead of `fnmul d0, d1, d2`.
  `FNMUL`'s pseudocode is `FPMul` followed by `FPNeg` of the
  ALREADY-ROUNDED product -- negation is a pure sign flip, applied
  after rounding and raising nothing -- which is exactly what the
  two-instruction spelling computes. The fold is therefore bit-exact
  in every FPCR rounding mode with identical FPSR exceptions, NaNs
  included: both spellings apply the same `FPNeg` to the same `FPMul`
  result. All three scalar writes zero the vector register above the
  written lane, so the final 128-bit state is identical too.
* The unsound sibling is deliberately not matched: negating an
  *operand* before the multiply (`fneg d1, d1 ; fmul d0, d1, d2`)
  computes `round(-(a*b))`, which differs from `FNMUL`'s
  `-(round(a*b))` under the directed rounding modes (`FPCR.RMode` =
  RP or RM) -- the two agree only under round-to-nearest, and armlint
  cannot know the dynamic mode.
* Soundness: the `FNEG` must read the `FMUL`'s destination (`Rn` =
  the product register). An in-place `fneg dd, dd` overwrites the
  product on the spot -- the same structural argument as the integer
  producer folds -- and reports immediately; a fresh destination
  defers through the FP/vector-register liveness scan until the
  product register provably dies. The scan watches all six views
  (B/H/S/D/Q/V) of the register and treats written vector operands
  as read-modify-writes unless their class provably overwrites in
  full (scalar FP ops, FP loads) -- lane inserts, accumulators and
  friends can never wrongly commit a finding. No aliasing
  exclusions are needed: the rewrite reads the multiply's own sources
  at its position, and even in-place multiplies read before writing
  in both spellings.
* Single and double precision fold; half precision (FEAT_FP16) is
  not matched, consistent with the FMOV folds.
* What it saves: one instruction, and the dependent `FNEG` leaves
  the critical path -- `FNMUL` costs the same as `FMUL` on current
  cores, so the negation is free.

## MOV #0 + use foldable to ZR

* `mov xd, #0 ; <use xd>` instead of `<use xzr>`. Five consumer
  families:
  * An integer **store** (B/H/W/X) with `Rt == mov_rd`, in either
    spelling -> `st(u)r <wzr/xzr>, [...]`. Saves the MOV when
    Rt-only.
  * `ADD/SUB/ADDS/SUBS` (shifted-register, LSL #0) with Rn or Rm
    == mov_rd -> the same op with that operand as ZR. `CMP`/`CMN`
    aliases are rendered when Rd == ZR + S-variant.
  * `AND/ORR/EOR/ANDS` (shifted-register, LSL #0, N = 0) with Rn
    or Rm == mov_rd -> the same op with the operand as ZR. `TST`
    alias when Rd == ZR + ANDS.
  * `CSEL/CSINC/CSINV/CSNEG` with Rn or Rm == mov_rd -> the same
    select with that slot as ZR (legal in either slot for all
    four). Both slots zero is left to the
    [CSEL identity](#csel-same-operand-identity-csel-rd-rn-rn-cond),
    a strictly better rewrite.
  * Register-form `CCMP/CCMN` with Rn == mov_rd -> `ccmp ZR, Rm,
    #nzcv, cond`. Only the left operand: an Rm-slot zero already
    folds to the `#0` immediate form via the
    [CCMP fold](#mov--ccmpccmn-foldable-to-immediate-form), which
    deletes the register read outright.
* The consumer's instruction count does not change, but the MOV
  becomes dead (assuming no other read of `xd`). Further
  simplification of forms like `ADD Rd, Rn, XZR -> MOV Rd, Rn` or
  `SUB Rd, XZR, Rm -> NEG Rd, Rm` is left to the reader.
* The Rn (base) slot of STR is intentionally excluded: register 31
  in addressing means SP, not ZR, so replacing the base would
  silently change semantics.
* Both spellings of the store are decoded. The unsigned-offset form
  scales its imm12 by the transfer size and cannot go negative; the
  unscaled `STUR` form carries a signed byte count. Nothing about this
  rewrite turns on which one the assembler picked -- only the data
  register changes, and the address is copied through untouched -- so
  reading one and not the other was a blind spot, the same class of
  error as the LDUR blindness in the
  [pair coalescer](#adjacent-ldrstr-foldable-into-ldpstp). The
  unscaled decoder covers loads as well, and only stores are taken: a
  load into `mov_rd` overwrites the zero rather than reading it, so
  there is no ZR to substitute.
* Corpus: **525** findings across 28.4M instructions. The store arm
  accounts for 195 of them -- 184 in the unsigned-offset spelling and
  **11** in the unscaled one, all 11 in librustc_driver. Both realize
  at about the same rate off their candidate pools (184 of 3,235 and
  11 of 225, 5.7% against 4.9%), which is the point: what was missing
  was the *spelling*, not a different deadness story, and what still
  gates both is the forward liveness scan proving the zero register
  dead. (These figures are post-`insn_writes_no_gpr`. This check was
  the largest victim of the compare-is-not-a-kill bug, losing 310 of
  835 -- 285 of them in the SUB arm, where `mov x0, #0 ; sub x3, x0,
  x2` is routinely followed by a compare of `x0`.) The dominant unscaled shape is LLVM clearing trailing bytes
  off a frame pointer, where the negative displacement leaves the
  assembler no choice:

  ```
  movz w14, #0
  sturb w14, [x12, #-3]   ->  sturb wzr, [x12, #-3]
  ```

  In librustc_driver the same unrolled clear emits `sturb` at -3, -2
  and -1 and then `strb` at 0 -- so the check had been reporting the
  last of four and passing over the other three.
* Two store addressing forms remain unread, the writeback and
  register-offset ones, where the ZR substitution would also be sound
  (only Rt changes, so the base update and the index are irrelevant
  to it). Measured rather than assumed: **5** and **10** candidate
  sites corpus-wide, which at the realization rate above is about one
  finding. Recorded in [TODO.md](TODO.md) and not implemented.
* Side entries dominate this check's false positives on optimized
  code -- by selection: were the pair straight-line, the compiler
  would have used ZR directly, so the findings that survive skew
  toward the shared-return shape, `mov x8, #0` on one arm joining a
  common `mov x0, x8 ; ret` tail whose other predecessors arrive
  with a live, non-zero register (every one of the 67 findings on
  /bin/bash and 38 on /bin/zsh was this). The central emission gate
  (`armlint_finding_has_side_entry`) drops a finding whose use slot
  is a direct-branch target.

## MOV + register-offset LDR/STR foldable to immediate offset

* `mov x8, #256 ; ldr x0, [x1, x8]` instead of `ldr x0, [x1, #256]`.
  A MOV chain materialises a constant whose only use is the index
  register of a register-offset load or store; the access already has
  an immediate-offset form, so the constant folds into it and the MOV
  dies. The index's scale carries into the byte offset:
  `mov x8, #4 ; ldr x0, [x1, x8, lsl #3]` -> `ldr x0, [x1, #32]`.
* The rewrite is the scaled unsigned-offset form when the byte offset
  is non-negative, a multiple of the access size, and at most
  4095 x size; otherwise the unscaled `LDUR`/`STUR` form when it lies
  in `[-256, 255]`: `mov x8, #3 ; ldr x0, [x1, x8]` ->
  `ldur x0, [x1, #3]`, and an X-form MOVN chain reaches the negative
  side, `mov x8, #-8 ; ldr x0, [x1, x8]` -> `ldur x0, [x1, #-8]`.
  Constants outside every form are not flagged.
* Consumers: the integer register-offset family -- the zero- and
  sign-extending loads (`LDRB`/`LDRH`/`LDR`, `LDRSB`/`LDRSH`/`LDRSW`;
  `PRFM` is excluded, its Rt being a prefetch operation) and the
  `STRB`/`STRH`/`STR` stores. SIMD&FP accesses are not matched. Only
  the `LSL`/`UXTX` index option (a full 64-bit index) qualifies: the
  chain pins that index's value exactly -- a W-form chain also
  qualifies, since its W write zeroed `X[63:32]` -- while the
  `UXTW`/`SXTW`/`SXTX` extend options re-interpret the index register
  and are left alone.
* Soundness and the dead-constant question: the fold's saving is the
  deleted MOV, so unlike the strength-reduction folds (whose consumer
  rewrite pays for itself), the finding is deferred through the same
  forward register-liveness scan as the
  [`MOV #0` fold](#mov-0--use-foldable-to-zr) and emitted only once
  the constant register is provably dead -- overwritten before any
  read or control transfer. A load whose destination IS the constant
  register kills it at the consumer itself and reports immediately.
  The base register must not be the constant (the rewrite would still
  read it), nor may a store's data register be. `Rn = 31` means SP in
  both the register-offset and immediate-offset forms, so SP-based
  accesses fold soundly.
* What it saves: one instruction -- the materialising MOV -- and the
  register that held the index. The access itself neither gains nor
  loses: the register-offset and immediate-offset forms cost the same
  on current cores.

## MUL + ADD/SUB foldable to MADD/MSUB

* `mul xt, xa, xb ; add xd, xt, xc` -> `madd xd, xa, xb, xc`.
  Standard array-indexing pattern (`base + i*stride`). Same for the
  commuted ADD (`add xd, xc, xt`) and for SUB with Rm=xt
  (`sub xd, xc, xt -> msub xd, xa, xb, xc`).
* `sub xd, xt, xc` is NOT folded: MSUB computes `Ra - Rn*Rm`, not
  `Rn*Rm - Ra`. There is no AArch64 instruction matching the
  latter form in one op.
* `mul xt, xa, xb ; neg xt, xt` (the `sub xt, xzr, xt` form, so the
  accumulator is XZR) folds to `mneg xt, xa, xb` -- the `MSUB`-with-ZR
  alias -- and is reported separately as "MUL + NEG foldable to MNEG".
* Soundness: the rewrite deletes the MUL, so the product register
  must be dead afterward -- an ADD/SUB that overwrites it (`Rd == Rt`)
  reports immediately, and one writing a fresh register defers
  through the forward register-liveness scan (`Rd = 31`, a dead
  write, is excluded). The accumulator operand must not equal Rt
  (otherwise the ADD reads the MUL's result twice while the MADD
  rewrite reads pre-MUL values, diverging), and an ADD whose
  accumulator is XZR is a multiply + register copy, not an
  accumulate -- a ZR-accumulator MADD would just respell the MUL.
* S-variants (ADDS/SUBS) skipped: MADD/MSUB have no flag-setting
  form. Widths must match (both W or both X).
* Fuse win (a "producer into consumer" fold, see the shift fold):
  `MADD`/`MSUB` has the same latency as the bare multiply, so the fold
  removes the dependent `ADD`/`SUB` essentially for free, plus one
  instruction.

## SMULL/UMULL + ADD/SUB foldable to SMADDL/UMADDL

* The widening (32x32 -> 64) analogue of the MUL+ADD check.
  `smull xt, wa, wb ; add xt, xt, xc` -> `smaddl xt, wa, wb, xc`.
  Same for the commuted ADD (`add xt, xc, xt`) and for SUB with
  Rm=xt (`sub xt, xc, xt -> smsubl xt, wa, wb, xc`). The `UMULL`
  forms fold to `UMADDL` / `UMSUBL`. `SMULL`/`UMULL` are the
  `Ra == XZR` aliases of `SMADDL`/`UMADDL`.
* Width asymmetry vs. the MUL+ADD check: the 32x32 product is
  64-bit, so the consumer ADD/SUB **must** be X-form. A W-form
  consumer would operate on only the low 32 bits and is rejected.
  In the rewrite the multiply operands stay W-form (`wa`, `wb`)
  while the destination and accumulator are X-form.
* `sub xt, xt, xc` is NOT folded: `SMSUBL` computes `Xa - Wn*Wm`,
  not `Wn*Wm - Xa` -- the same asymmetry that blocks `sub xd, xt, xc`
  in the MUL+ADD check.
* `smull xt, wa, wb ; neg xt, xt` folds to `smnegl xt, wa, wb` (and the
  `UMULL` form to `umnegl`) -- the long `MSUB`-with-ZR alias -- reported
  as "SMULL/UMULL + NEG foldable to SMNEGL/UMNEGL".
* Soundness (identical to MUL+ADD): the rewrite deletes the multiply,
  so the 64-bit product must be dead afterward -- an ADD/SUB that
  overwrites Xt reports immediately, one writing a fresh register
  defers through the forward register-liveness scan (`Rd = 31`
  excluded), the accumulator operand must not equal Xt, and an
  XZR-accumulator ADD (a multiply + register copy) is rejected.
  Signedness must match the producer (`SMULL` pairs only with
  `SMADDL`/`SMSUBL`, `UMULL` only with `UMADDL`/`UMSUBL`). S-variants
  (ADDS/SUBS) are skipped (no flag-setting long MAC); `SMULL`/`UMULL`
  writing to ZR is excluded.
* Fuse win: same as `MUL + ADD -> MADD` above -- `SMADDL`/`UMADDL` has
  the latency of the widening multiply, so the dependent add is removed
  essentially for free, plus one instruction.

## NEG + ADD/SUB foldable to SUB/ADD

* `neg xt, xs ; add xd, xc, xt` -> `sub xd, xc, xs`. The ADD is
  commutative, so `neg xt, xs ; add xd, xt, xc` folds the same
  way. The SUB consumer mirrors:
  `neg xt, xs ; sub xd, xc, xt` -> `add xd, xc, xs`.
* `sub xd, xt, xc` is NOT foldable: computes `-xs - xc`, which
  has no single-instruction AArch64 form.
* A `CSEL` consumer folds too, because `CSNEG`'s else-branch is a
  negation (`Rd = cond ? Rn : -Rm`):
  * `neg xt, xs ; csel xd, xn, xt, cc` -> `csneg xd, xn, xs, cc`
    (negation in the else slot; the condition carries over).
  * `neg xt, xs ; csel xd, xt, xm, cc` -> `csneg xd, xm, xs, !cc`
    (negation in the then slot; the rewrite swaps the operands and
    inverts the condition).
  Only `CSEL` proper (op2 = 00) matches -- `CSINC`/`CSINV`/`CSNEG`
  have different else-branches. The rewrite reads the same NZCV the
  `CSEL` did (a `NEG` writes no flags), so no flag-liveness scan is
  needed, and it reads `xs`, which the adjacent pair leaves unchanged
  even for the in-place `neg xt, xt`. `AL`/`NV` conditions are
  excluded: `ConditionHolds` treats both as always-true, so such a
  select is a plain `MOV` and the then-slot inversion (`AL` <-> `NV`)
  would still be always-taken. A `CSEL` reading `xt` in both slots is
  the same-operand identity, which the CSEL identity check owns.
  Unlike the `ADD`/`SUB` consumers, the surviving operand may be
  `XZR` (`csneg xd, xzr, xs, cc` -- `cond ? 0 : -xs` -- has no
  shorter form). Reported as "NEG + CSEL foldable to CSNEG"; the
  shape appears when codegen materialises a negation and then
  selects between the original and negated value (`abs`/`nabs`-style
  branchless idioms).
* Soundness: the rewrite deletes the NEG, so its destination must be
  dead afterward -- a consumer that overwrites it (`Rd == Rt`)
  reports immediately, and one writing a fresh register defers
  through the forward register-liveness scan (`Rd = 31` -- a dead
  write, or a discarded select -- is excluded). The ADD/SUB
  accumulator operand must not equal Rt -- otherwise both ADD/SUB
  sources are `-xs`, computing `-2*xs` or `0` instead of the
  additive identity the fold assumes -- nor XZR, whose shapes are
  double negations (a copy of the negation, or the negation of it),
  not accumulates.
* S-variants (ADDS/SUBS, NEGS) are skipped: flag definitions
  differ between the original and the rewrite. Widths must match
  (both W or both X). NEG of XZR (computes 0) is excluded.
* Fuse win (see the shift fold): the negate is absorbed into the
  consumer's sign -- one fewer instruction, the `NEG` off the critical
  path.

## MVN + AND/ORR/EOR foldable to BIC/ORN/EON

* The logical-op counterpart of the NEG fold. `mvn wt, ws` (bitwise
  NOT) feeding a logical op collapses into that op's built-in
  negated-operand form:
  * `mvn wt, ws ; and  wd, wn, wt` -> `bic  wd, wn, ws`
  * `mvn wt, ws ; orr  wd, wn, wt` -> `orn  wd, wn, ws`
  * `mvn wt, ws ; eor  wd, wn, wt` -> `eon  wd, wn, ws`
  * `mvn wt, ws ; ands wd, wn, wt` -> `bics wd, wn, ws`
* All four consumers are commutative, so the `mvn` result may sit in
  the consumer's Rn or Rm slot; the fold puts the other operand in Rn
  and `ws` in the negated Rm slot. (`ANDS` -> `BICS` is sound because
  both set N/Z from the same result with C = V = 0.)
* Soundness (mirrors the NEG fold): the rewrite deletes the `mvn`, so
  its destination must be dead afterward -- a consumer that
  overwrites it (`Rd == wt`) reports immediately, and one writing a
  fresh register defers through the forward register-liveness scan
  (`Rd = 31` -- a dead write, or the `TST` alias for `ANDS` -- is
  excluded). The independent operand must not also be `wt` -- the
  `mvn wt, ws ; and wt, wt, wt` degenerate is a self-op, reported by
  the self-op check instead -- nor XZR (`orr wd, wzr, wt` is the
  `MOV` alias, whose fold is `MVN` itself; the `AND`/`EOR` forms are
  constants). The shifted `MVN` form is not handled
  (the consumer would shift the complemented value, not `ws`). `MVN`
  to ZR, and `MVN` of ZR (the all-ones `mov wd, #-1` idiom), are
  excluded.
* A `CSEL` consumer folds to `CSINV`, whose else-branch is a
  complement (`Rd = cond ? Rn : ~Rm`) -- the exact mirror of the
  [`NEG` + `CSEL` -> `CSNEG`](#neg--addsubcsel-foldable-to-negated-operand-form)
  fold: the else slot carries the condition over
  (`mvn wt, ws ; csel wd, wn, wt, cc` -> `csinv wd, wn, ws, cc`),
  the then slot swaps operands and inverts it. AL/NV, `Rd = 31`,
  both-slots (check_csel_self's shape) and width mismatches are
  excluded; the destination overwriting `wt` reports immediately,
  a fresh destination defers through the register-liveness scan.
* Fuse win (see the shift fold): the `MVN` is absorbed into the
  consumer's negated-operand form -- one fewer instruction, the `MVN`
  off the critical path.

## ADD + LDR foldable to register-offset LDR

* `add xt, xn, xm{, lsl #s} ; ldr xt, [xt]` ->
  `ldr xt, [xn, xm{, lsl #s}]`. Saves the ADD by letting the LDR
  do the address arithmetic via its register-offset addressing
  mode.
* Shift constraint: AArch64's LDR (register) accepts only LSL #0
  or LSL #log2(access\_size) -- 0 or 1 for LDRH, 0 or 2 for LDR W,
  0 or 3 for LDR X. The check filters to those amounts.
* Soundness: the rewrite deletes the ADD, so its destination must be
  dead afterward. A load whose `Rt` equals the ADD's Rd proves that
  structurally -- the write to Wt/Xt destroys the pre-LDR address
  value -- and reports immediately.
* The sign-extending loads (`LDRSB`/`LDRSH`, Wt or Xt; `LDRSW`) fold
  identically: they too overwrite the full X register named by `Rt`
  (a W-form write zeros the upper half) and have register-offset
  forms with the same shift rule. `PRFM`, which shares the encoding
  family, is excluded -- its `Rt` field is a prefetch operation, not
  a destination, so the address register stays live.
* Stores and fresh-destination loads fold too, through the deferred
  tier: `add xt, xn, xm ; str x0, [xt]` -> `str x0, [xn, xm]` (same
  for `STRB`/`STRH`, reported as "ADD + STR foldable to
  register-offset STR"), and `add xt, xn, xm ; ldr xq, [xt]` with
  `xq != xt`. Neither consumer overwrites `xt`, so emission defers
  through the forward register-liveness scan and reports only once a
  later instruction overwrites `xt` before any read or control
  transfer. A store whose data register is `xt` never folds -- the
  rewritten store would read the deleted sum.
* Rn = XZR in the ADD is excluded because Rn = 31 in the LDR's
  register-offset form means SP, a semantic mismatch. Rm = XZR
  (degenerate ADD) is skipped for cleanliness.

## SXTW + register-offset LDR foldable into the load

* The extend analogue of the check above: where that absorbs an `ADD`
  into the load's register offset, this absorbs a sign-extend into the
  offset's *extend* modifier. The canonical 32-bit-signed-index idiom:
  * `sxtw x0, w1 ; ldr x0, [x3, x0]` -> `ldr x0, [x3, w1, sxtw]`
  * `sxtw x0, w1 ; ldr x0, [x3, x0, lsl #3]`
    -> `ldr x0, [x3, w1, sxtw #3]`
  All four zero-extending sizes (LDRB/LDRH/LDR W/LDR X), the
  sign-extending loads (`LDRSB`/`LDRSH`, Wt or Xt; `LDRSW`), and the
  `STRB`/`STRH`/`STR` stores are handled, and the scale bit carries
  over.
* Why it helps: one fewer instruction, and the sign-extend leaves the
  critical path -- the load's address-generation unit does it for free
  rather than a separate dependent op feeding the load. (Same profile
  as the LSL/extend folds; this is the load-addressing form of it.)
* Soundness (mirrors the `ADD + LDR` register-offset check): the
  consumer must use the LSL/UXTX index option (a full 64-bit register
  offset, identical to the `SXTW` result) with `Rm == Xt`. The rewrite
  deletes the `SXTW`, so `Xt` must be dead afterward: a load with
  `Rt == Xt` proves that structurally and reports immediately; a store
  (reported as "SXTW + register-offset STR foldable into the store"),
  or a load into a different register, defers through the forward
  register-liveness scan until `Xt` is provably overwritten before any
  read or control transfer. A store whose data register is `Xt` never
  folds (the rewritten store would read the deleted extend's result),
  and `PRFM` is excluded (its `Rt` is a prefetch operation rather than
  a destination). The base `Rn` must NOT be `Xt`: with the `SXTW`
  folded away the base would read its pre-`SXTW` value, changing the
  address. `SXTW` into ZR is excluded.
* Only `SXTW` is matched: the load-index extend is word-width, and a
  standalone 32->64 zero-extend is normally a `W`-register `MOV`, not a
  literal `UXTW` instruction.

## load + sign-extend foldable to LDRSB/LDRSH/LDRSW

* A zero-extending load immediately re-extended with the sign is the
  sign-extending load:
  * `ldrb w3, [x1] ; sxtb w3, w3` -> `ldrsb w3, [x1]`
  * `ldrb w3, [x1] ; sxtb x3, w3` -> `ldrsb x3, [x1]` (the X-form
    consumer widens to 64 bits, so the fold is the `Xt` form)
  * `ldrh w4, [x1, #2] ; sxth w4, w4` -> `ldrsh w4, [x1, #2]`
  * `ldr w2, [sp, #4] ; sxtw x2, w2` -> `ldrsw x2, [sp, #4]`
* Fuse win (see the shift fold): one fewer instruction, and the
  extension moves off the critical path into the load's own writeback
  -- the dependent `SXT` no longer executes as a separate ALU op.
* Soundness (structural): the `SXT` reads and overwrites the load's
  `Rt`, so the zero-extended intermediate is provably dead, and the
  rewrite performs the identical memory access -- same address, same
  size -- with only the extension behaviour changed to match what the
  pair computed.
* The W-form sign-extending loads (`LDRSB`/`LDRSH Wt`) are a second
  producer family: re-widened to 64 bits by an X-form consumer, the
  pair is exactly the X-form load.
  * `ldrsb w8, [x9] ; sxtb x8, w8` -> `ldrsb x8, [x9]`
  * `ldrsb w8, [x9] ; sxtw x8, w8` -> `ldrsb x8, [x9]`
  * `ldrsh w8, [x9, #2] ; sxth x8, w8` -> `ldrsh x8, [x9, #2]`
  Here the threshold need only be AT OR ABOVE the access width:
  every bit from the width up is a copy of the loaded sign, so
  `SXTB`, `SXTH` and `SXTW` all reproduce what the X-form load
  computes. The W-form consumer is excluded -- after a W-form
  sign-extending load it changes nothing, which is the
  redundant-sext check's finding, not a fold.
* For the zero-extending producers, the consumer's sign threshold
  must equal the load's access width.
  Below it (`ldr w2, [x1] ; sxtb w2, w2`) the `LDRS` rewrite would
  shrink the memory access, which is not architecturally identical
  (alignment, permissions and watchpoints are checked per byte
  accessed) -- the same exclusion applies to below-width thresholds
  after a sign-extending load (`ldrsh w8, [x9] ; sxtb x8, w8`),
  where bit 7 of the halfword is data, not its sign. Above it
  (`ldrb w3, [x1] ; sxth w3, w3`) the consumer sign-extends from a
  bit the load provably zeroed -- a no-op worth removing, but not
  this rewrite. An X-form load never folds: LDR Xt is already
  full-width, and the X-form sign-extending loads are already
  extended through bit 63 (their re-extensions are the
  redundant-sext check's no-ops).
* v1 matches the unsigned-offset addressing form only, like the other
  load-rewriting folds. The unscaled, pre-/post-indexed and
  register-offset forms have `LDRS` equivalents and could fold the
  same way.

## ADD + LDR foldable to immediate-offset LDR

* `add xt, xn, #a ; ldr xt, [xt, #b]` -> `ldr xt, [xn, #(a+b)]`,
  with `b == 0` the most common case. The immediate-form
  complement of the register-offset fold: same deadness
  soundness argument, but the ADD's constant offset (plus the
  access's, if any) moves into the unsigned immediate slot.
  The sign-extending loads (`LDRSB`/`LDRSH`, Wt or Xt; `LDRSW`)
  fold the same way -- they too overwrite the full X register named
  by `Rt` and have unsigned-offset forms; `PRFM` is excluded (its
  `Rt` is a prefetch operation, so the address register stays
  live).
* Stores and fresh-destination loads fold through the deferred tier
  (mirroring the register-offset check): `add xt, xn, #a ;
  str x0, [xt, #b]` -> `str x0, [xn, #(a+b)]` (same for
  `STRB`/`STRH`, reported as "ADD + STR foldable to immediate-offset
  STR"), and `add xt, xn, #a ; ldr xq, [xt]` with `xq != xt`.
  Neither consumer overwrites `xt`, so emission defers through the
  forward register-liveness scan and reports only once `xt` is
  provably overwritten before any read or control transfer. A store
  whose data register is `xt` never folds (the rewritten store would
  read the deleted sum). The canonical stack-spill-through-a-temp --
  `add x8, sp, #32 ; str x0, [x8]` -> `str x0, [sp, #0x20]` -- is
  the flagship store shape.
* Both register files are matched. An access's data register has no
  bearing on its address arithmetic, so the SIMD&FP forms fold on the
  same terms as the integer ones, with the log2 transfer size coming
  from the encoding -- 16 bytes for a `Q`, 8 for a `D` -- and setting
  the grid the combined offset must land on. Two things do turn on the
  register file, and both cut the same way: a SIMD&FP data register can
  never alias the integer base, so it is neither the
  read-the-deleted-sum case that blocks a store fold nor the
  load-into-its-own-base that proves the sum dead on the spot. Every
  SIMD&FP site defers to the forward liveness scan; there is no
  structural tier there at all.
* Both spellings of the access are decoded. AArch64 gives every
  base-plus-offset access two encodings -- the unsigned-offset form,
  whose `imm12` is scaled by the transfer size and cannot go negative,
  and the unscaled `LDUR`/`STUR` form, whose `imm9` is a signed byte
  count -- and an assembler picks per instruction. Which one it picked
  says nothing about whether the sum folds, so both decode to a signed
  byte displacement and mix freely.
* Encoding constraint: the combined byte offset must encode in one
  spelling or the other -- non-negative, on the access-size grid and
  under `4095 * size` for the scaled form, or within `-256..255` for
  the unscaled one. Neither property can be inferred from the ADD's
  immediate the way it could when every input was scaled, because an
  unscaled input carries no alignment guarantee; the sum itself is
  tested. That also admits sums the old test refused: a misaligned ADD
  immediate under a *scaled* access lands outside `imm12` but inside
  `imm9`, so `add x3, x1, #4 ; ldr x3, [x3]` folds to
  `ldur x3, [x1, #4]`. The output spelling is chosen from the sum
  alone. The ADD's `sh=1` form (`imm12 << 12`) is supported.
  The `-256` floor is unreachable from this producer -- ADD-immediate
  is non-negative and `imm9` bottoms out at `-256`, so the sum never
  goes below it -- but the guard states the encoding's range rather
  than this caller's reach.
* Rn = SP (Rn = 31 in ADD-imm) is intentionally flagged: ADD-imm
  and LDR-uimm both encode 31 as SP, so the canonical stack-
  relative load pattern (`add xt, sp, #imm ; ldr xt, [xt]`) folds
  correctly. That includes `imm == 0` -- the MOV-from-SP alias:
  `mov xt, sp ; ldr xt, [xt]` -> `ldr xt, [sp]` (rendered with the
  `mov` spelling). `imm == 0` with a GPR source stays excluded;
  that is the redundant ADD `check_add_sub_zero` owns. Rd = SP in
  the ADD is excluded -- folding would discard the observable SP
  update.
* SUB-immediate is not folded. The reason used to be that the LDR
  unsigned-offset form has no negative-immediate encoding; with the
  unscaled spelling understood that is no longer true, and the only
  remaining reason is that the pending slot opens on ADD-immediate
  alone. A SUB producer whose sum lands in `imm9` would fold; it is
  simply not looked for.
* Side entries: a memory op that is itself the target of a direct
  branch (B/BL, B.cond/BC.cond, CBZ/CBNZ, TBZ/TBNZ) never closes a
  fold. The entering path skips the ADD -- the list-walk idiom
  `p = p->next` re-enters at the load with the base holding a node
  pointer, not the ADD's sum -- so the merged instruction would apply
  the immediate on a path that never added it. The gate reads the
  branch-target map that armlint_state_set_buffer builds once per
  section from the raw words; without a buffer it is off (bufferless
  callers keep the old behavior). The map deliberately
  under-approximates: indirect branches (BR, jump tables) and
  cross-section entries are invisible, so a residual false positive
  is possible where such an entry lands exactly on a flagged memory
  op. A branch onto the ADD itself does not suppress the fold --
  that entry executes the whole pair. Data words that decode as
  branches can only add spurious targets, i.e. suppress a finding,
  never unsuppress one. The same rule is enforced centrally for
  every multi-instruction finding at emission
  (`armlint_finding_has_side_entry`: no instruction of the rewritten
  window after the first may be a branch target); this check gates
  at close anyway so a doomed pairing never occupies the shared
  deferral slot.
* Corpus: 7,394 findings across 28.4M instructions (6,304
  librustc_driver, 903 bash, 77 dyld, 58 libcrypto, 51 ssh, 1 go).
  Two coverage fixes account for 1,956 of those: teaching the check
  the unscaled spelling added 126, and teaching it the SIMD&FP
  register class added 1,830. The second cost 18 pair findings it did
  not intend to: the newly-matched SIMD&FP accesses open deferrals of
  their own, and `defer_dead_mov`'s single slot silently drops an
  earlier one when a second arrives, so a pending ADD + LDP finding
  waiting on its kill can now be evicted by an FP access two
  instructions later. Net +1,812, and the eviction is the tracked
  multi-slot item in [TODO.md](TODO.md) rather than anything specific
  to this check. The unscaled figure is
  far below what the candidate population suggests -- 23,503 adjacent
  ADD + LDUR/STUR pairs exist in the corpus, 9,124 of them with a sum
  that encodes -- and the gap is structural, not a further blind spot.
  The immediate tier is a load into its own base (`add x3, x1, #16 ;
  ldr x3, [x3]`), which proves the sum dead on the spot; everything
  else defers to the forward liveness scan, which usually refuses. That
  tier is **21.3%** of the encodable scaled population and **1.4%** of
  the unscaled one, because the two spellings sit in different idioms:
  a scaled offset is the compute-an-address-and-dereference-it shape,
  while the unscaled one appears on field accesses off a long-lived
  base that the ADD does not consume (the next instruction is another
  access off the same base at 10.2% of unscaled sites against 4.4% of
  scaled ones). The remaining ~8,000 are visible to the check and
  refused on soundness, which is a different backlog entry from being
  unable to see them. One specific reason accounts for much of it --
  the base having a second consumer, which forces the deferred scan to
  refuse -- and that is what the multi-use fold below now claims,
  3,188 sites drawn from this backlog and from the scaled, SIMD&FP and
  pair populations alongside it.
* Strict adjacency is the other boundary, and it is a boundary between
  the two checks rather than a condition on the rewrite. The pending
  slot clears on any instruction that is not the consumer, so a base
  whose sole use sits even one instruction further on is invisible
  here; the multi-use fold's window reaches it and reports it under
  that name, 616 more sites.

## ADD + LDP/STP foldable to immediate-offset LDP/STP

* `add xt, xn, #a ; ldp xq, xr, [xt, #b]` ->
  `ldp xq, xr, [xn, #(a+b)]`, and the store twin
  (`ADD + STP foldable to immediate-offset STP`). The pair arm of the
  single-access fold above, sharing its pending-ADD state, its
  side-entry gate and its liveness scan; what differs is the slot the
  combined offset has to fit.
* Why it is not just the single-access rule with a wider register
  list: the pair forms have **no unsigned-offset encoding**. Their
  `imm7` is SIGNED and pre-scaled by the per-register transfer size,
  so the combined offset may land on either side of the new base. The
  shape that dominates real code is an ADD forward and a negative
  `imm7` back, cancelling to a bare base --
  `add x19, x26, #0xb8 ; ldp x21, x20, [x19, #-0xb8]` ->
  `ldp x21, x20, [x26]`. The single-access fold reaches a negative sum
  only through the unscaled `LDUR`/`STUR` spelling, whose `imm9` stops
  at `-256`; a pair's `imm7` is pre-scaled, so it reaches `-512` for X
  and `-1024` for Q. Beyond that the pair form is simply a different
  slot, not a wider one.
* Encoding constraint: `imm7` is already a multiple of the transfer
  size, so the combined offset's alignment is decided solely by the
  ADD's byte immediate, and the SCALED total must fit signed 7 bits
  (`-64 .. 63`, i.e. -512..504 bytes for an X pair, -1024..1008 for a
  Q pair). The `sh=1` ADD form is accepted; a total that overflows the
  slot keeps its own ADD, as before. The negative end cannot be
  undershot: source `imm7` bottoms out at -64 and the ADD's immediate
  is non-negative, so the only way to reach exactly -64 scaled is the
  zero-immediate MOV-from-SP alias.
* Both integer and SIMD&FP pairs fold, plus `LDPSW` (whose transfer is
  4 bytes per register even though it writes X destinations, so it
  scales by 4). The writeback spellings are not matched here -- those
  belong to the pre-/post-index checks.
* Deadness tiers, as for the single-access fold. An integer pair LOAD
  whose destination list covers the ADD's `Rd` overwrites the address
  register on the spot, proving the sum dead with no scan; every other
  pair -- stores, fresh-destination loads, and all SIMD&FP pairs --
  defers through the forward register-liveness scan. In the mining
  corpus the structural tier is tiny (27 sites of 8,775 candidates):
  essentially the whole population is deferred, which is why this
  check could not have been written before that scan existed.
* A pair STORE whose data registers include the ADD's `Rd` never
  folds -- the rewritten store would read the deleted sum. The test is
  for integer pairs only: SIMD&FP data registers live in the other
  register file and can never alias the integer base, so
  `stp q8, q9, [x8]` off `add x8, ...` folds despite the shared
  register number. `Rt = 31` in a pair is ZR, never SP, and the ADD's
  `Rd` is never 31, so no zero-register case slips through the alias
  test.
* Naming the new base among a pair LOAD's destinations is safe: the
  no-writeback form reads the base once before writing either
  destination (the `t == n` restriction applies to the pre- and
  post-indexed forms, not this one), and compilers emit that shape
  freely -- 32,078 sites across the mining corpus.
* Actionability limit: in an UNLINKED object an ADD immediate may be a
  relocation field (`R_AARCH64_ADD_ABS_LO12_NC`, Mach-O `PAGEOFF12`),
  and no relocation type targets a pair's `imm7`, so the fold would
  not be expressible even though it is sound. armlint does not read
  relocations, so this is a residual false positive on unlinked input;
  on linked binaries -- what the corpus figures below measure -- the
  immediate is final and the concern does not arise. The same caveat
  applies to the single-access fold, where the `:lo12:` load form
  happens to make it expressible.
* Corpus: 8,775 candidate sites fold 2-for-1 across 28.4M instructions
  (5,467 librustc_driver, 3,270 go), of which armlint reports 2,864
  after the liveness scan -- 2,811 in librustc_driver, a 51% realized
  rate matching the ADD/SUB chain check's. Go realizes far less (50 of
  3,270): gc's fixed `x27` scratch stays live across the pair, so the
  scan correctly refuses. A further 17,565 sites have a combined
  offset too large for `imm7`; those split into two singles rather
  than one pair and are tracked in [TODO.md](TODO.md) as a
  latency-only, size-neutral rewrite.

## ADD foldable into every access it feeds

* `add xt, xn, #a ; <access> [xt, #b] ; <access> [xt, #c] ; ...` ->
  the accesses rebased on `xn` at `a+b`, `a+c`, ... and the ADD
  deleted. The other half of the single-access fold's population: that
  check folds an ADD into the one access next to it and gives up as
  soon as the base is read again -- correctly, since the ADD would
  have to survive for the second consumer and the rewrite would save
  nothing. But when *every* consumer in the base's live range can be
  rebased, all of them are, and the ADD goes away. Three instructions
  become two, the same saving, off a shape the adjacency rule cannot
  see:

  ```
  add  x8, x0, #0x120
  ldur w1, [x8, #-4]     ->  ldur w1, [x0, #0x11c]
  ldr  w2, [x8, #4]      ->  ldr  w2, [x0, #0x124]
  ```

* A **sole** use reports here too, provided it is not the instruction
  directly after the ADD. One use pays exactly as well as many -- the
  ADD goes either way, so the saving is one instruction -- and the
  only question is whose finding it is. That one position is the whole
  of `check_add_ldr_imm_offset`'s reach: it clears its pending slot on
  anything that is not the consumer. So the two split by position and
  stay disjoint by construction, not by arrangement -- at one use this
  check refuses the adjacent site, and at two or more the other one's
  deferred liveness scan sees the base read again and discards.
* The split is by position, not by outcome, which leaves a narrow
  false negative. An adjacent sole use that `check_add_ldr_imm_offset`
  opens a deferral for and then loses -- to an evicted slot or an
  expired window -- is refused here too rather than picked up as a
  second chance. Reporting a site twice is the worse failure.
* The gapped sole use is also what makes the side-entry span below
  earn its keep. With two or more uses the instructions between them
  are almost always uses themselves; with one use across a gap the
  finding covers instructions it does not mention, and a branch into
  that gap rejects it.
* Rebasable means an access whose displacement is a plain immediate:
  the integer and SIMD&FP single accesses in both the unsigned-offset
  and the unscaled spelling, and the signed-offset pairs. Covering all
  of them matters more here than for a single-access fold, because one
  unrecognized use fails the whole site -- the SIMD&FP and pair forms
  are not an extension of this check but a precondition for it, since
  the dominant real shape is a block of `q`-register spills. The
  writeback (pre- and post-index) and register-offset forms are absent
  by design: a writeback also updates the base, so deleting the ADD
  would drop an observable update, and a register-offset address is
  not a constant the ADD's immediate can join.
* The range test is per-use and per-form. A single access takes
  whichever of its two spellings fits, since the assembler picks
  between them; the pair forms have no unsigned-offset spelling at
  all, so there the sum must be on the transfer-size grid and fit
  signed 7 bits once scaled.
* Proving *every* use is what this needs a forward scan for, where the
  other folds need only adjacency. The scan runs to whichever comes
  first: the base overwritten (the fold is safe, every use is behind
  us), any other read of it (a use that does not fold, so the ADD must
  stay), a control transfer, or the window expiring. The window counts
  only instructions that are neither uses nor the kill, so a long run
  of consecutive accesses never exhausts it -- the corpus has a
  20-use site.
* The ADD's **source** is watched too, which no adjacency-based fold
  has to do. Every rewritten access reads `xn` at its own offset
  instead of at the ADD, so anything that writes `xn` in between
  invalidates the rebase. When the source is SP the register-liveness
  scan cannot help: `arm64_gpr_num` maps SP (like the zero register)
  to -1, so `insn_reg_access` never reports it, and the encodings that
  can name SP as a destination are matched directly instead -- ADD/SUB
  immediate and extended-register with `Rd = 31` and `S = 0`, and the
  writeback addressing forms with `Rn = 31`. A dynamic stack
  allocation between the base copy and its uses would otherwise be
  silently dropped.
* Side entries: `insn_count` spans the ADD through the **last use**,
  not the rendered lines, and the central gate
  (`armlint_finding_has_side_entry`) then covers exactly that range.
  That is not conservatism -- a branch landing anywhere between the
  ADD and the last use reaches a rewritten access on a path that never
  added the immediate, so the address would differ. A branch past the
  last use is harmless, and the span ends there.
* One tracked ADD at a time. A second arriving while one is live
  replaces it, so interleaved bases report only the inner one. Like
  `defer_dead_mov`'s single slot this is false-negative-only, and it
  costs little in practice: the measured yield landed within 0.1% of
  the estimate made without the restriction.
* Corpus: 3,804 findings across 28.4M instructions (2,935
  librustc_driver, 708 go, 70 dyld, 68 bash, 16 libcrypto, 7 ssh).
  Uses per site: 1 at 616 sites, 2 at 2,174, 3 at 664, 4 at 170, 5 at
  65, 6 at 64, and a tail to 20. By what produces the base, **2,644**
  of the multi-use sites are stack frames (`add xt, sp, #a`), 468 are
  global addresses off an ADRP, and 76 are plain pointer arithmetic.
* The sole-use population inverts that. Of its 616 sites **318** are
  ADRP globals, 213 stack frames and 85 pointer arithmetic -- the one
  shape where a base is computed for exactly one access is a global's
  page offset, and the tail of the LLVM frame shape is the part where
  the virtual base register ended up feeding a single slot. They also
  sit close: **553 of the 616 are gapped by exactly one instruction**,
  and in 412 of those the gap is itself a load or store. That is a
  scheduler covering the address's latency with independent work, and
  it is the entire reason `check_add_ldr_imm_offset` cannot see them:

  ```
  add x8, sp, #0x1d0
  movi v0.2d, #0             <- the value the store needs
  stp  q0, q0, [x8, #0x10]   ->  stp q0, q0, [sp, #0x1e0]
  ```

  By what the use is: 270 integer single accesses, 224 SIMD&FP pairs,
  118 SIMD&FP singles, 4 integer pairs.
* The stack-frame majority is a single LLVM shape. `LocalStackSlotAllocation`
  inserts a virtual base register when a frame index's *estimated*
  offset looks out of addressing range, and the estimate is made
  before the frame layout is final; when the real offset turns out to
  fit, the base register stays. The tell is that the ADD's immediate
  is usually off the transfer-size grid, which is what forced the
  accesses into the unscaled spelling in the first place -- rebasing
  puts them all back on it:

  ```
  add  x8, sp, #0x2a8
  stur q0, [x8, #0x68]   ->  str q0, [sp, #0x310]
  stur q0, [x8, #0x78]   ->  str q0, [sp, #0x320]
  ... eight more, then x8 is overwritten
  ```

  Not a toolchain-forced shape: nothing about the ISA or the object
  format requires the scratch base, and the rewrite is a pure
  deletion.

## LDR/STR (or LDP/STP) + ADD/SUB foldable to post-indexed form

* `ldr xt, [xn] ; add xn, xn, #imm` -> `ldr xt, [xn], #imm`, and the
  negative-direction `ldr xt, [xn] ; sub xn, xn, #imm` ->
  `ldr xt, [xn], #-imm`. Same for STR, all four integer access sizes
  (B/H/W/X), and every SIMD&FP size (B/H/S/D/Q) -- an FP Rt never
  aliases the integer base, so the Rt == Rn writeback restriction
  is integer-only. The post-indexed encoding already expresses "load/store
  from `[xn]` and then bump `xn` by ±imm", so the rewrite is a literal
  source-to-encoding fold with no semantic change.
* Pairs fold the same way: `ldp xt, xu, [xn] ; add xn, xn, #imm` ->
  `ldp xt, xu, [xn], #imm`, covering the integer W/X pairs, `LDPSW`,
  and the SIMD&FP S/D/Q pairs. The flagship shape is the canonical
  frame epilogue, `ldp x29, x30, [sp] ; add sp, sp, #imm` ->
  `ldp x29, x30, [sp], #imm` -- exactly what compilers emit, so its
  unfused spelling is a reliable tell of naive codegen (baseline JIT
  tiers, hand-written assembly).
* What you actually save: 4 bytes per fold and one fetch/decode
  slot. The backend cost is typically unchanged -- most modern OoO
  cores (Apple M-series, Cortex-A76+, Neoverse N1+) crack the
  post-indexed load into two micro-ops (load and base-register
  writeback), the same backend work as the original two
  instructions. Critical-path latency is unchanged. The wins are in
  code size, I-cache footprint, and front-end bandwidth (helpful
  on decode-bound inner loops); don't expect a measurable cycle
  drop on backend-bound code. The same accounting holds for the
  pair forms: a writeback LDP cracks into about the same total
  micro-op count as the separate LDP + ADD on current big cores, so
  the pair fold is likewise a size and front-end win rather than a
  cycle win -- mainstream compilers emit the folded form for every
  frame prologue/epilogue.
* Encoding constraint: single post-index uses a 9-bit signed byte
  immediate (-256..255). An `ADD`-imm self-update with imm in 1..255
  folds to a positive writeback; a `SUB`-imm self-update with imm in
  1..256 folds to a negative one (-256 is the signed-9-bit minimum,
  so the negative side reaches one further than the positive). Pair
  post-index instead uses a scaled signed 7-bit immediate: the
  ADD/SUB amount must be a multiple of the per-register transfer
  size (4 for W/S/`LDPSW`, 8 for X/D, 16 for Q) with quotient 1..63
  for `ADD` or 1..64 for `SUB` (so X pairs reach +504/-512 bytes and
  Q pairs +1008/-1024). The `sh=1` form (imm >= 4096) is out of
  every slot's range. The access's offset must be 0 -- a non-zero
  offset combined with a base bump matches the pre-indexed pattern,
  not post-index.
* Soundness: the ADD/SUB must be a self-update (`Rd == Rn ==` the
  access's `Rn`), since post-index can only update its own base
  register. Rt == Rn writeback is UNPREDICTABLE for loads and
  CONSTRAINED UNPREDICTABLE for stores -- for pairs that applies to
  either data register -- so those cases are rejected, except
  when Rn == 31, where Rn means SP and Rt means XZR (distinct
  registers, no conflict). A load pair with Rt == Rt2 is CONSTRAINED
  UNPREDICTABLE even without writeback and is never folded; a store
  pair with a repeated source is well-defined, so
  `stp xzr, xzr, [sp] ; add sp, sp, #imm` (the common 16-byte zero
  store plus bump) is flagged. `str xzr, [sp] ; add sp, sp, #imm` and
  `ldr xt, [sp] ; add sp, sp, #imm` are both flagged as the
  canonical stack-frame teardown patterns.
* `ADDS`/`SUBS` (flag-setting) are excluded because post-index has no
  flag-setting form. Distinct from `check_add_ldr_imm_offset`,
  which catches the reversed sequence (ADD then LDR) and folds
  into the unsigned-offset form rather than post-index.

## ADD/SUB + LDR/STR (or LDP/STP) foldable to pre-indexed form

* `add xn, xn, #imm ; ldr xt, [xn]` -> `ldr xt, [xn, #imm]!`, and the
  negative-direction `sub xn, xn, #imm ; ldr xt, [xn]` ->
  `ldr xt, [xn, #-imm]!`. Same for STR, all four integer access sizes
  (B/H/W/X), and every SIMD&FP size (B/H/S/D/Q) -- an FP Rt never
  aliases the integer base, so the Rt == Rn writeback restriction
  is integer-only. The pre-indexed encoding already expresses "bump `xn` by
  ±imm and then load/store from the new `xn`", which is exactly what
  the source sequence does.
* Pairs fold the same way: `sub sp, sp, #imm ; stp x29, x30, [sp]`
  -> `stp x29, x30, [sp, #-imm]!` is THE canonical frame prologue,
  and the fold covers the integer W/X pairs, `LDPSW`, and the
  SIMD&FP S/D/Q pairs.
* Same code-size and decode-slot win as the post-index check. The
  backend cost is also unchanged: most modern OoO cores crack
  pre-indexed loads into two micro-ops (address update and load),
  the same dependency chain as ADD followed by LDR; the pair forms
  carry the same accounting (see the post-index notes).
* Encoding constraint: same slots as post-index. Singles use the
  9-bit signed byte immediate -- an `ADD` self-update with imm in
  1..255 folds to a positive writeback, a `SUB` self-update with imm
  in 1..256 to a negative one. Pairs use the scaled signed 7-bit
  immediate: a multiple of the 4/8/16-byte transfer size with
  quotient 1..63 (`ADD`) or 1..64 (`SUB`). The pending ADD/SUB is
  admitted up to the largest pair writeback (1008/1024 bytes) and
  the consumer's actual slot is re-checked when the access arrives,
  so `add xn, xn, #304 ; ldp ...` folds while the same bump with a
  single `ldr` correctly does not. The access's offset must be 0 --
  a non-zero offset combined with a base bump has no single
  pre-index expression that preserves both the access address and
  the final base register value.
* Soundness: the ADD/SUB must be a self-update (`Rd == Rn ==` the
  access's `Rn`). Rt == Rn writeback is rejected (UNPREDICTABLE /
  CONSTRAINED UNPREDICTABLE) -- for pairs, either data register --
  except when Rn == 31 (Rn means SP, Rt means XZR; distinct
  registers). A load pair with Rt == Rt2 is CONSTRAINED
  UNPREDICTABLE on its own and is never folded; a store pair with a
  repeated source (`stp xzr, xzr`) is well-defined and folds.
* Cross-check interaction with `check_add_ldr_imm_offset`: when
  Rt == Rn == ADD's Rd, that earlier check fires instead and folds
  to the unsigned-offset form (no writeback) -- but only for `ADD`,
  since the unsigned-offset form has no negative immediate, so a
  `SUB` with Rt == Rn yields no finding at all. When Rt != Rn but
  rn == ADD's Rd, both can fire: this check reports the pre-indexed
  form immediately, and the immediate-offset fold additionally
  reports once its forward scan proves the updated base dead -- the
  writeback is pointless for a dead base, so its no-writeback rewrite
  is strictly better there. The two findings offer alternative
  outcomes, like the CMP-drop/CBZ-fold overlap.
* Side entries: a memory op that is itself the target of a direct
  branch never closes a fold. The rotated-loop idiom -- `while
  (isspace(*p)) p++` compiles to an entry branch that lands on the
  load, past the increment -- is exactly this shape, and the
  pre-indexed rewrite would bump the base on the entering path too.
  Unlike the immediate-offset fold, no liveness argument catches
  this (the rewrite keeps the base live on purpose), so the gate is
  the only defense. It shares the branch-target map described in the
  immediate-offset section (built by armlint_state_set_buffer; off
  without a buffer; blind to indirect branches), and the central
  emission gate covers it as well. A branch onto the ADD/SUB itself
  does not suppress the fold.
* The `ADD` half of a linker-materialized address pair never opens
  the pattern: `ADD Rd, Rd, #imm` immediately preceded by `ADR`/`ADRP`
  with the same `Rd` is the page-relative addressing pair
  (`adrp xn, page ; add xn, xn, #pageoff`), and `#pageoff` is a
  relocation field (ELF `R_AARCH64_ADD_ABS_LO12_NC`, Mach-O
  `ARM64_RELOC_PAGEOFF12`, Go's `R_ADDRARM64`). Relocation types
  exist only for the single load/store scaled imm12 slot (the
  `R_AARCH64_LDST{8,16,32,64}_ABS_LO12_NC` family) -- none targets
  the pre-indexed imm9 or the pair imm7 field -- so no compiler or
  assembler can emit the suggested rewrite; changing the pair
  requires re-linking, not a code rewrite, the same reasoning as the
  ADD/SUB #0 check's ADRP+ADD suppression. This is why toolchains
  that fold `#pageoff` into single loads (Go emits
  `adrp ; ldr xt, [xn, #lo12]` for every aligned global load) still
  emit `adrp ; add ; ldp` for pair loads of 16-byte globals -- the
  three-instruction form is already optimal under the available
  relocations, and flagging it (209 LDP + 12 STP + 1 STR sites in
  go1.26.4's `go` binary, every one an ADRP pair) would demand the
  impossible. `SUB` self-updates are unaffected (no relocation uses
  `SUB`), an intervening instruction between the ADR/ADRP and the
  ADD re-enables the fold (strict adjacency, matching the relocation
  span), and the tracking is private to this check:
  `check_add_sub_zero` owns the shared `adr_recent` flag and has
  already cleared it (the ADD is not an ADR) by the time this check
  runs. `check_add_ldr_imm_offset` deliberately keeps flagging
  ADRP-paired singles: its unsigned-offset rewrite *is* expressible
  with the LDST relocations, so those findings mark real toolchain
  gaps (typically missing alignment metadata on the symbol).

## Appendix: folds rejected for soundness

Patterns that look like they should fold and deliberately do not.
Each entry is a near-miss of an implemented check; the check's own
section describes the sound sibling, this appendix consolidates the
counter-arguments so a reviewer wondering "why doesn't armlint flag
this?" has one place to look.

### Floating-point rounding

* **`fmul` + `fadd`/`fsub` -> `fmadd`/`fmsub`/`fnmadd`/`fnmsub`
  (contraction).** The fused ops round ONCE: `fmadd` computes
  `round(a*b + c)` with the infinitely precise product feeding the
  add. The two-instruction sequence rounds twice --
  `round(round(a*b) + c)` -- and the results differ in the last ulp
  for well-chosen inputs. Compilers only contract under
  `-ffp-contract=fast` (or `#pragma STDC FP_CONTRACT ON`), an
  explicit license to change results that a binary-level linter
  cannot assume. This is the canonical member of the family and the
  reason the [`FMUL` + `FNEG` fold](#fmul--fneg-foldable-to-fnmul)
  spells out why IT is exact: `FNMUL` negates the already-rounded
  product, adding no rounding step.
* **`fneg` of an operand + `fmul` -> `fnmul`.** Negating an operand
  first computes `round(-(a*b))`; `FNMUL` computes `-(round(a*b))`.
  Under round-to-nearest these agree (rounding is symmetric), but
  under the directed modes (`FPCR.RMode` = toward +inf or -inf) they
  differ, and armlint cannot know the dynamic rounding mode. Only
  the result-negating order folds -- see
  [`FMUL` + `FNEG`](#fmul--fneg-foldable-to-fnmul), whose fixture
  pins this sibling as a negative.

### Floating-point value semantics

* **`fcmp` + `fcsel` -> `fmax`/`fmin`.** `FMAX`/`FMIN` have their
  own NaN and signed-zero semantics: a quiet-NaN operand propagates
  (the result is NaN), and `fmax(+0.0, -0.0)` is `+0.0`. The
  compare-and-select computes something else on exactly those
  inputs: `fcmp` with a NaN sets the unordered flags, so
  `fcsel ..., gt` takes the ELSE operand (yielding the NaN's
  partner, not the NaN), and +/-0.0 compare EQUAL, so the select
  picks whichever slot the condition maps to, not canonical +0.0.
  The integer twin has no such trap, which is why
  [`CMP` + `CSEL` -> `SMAX`/`SMIN` (CSSC)](#cssc-synthesis-feature-gated--m-cssc)
  folds and the FP shape never will. (`FMAXNM`/`FMINNM` change the
  NaN rule but not the +/-0.0 one; no variant matches the select.)

### Integer arithmetic

* **`SDIV`-based power-of-two remainder -> `AND`.** For unsigned
  values, `dividend - (dividend / 2^N) * 2^N` is a low-bits mask
  because `UDIV` truncates and truncation IS flooring there. `SDIV`
  truncates toward zero: for a negative dividend the flooring `AND`
  and the truncating remainder disagree (C's `%` yields -1 for
  -1 % 4; the mask yields 3). Only the unsigned idiom folds -- see
  [remainder by power of two](#remainder-by-power-of-two-foldable-to-and).
* **`sub` + swapped `cmp` -> `subs`.** Subtraction does not
  commute: `cmp x2, x1` computes `x2 - x1`, whose NZCV bear no fixed
  relation to `subs x0, x1, x2`. Only the identical-operand compare
  folds for the SUB family; the swap is sound solely for
  [`ADD` + `CMN`](#sub--cmp-of-identical-operands-foldable-to-subs),
  where both spellings compute the identical 65-bit sum.
* **`ADD` + swapped `CMN` with a shifted operand.** The swap
  argument needs plain registers: `Rn + (Rm << s)` is not
  `Rm + (Rn << s)`, so only the LSL #0 shifted-register form swaps.
  The immediate form has no second register and the extended form
  extends Rm only -- neither has a swapped spelling at all.
* **`csinc`/`csinv`/`csneg` with equal operands as an "identity".**
  Only [`CSEL Rd, Rn, Rn`](#csel-same-operand-identity-csel-rd-rn-rn-cond)
  selects the same value on both branches. The rest of the family
  computes `Rn+1`, `~Rn` or `-Rn` on the else path, so the equal-
  operand forms are conditional increment/invert/negate (the CINC /
  CINV / CNEG aliases), not copies.

### Flag-agreement discipline

* **Blessing "harmless" flag readers after a flag-CHANGING
  rewrite.** Whether a later `b.eq` can survive a fold depends on
  which flags the rewrite preserves, not on the reader looking
  benign. The [zero-CMP -> S-variant fold](#addsubandbic--zero-cmp-foldable-to-s-variant)
  keeps N and Z bit-identical but changes C and V (`cmp #0` pins
  C = 1, V = 0), so its scan admits EQ/NE readers and rejects
  everything else; the [CSSC folds](#cssc-synthesis-feature-gated--m-cssc)
  delete the compare outright and set NO flags, so their scan
  rejects every reader, `b.eq` included. Same machinery, different
  flag-agreement proofs -- neither is transferable to the other.

### Architectural rules

* **`LDP` with `Rt1 == Rt2`.** CONSTRAINED UNPREDICTABLE, so
  adjacent same-register LOADS never
  [coalesce](#adjacent-ldrstr-foldable-into-ldpstp); adjacent
  same-register stores do (`STP Rt, Rt` is well-defined -- it simply
  stores the value twice).
* **The `STR` base slot as ZR.** In addressing, register 31 means
  SP, not the zero register: rewriting a base to "ZR" would silently
  re-address the store. The [MOV #0 fold](#mov-0--use-foldable-to-zr)
  substitutes only data slots (`Rt`, ALU operands, select operands),
  never a base.
* **`adr` + `blr` -> `bl`.** A callee legitimately receives values
  in registers -- x8 in particular is the indirect-result (sret)
  pointer -- so the address register cannot be assumed dead at a
  call target the way x16/x17 can across a
  [veneer-shaped `br`](#adr--single-use-of-its-target-foldable-to-the-direct-form).
* **Cross-width load + convert.** `ldr w8 ; scvtf d0, w8`
  (int32 -> double) has no FP-side twin: there is no in-SIMD
  cross-width scalar conversion, so only the width-matched pairs
  fold in the [load + convert check](#load--scvtfucvtf-via-gpr-foldable-to-fp-load--convert).
