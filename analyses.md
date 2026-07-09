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
  overwrites NZCV without reading them (ADDS/SUBS/ANDS/BICS/FCMP)
  or a terminator that makes prior flags unobservable (RET, BL,
  BLR). The scan suppresses on any flag-reader, an unsafe
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

## adjacent LDR/STR foldable into LDP/STP

* Two unsigned-offset `LDR Wt, [Rn, #imm12*4]` (or X-form,
  scale 8) to consecutive scaled offsets fold into a single
  `LDP Wt1, Wt2, [Rn, #imm7*4]`. Analogous for stores ->
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
* Currently supports only the unsigned-offset form. The scaled imm12
  guarantees natural alignment to the access size, which the LDP
  encoding requires. `LDUR` (unscaled) and pre-/post-indexed forms
  are deferred: their byte offsets aren't constrained to be a
  multiple of the access size, and `LDP/STP` on unaligned
  addresses has implementation-defined behaviour on AArch64
  (some cores fault even when single `LDR/STR` works under
  `SCTLR_EL1.A = 0`).
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
  of the two imm12s must also fit LDP's signed-7-bit imm7 (i.e.,
  be at most 63 for non-negative unsigned-offset sources).
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
* Adjacent unsigned-offset `LDRSW Xt, [Rn, #imm12*4]` pairs fold
  analogously into a single `LDPSW Xt1, Xt2, [Rn, #imm7*4]`. Same
  constraints (same base, consecutive offsets, distinct Rts, first
  `Rt != Rn`, first imm12 <= 63), with the added requirement that
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
* Soundness (structural): the `FNEG` must read and overwrite the
  `FMUL`'s destination in place (`fneg dd, dd`), proving the
  intermediate product dead -- the same argument as the integer
  producer folds. A fresh `FNEG` destination would need an
  FP-register liveness scan, which does not exist yet (the same v1
  limitation as the `MOVI` + vector-compare fold). No aliasing
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
  * `STR` (B/H/W/X, unsigned-offset) with `Rt == mov_rd`
    -> `str <wzr/xzr>, [...]`. Saves the MOV when Rt-only.
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
* Encoding constraint: the combined byte offset must be a multiple
  of the LDR's access size and its scaled value must fit in 12
  bits. The LDR's own imm12 is already a multiple of access_size,
  so alignment is determined solely by the ADD's byte immediate.
  The ADD's `sh=1` form (`imm12 << 12`) is supported.
* Rn = SP (Rn = 31 in ADD-imm) is intentionally flagged: ADD-imm
  and LDR-uimm both encode 31 as SP, so the canonical stack-
  relative load pattern (`add xt, sp, #imm ; ldr xt, [xt]`) folds
  correctly. That includes `imm == 0` -- the MOV-from-SP alias:
  `mov xt, sp ; ldr xt, [xt]` -> `ldr xt, [sp]` (rendered with the
  `mov` spelling). `imm == 0` with a GPR source stays excluded;
  that is the redundant ADD `check_add_sub_zero` owns. Rd = SP in
  the ADD is excluded -- folding would discard the observable SP
  update.
* SUB-immediate is not folded: the LDR unsigned-offset form has
  no negative-immediate encoding.

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
