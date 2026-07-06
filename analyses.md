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
  distinct sources is a funnel shift and does not fold. Conservative:
  only flags when the consumer overwrites the shift's destination,
  guaranteeing the shifted value is dead.
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
  value for the second operand.

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
* Soundness: like the shift-fold check, armlint flags only when the
  consumer overwrites the producer's destination (`Rd == Rt`), proving the
  intermediate shift result is dead -- with no liveness pass, a consumer
  that writes a fresh register (whose shift result might still be read
  later) is conservatively skipped. The inline-shifted source must be a
  different register than the shift destination, else the funnel would read
  the shifted value rather than the original register. Shifting or writing
  `XZR` is rejected as degenerate.
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
* Conservative soundness (mirrors the shift fold): Rd of the consumer
  must equal the extend's destination (so the extended value is dead),
  and the other source operand must not also be it -- nor register 31,
  which the shifted-register consumer read as ZR but the
  extended-register rewrite would read as SP. The producer form (W vs
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
  scaled units); `Rt1 != Rt2` (LDP/STP requires distinct
  destinations); for integer loads, the first instruction's
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
  accumulator is not flagged.
* The `2^N - 1` case is intentionally not folded. AArch64 has no
  single shifted-register form that computes `x*(2^N - 1)`:
  `SUB Xd, Xn, Xn, LSL #N` gives `x*(1 - 2^N)`, the negation, so
  the rewrite would be two instructions (`LSL+SUB` or `SUB+NEG`)
  at parity with `MOV+MUL` in count.
* Dead-constant verification (shared by every MOV-chain fold --
  `MNEG`, `UDIV`, `MOV + ADD/SUB`, `MOV + AND/ORR/EOR`, `MOV + CCMP`,
  `MOV #0 + use`, and the register-offset fold): the reported saving
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

## MOV + ADD/SUB foldable to immediate form

* `mov xc, #C ; add xd, xn, xc` instead of `add xd, xn, #C` when
  `C` fits the ADD/SUB immediate encoding (12-bit unsigned with
  optional `LSL #12`: `C` in `[1, 0xFFF]` or `C` a multiple of
  `0x1000` with `C/0x1000` in `[1, 0xFFF]`). Same for `SUB`,
  `ADDS`, `SUBS`, and the `CMP`/`CMN` aliases (S-variant with
  `Rd == ZR`).
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
* `C` outside `[0, 31]` has no immediate form and is skipped. The
  sign-crossing rewrite for negative constants (`ccmp Rn, #-C` <->
  `ccmn Rn, #C`, whose NZCV agree exactly) is not attempted,
  consistent with the `MOV + ADD/SUB` fold's direct-form-only policy.

## MOV #0 + use foldable to ZR

* `mov xd, #0 ; <use xd>` instead of `<use xzr>`. Three consumer
  families:
  * `STR` (B/H/W/X, unsigned-offset) with `Rt == mov_rd`
    -> `str <wzr/xzr>, [...]`. Saves the MOV when Rt-only.
  * `ADD/SUB/ADDS/SUBS` (shifted-register, LSL #0) with Rn or Rm
    == mov_rd -> the same op with that operand as ZR. `CMP`/`CMN`
    aliases are rendered when Rd == ZR + S-variant.
  * `AND/ORR/EOR/ANDS` (shifted-register, LSL #0, N = 0) with Rn
    or Rm == mov_rd -> the same op with the operand as ZR. `TST`
    alias when Rd == ZR + ANDS.
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
* Conservative soundness: Rd of the ADD/SUB must equal Rt (so the
  MUL's destination is overwritten and its post-MUL value is
  dead), and the accumulator operand must not equal Rt (otherwise
  the ADD reads the MUL's result twice while the MADD rewrite
  reads pre-MUL values, diverging).
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
* Conservative soundness (identical to MUL+ADD): Rd of the ADD/SUB
  must equal Xt (so the 64-bit product is overwritten and dead), and
  the accumulator operand must not equal Xt. Signedness must match
  the producer (`SMULL` pairs only with `SMADDL`/`SMSUBL`, `UMULL`
  only with `UMADDL`/`UMSUBL`). S-variants (ADDS/SUBS) are skipped
  (no flag-setting long MAC); `SMULL`/`UMULL` writing to ZR is
  excluded.
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
* Conservative soundness: Rd of the ADD/SUB must equal Rt (so the
  NEG's destination is overwritten and `-xs` is dead), and the
  accumulator operand must not equal Rt -- otherwise both ADD/SUB
  sources are `-xs`, computing `-2*xs` or `0` instead of the
  additive identity the fold assumes.
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
* Conservative soundness (mirrors the NEG fold): Rd of the consumer
  must equal `wt` (so the `mvn` destination is overwritten and `~ws`
  is dead), and the independent operand must not also be `wt` -- the
  `mvn wt, ws ; and wt, wt, wt` degenerate is a self-op, reported by
  the self-op check instead. The shifted `MVN` form is not handled
  (the consumer would shift the complemented value, not `ws`). `MVN`
  to ZR, and `MVN` of ZR (the all-ones `mov wd, #-1` idiom), are
  excluded.
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
* Conservative soundness: Rd of the ADD must equal Rt of the LDR
  (the loaded register). The LDR's write to Wt/Xt destroys the
  pre-LDR address value of Xt, so Xt's only consumer was the
  LDR itself.
* The sign-extending loads (`LDRSB`/`LDRSH`, Wt or Xt; `LDRSW`) fold
  identically: they too overwrite the full X register named by `Rt`
  (a W-form write zeros the upper half) and have register-offset
  forms with the same shift rule. `PRFM`, which shares the encoding
  family, is excluded -- its `Rt` field is a prefetch operation, not
  a destination, so the address register stays live.
* STR is intentionally not flagged: there is no analogous
  Rd-overwrite to prove Xt is dead after the store.
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
  All four zero-extending sizes (LDRB/LDRH/LDR W/LDR X) and the
  sign-extending loads (`LDRSB`/`LDRSH`, Wt or Xt; `LDRSW`) are
  handled, and the scale bit carries over.
* Why it helps: one fewer instruction, and the sign-extend leaves the
  critical path -- the load's address-generation unit does it for free
  rather than a separate dependent op feeding the load. (Same profile
  as the LSL/extend folds; this is the load-addressing form of it.)
* Soundness (conservative, mirrors the `ADD + LDR` register-offset
  check): the consumer must be an integer load (not `STR` -- no `Rt`
  overwrite to prove the index dead -- nor `PRFM`, whose `Rt` is a
  prefetch operation rather than a destination) using
  the LSL/UXTX index option (a full 64-bit register offset, identical
  to the `SXTW` result), with `Rt == Rm == Xt` so the load overwrites
  the index. The base `Rn` must NOT be `Xt`: with the `SXTW` folded
  away the base would read its pre-`SXTW` value, changing the address.
  `SXTW` into ZR is excluded.
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
  complement of the register-offset fold: same Rd-overwrite
  soundness argument, but the ADD's constant offset (plus the
  LDR's, if any) moves into the LDR's unsigned immediate slot.
  The sign-extending loads (`LDRSB`/`LDRSH`, Wt or Xt; `LDRSW`)
  fold the same way -- they too overwrite the full X register named
  by `Rt` and have unsigned-offset forms; `PRFM` is excluded (its
  `Rt` is a prefetch operation, so the address register stays
  live).
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
  rn == ADD's/SUB's Rd, only this check fires. So the checks together
  cover the full ADD/SUB + LDR/STR space without double-firing on the
  same pair.
