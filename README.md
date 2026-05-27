# armlint

armlint examines AArch64 machine code to find suboptimal instruction
sequences. For example, building the constant `0x66666666` as

```
movz w0, #0x6666
movk w0, #0x6666, lsl #16
```

is two instructions where one would do, because `0x66666666` is encodable
as an AArch64 logical (bitmask) immediate:

```
mov w0, #0x66666666     ; orr w0, wzr, #0x66666666
```

armlint helps compiler writers and assembly authors generate tighter
code, and documents corners of the A64 instruction set.

## Implemented analyses

### suboptimal MOVZ/MOVK sequence
* `movz w0, #0x6666 ; movk w0, #0x6666, lsl #16` instead of
  `mov w0, #0x66666666` (single bitmask-immediate ORR)

### LSL foldable into shifted-register form
* `lsl w0, w1, #3 ; add w0, w2, w0` instead of
  `add w0, w2, w1, lsl #3`. Same for SUB, AND, ORR, EOR (and
  flag-setting variants). Conservative: v1 only flags when the
  consumer overwrites the LSL destination, guaranteeing the LSL
  result is dead.

### compare-zero branch foldable into CBZ/CBNZ
* `cmp w0, #0 ; b.eq target` instead of `cbz w0, target`. Same for
  `b.ne` -> `cbnz`. Also matches the equivalent zero-test idioms
  `cmp Rn, xzr` (SUBS XZR, Rn, XZR) and `tst Rn, Rn`
  (ANDS XZR, Rn, Rn): all three set `Z=1` iff `Rn==0` and so fold
  identically.
* Soundness: `CBZ`/`CBNZ` does not write NZCV, but `CMP Rn, #0`
  writes all four flags. Folding is unsound if subsequent code
  reads N, C, or V (e.g. `ADCS`, `CSEL`, `B.LT`, `CCMP`). armlint
  runs a forward NZCV-liveness scan on the fall-through path: the
  finding is emitted only after seeing an instruction that
  overwrites NZCV without reading them (ADDS/SUBS/ANDS/BICS/FCMP)
  or a terminator that makes prior flags unobservable (RET, BL,
  BLR). The scan suppresses on any flag-reader, an unsafe
  terminator (B unconditional, BR), or after a 16-instruction
  window with no decision. The branch-target path is not scanned;
  full soundness would require basic-block analysis.

### compare-zero signed-branch foldable into TBZ/TBNZ
* `cmp wn, #0 ; b.lt target` (or `b.ge`/`b.mi`/`b.pl`) folds to
  `tbnz wn, #(datasize-1), target` (or `tbz`). After `CMP Rn, #0` /
  `CMP Rn, ZR` / `TST Rn, Rn`, `V == 0`, so `B.LT` (N != V) reduces
  to "N == 1" -- exactly a test of the sign bit. `B.MI` directly
  tests `N`; `B.GE`/`B.PL` are the inverse.
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

### TST single-bit + B.EQ/NE foldable into TBZ/TBNZ
* `tst w0, #(1<<5) ; b.eq target` instead of `tbz w0, #5, target`.
  Same for `b.ne` -> `tbnz`. Only the immediate-form `TST` is
  matched (`ANDS XZR, Rn, #imm`) and only when the immediate is a
  single power-of-two bit.
* Range: `TBZ`/`TBNZ` use a 14-bit signed offset (~32 KB reach),
  much shorter than `B.cond`'s 19-bit (~1 MB). The fold is
  suggested only when the target fits in the TBZ encoding.
* Soundness: same NZCV-liveness scan as the CMP-branch check.

### bitfield op via two shifts foldable into UBFX/SBFX or UBFIZ/SBFIZ
* `lsl wd, ws, #a ; lsr wd, wd, #b` folds depending on the
  relationship between `a` and `b`:
  * `b >= a`: extraction. `ubfx wd, ws, #(b-a), #(datasize-b)`.
    With `asr` it folds to `sbfx` (sign-extending).
  * `b < a`: insertion. `ubfiz wd, ws, #(a-b), #(datasize-a)` --
    places `ws[datasize-a-1 .. 0]` at `wd[datasize-b-1 .. a-b]` with
    bits below `a-b` zeroed. With `asr` it folds to `sbfiz`
    (sign-extending the high bits from `ws[datasize-a-1]`).
  * Same for X-form.
* Compilers occasionally leave the two-shift form when bit-tracking
  can't prove the LSL invariant; armlint flags such pairs as a
  missed combine.
* v1 requires the consumer's `Rd` and `Rn` to equal the LSL's `Rd`
  so the LSL result is dead after the rewrite.

### shift-and-mask bitfield extraction foldable into UBFX
* `lsr wd, ws, #n ; and wd, wd, #((1<<w)-1)` extracts bits
  `ws[n+w-1 .. n]`; equivalent to `ubfx wd, ws, #n, #w` (capping
  `w` at `datasize-n` when the mask is wider than the LSR-fillable
  bits). Same for X-form.
* Mask must be a contiguous run of low bits with no rotation
  (`immr=0` and `(N, imms)` encoding `S+1=w` ones at the
  appropriate element size); rotated/non-contiguous masks like
  `#0x6` are correctly skipped.

### redundant zero-extension after a producer that already zeroed those bits
* Generalises the previous "redundant UXTW after W-form ALU" rule
  to size-aware producer/consumer pairs. The check tracks the
  threshold `P` at which the producer guarantees `Rt[63:P] == 0`:
  32 for W-form data-processing or `LDR Wt` / `LDRSB Wt` / `LDRSH Wt`,
  16 for `LDRH Wt`, 8 for `LDRB Wt`. A consumer that clears bits
  above `C` is redundant when `P <= C`.
* Recognised consumers: `UXTB / UXTH / UXTW` (W- or X-form UBFM
  aliases with `immr=0`, `imms ∈ {7,15,31}`, `N=sf`), AND-imm
  with mask `0xff` / `0xffff` / `0xffffffff` (both forms in W and
  X register variants), and `MOV Wd, Wd` (`ORR Wd, WZR, Wd` with
  `Rm = Rd`; the W-form register MOV writes back through the W
  register and so clears X[63:32], giving `C = 32`).
* Example flags: `add w0,w1,w2 ; uxtw x0,w0`, `ldrh w0,[x1] ; uxth
  w0,w0`, `ldrb w8,[x9] ; and w8,w8,#0xff`. Counter-example (`P >
  C`, not flagged): `ldr w0,[x1] ; uxth w0,w0` -- LDR W loads 32
  valid bits, so UXTH would actually clear bits 31..16.
* v1 still requires `Rd == Rn == producer.Rd` so the consumer is
  purely dead. Producer set covers all W-form DP classes (`ADD/SUB`
  immediate/shifted/extended, logical immediate, `MOVZ/MOVN/MOVK`,
  bitfield `SBFM/BFM/UBFM`, `EXTR`, logical shifted register,
  `ADC/SBC`, conditional select, DP-3/2/1-source) plus integer
  loads with `Wt` destination in any addressing mode.

### `MOV Xd, Xd` is a literal no-op
* The X-form register MOV alias (`ORR Xd, XZR, Xm, LSL #0`) with
  `Rm = Rd` reads `Xd` and writes the same 64 bits back; the
  instruction has no architectural effect and can be removed. Modern
  optimisers almost never emit this, but it shows up occasionally in
  hand-written assembly and in legacy object code.
* The W-form `MOV Wd, Wd` is NOT a no-op: writing through `Wd`
  clears `X[63:32]`. It is handled instead as a consumer of the
  redundant-zero-extension check above, where it fires only when a
  preceding producer already zeroed those bits.

### redundant sign-extension after a producer that already replicated the sign
* Mirror of the zero-extension framework above. The check tracks two
  thresholds `(S, W)`: the producer guarantees `Rd[W-1:S] =
  sign(Rd[S-1])`. A consumer `SXTB / SXTH / SXTW` with thresholds
  `(S_c, W_c)` is redundant iff `S_p <= S_c` AND `W_p == W_c` AND
  `Rd == Rn == producer.Rd`.
* Recognised producers: `SXTB / SXTH / SXTW` (SBFM aliases with
  `immr = 0`, `imms in {7, 15, 31}`); the sign-extending integer
  loads `LDRSB / LDRSH / LDRSW` in any addressing mode; and `ASR
  Rd, Rn, #k` (SBFM with `imms = datasize-1`, `immr = k > 0`), which
  replicates `Rn[datasize-1]` through bits `[datasize-k, datasize)`
  of `Rd`, so `S = datasize-k`. (S, W) maps for the canonical SXT*
  pairs: `LDRSB Wt` / `SXTB Wd,Wn` -> (8, 32); `LDRSH Wt` /
  `SXTH Wd,Wn` -> (16, 32); `LDRSB Xt` / `SXTB Xd,Wn` -> (8, 64);
  `LDRSH Xt` / `SXTH Xd,Wn` -> (16, 64); `LDRSW Xt` /
  `SXTW Xd,Wn` -> (32, 64). Example flagged ASR pair: `asr w0, w1,
  #24 ; sxtb w0, w0` (S_p=8 = S_c=8); `asr x0, x1, #48 ; sxth x0,
  w0`.
* `W_p == W_c` (not `<=`) because a W-form consumer writes back
  through `Wd` and zeros `X[63:32]`, which differs from an X-form
  producer's sign-extended upper half. Example flagged: `ldrsb w0,
  [x1] ; sxtb w0, w0`; `ldrsh x0, [x1] ; sxth x0, w0`; `ldrsb w0,
  [x1] ; sxth w0, w0` (S_p=8 subsumes S_c=16 within W=32).
  Counter-example: `ldrsb w0, [x1] ; sxtb x0, w0` -- producer left
  `X[63:32] = 0`, consumer would set those bits to sign of byte;
  not redundant.
* Same producer state also feeds a "dead sign-extension" path: if
  the next instruction is a zero-ext consumer (`UXTB`/`UXTH`/`UXTW`,
  `AND` with low-mask, or `MOV Wd, Wd`) that clears bits `>= C_c`
  with `C_c <= S_p`, the consumer overwrites every sign-extended
  bit and the sign-extension is dead. No width-matching constraint
  is needed -- when widths mismatch, the W-form auto-zero of
  `X[63:32]` covers the upper half. Example flagged: `sxtb w0, w1 ;
  uxtb w0, w0` (replace with `uxtb w0, w1`); `ldrsb w0, [x1] ;
  uxtb w0, w0` (replace with `ldrb w0, [x1]`); `ldrsw x0, [x1] ;
  uxtw x0, w0` (replace with `ldr w0, [x1]`).

### self-op identities (`AND/ORR/EOR/SUB/BIC/ORN/EON Rd, Rs, Rs`)
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
  is the canonical x86 zero idiom that occasionally bleeds into
  AArch64 toolchain output; the canonical AArch64 form is `MOV Rd,
  XZR` (eight occurrences observed in dyld at the time of writing).

### adjacent LDR/STR foldable into LDP/STP
* Two unsigned-offset `LDR Wt, [Rn, #imm12*4]` (or X-form,
  scale 8) to consecutive scaled offsets fold into a single
  `LDP Wt1, Wt2, [Rn, #imm7*4]`. Analogous for stores ->
  `STP`. Both W- and X-form supported; load+load and store+store
  only (no mixing).
* v1 supports only the unsigned-offset form. The scaled imm12
  guarantees natural alignment to the access size, which the LDP
  encoding requires. `LDUR` (unscaled) and pre-/post-indexed forms
  are deferred: their byte offsets aren't constrained to be a
  multiple of the access size, and `LDP/STP` on unaligned
  addresses has implementation-defined behaviour on AArch64
  (some cores fault even when single `LDR/STR` works under
  `SCTLR_EL1.A = 0`).
* Constraints checked: same base register `Rn`; same access size
  (both W or both X); same direction (load/load or store/store);
  consecutive offsets (`imm12_2 = imm12_1 + 1` in scaled units);
  `Rt1 != Rt2` (LDP/STP requires distinct destinations); for
  loads, the first instruction's `Rt != Rn` (else the first load
  clobbers the base before the second load reads it). The LOWER
  of the two imm12s must also fit LDP's signed-7-bit imm7 (i.e.,
  be at most 63 for non-negative unsigned-offset sources).
* Reverse-order pairs (`ldr Rt2, [Rn, #imm+1] ; ldr Rt1, [Rn,
  #imm]` -- higher offset first) are also coalesced, into a
  `ldp Rt1, Rt2, [Rn, #imm]` with the Rt operands ordered by
  ascending address. The load-aliasing concern is about source
  order, not address order, so the constraint is on the FIRST
  instruction in source order regardless of which offset it
  targets. Reverse-order pairs are common in Go-compiled
  binaries (~24% of total LDP/STP coalesce findings in kubectl).
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
  always 64-bit destination, load-only, 4-byte transfer. LLVM is
  aggressive about emitting LDPSW directly, so LLVM-built system
  binaries show 0 hits; Go-compiled binaries (`kubectl`, `docker`,
  ...) commonly leave un-coalesced LDRSW pairs.

### BFXIL synthesis via AND-AND-ORR
* `AND Rd, Rd, #~mask ; AND Rt, Rs, #mask ; ORR Rd, Rd, Rt` (with
  `mask = (1<<w)-1`, the two ANDs in either order, and the ORR's
  second-and-third operands in either order) is equivalent to a
  single `BFXIL Rd, Rs, #0, #w`. Both W- and X-form. The check
  detects the 3-instruction window with strict adjacency.
* The high-mask `AND Rd, Rd, #~mask` is identified by the
  bitmask-immediate encoding `immr = imms + 1` (S =
  `datasize-w-1`, R = `datasize-w`, esize = datasize). The
  low-mask consumer reuses the existing `decode_and_imm_lowmask`
  decoder. The ORR is logical-shifted-register with LSL #0.
* Aliasing constraints needed for the BFXIL rewrite to be
  semantically equivalent: `Rt != clear.Rd` (else the isolate
  clobbers the cleared register in place), `Rt != Rs` (else the
  isolate modifies the source -- BFXIL leaves the source
  unchanged), and `Rs != clear.Rd` (the degenerate case where
  Rs is the just-cleared register yields the wrong result -- the
  original sequence zeros Rd's low bits, but BFXIL Rd, Rd, ... is
  a no-op).
* Modern compilers fuse this pattern themselves; 0 hits in the
  system-binary sample. Useful for hand-written assembly and
  legacy object code.

### CSEL same-operand identity (`CSEL Rd, Rn, Rn, cond`)
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

### ADD/SUB #0 is redundant
* The non-flag-setting `ADD Rd, Rn, #0` or `SUB Rd, Rn, #0` is a
  no-op when `Rd == Rn` and is equivalent to `MOV Rd, Rn` when
  `Rd != Rn`. Modern toolchains usually emit the `MOV` (ORR-alias)
  form directly, but the explicit `ADD #0` shows up occasionally in
  real code, notably as a way to set up a function argument from a
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

### redundant zero-CMP/TST after a flag-setting ALU
* `adds/subs/ands/bics/adcs/sbcs Rd, ... ; cmp Rd, #0 ; b.eq/b.ne L`
  -- the S-variant ALU already set `Z = (Rd == 0)`, so the `CMP/TST`
  is recomputing the same `Z`. The `B.EQ/B.NE` can read the
  S-variant's flags directly; the `CMP/TST` is dead.
* v1 requires the full three-instruction window: S-variant
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

### MUL by constant foldable to shift/add
* `mov xc, #(1<<N) ; mul xd, xa, xc` instead of `lsl xd, xa, #N`
  (power-of-2 multiplier). Same for W-form.
* `mov xc, #(2^N + 1) ; mul xd, xa, xc` instead of
  `add xd, xa, xa, lsl #N`.
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
* Compilers strength-reduce constant multiplies aggressively, so
  real-binary hit density is low; survey of a dozen system and
  application binaries found 10 hits in Firefox's XUL and 0 in
  `kubectl`, `dyld`, `git`, `python3`, etc.

### MNEG by constant foldable to NEG/SUB
* Direct symmetric counterpart to the MUL strength reduction.
  `MNEG Rd, Rn, Rm` is the canonical alias for
  `MSUB Rd, Rn, Rm, ZR`; same MOV-chain plumbing applies.
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
* Hit density is even lower than MUL: real MNEGs almost always
  have computed (non-constant) operands. Survey of the same
  dozen binaries found 0 hits.

### UDIV by constant foldable to shift
* `mov xc, #(1<<N) ; udiv xd, xn, xc` -> `lsr xd, xn, #N`. Same
  MOV-chain plumbing as the MUL/MNEG checks.
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

### MOV + ADD/SUB foldable to immediate form
* `mov xc, #C ; add xd, xn, xc` instead of `add xd, xn, #C` when
  `C` fits the ADD/SUB immediate encoding (12-bit unsigned with
  optional `LSL #12`: `C` in `[1, 0xFFF]` or `C` a multiple of
  `0x1000` with `C/0x1000` in `[1, 0xFFF]`). Same for `SUB`,
  `ADDS`, `SUBS`, and the `CMP`/`CMN` aliases (S-variant with
  `Rd == ZR`).
* Reuses the MOVZ/MOVK chain state. ADD is commutative -- either
  operand may be the MOV destination. SUB is not: only
  `Rm == mov_rd` folds, since `Rn == mov_rd` would need a
  reverse-subtract that AArch64 lacks. Width of the MOV chain
  must match the consumer's.
* `C == 0` is excluded (the no-op / MOV-to-Rn case is covered by
  check_add_sub_zero); `ZR` as the non-MOV operand is excluded
  (degenerate MOV/NEG).
* Hit density is modest -- compilers usually fold these, but
  Go-compiled binaries (`kubectl`, `docker`) and Firefox's `XUL`
  leak the pattern often; survey found 230 hits in XUL, 35 each
  in kubectl/docker, 12 in dyld, with smaller counts elsewhere.

### MOV + AND/ORR/EOR/ANDS foldable to bitmask immediate
* `mov xc, #C ; and xd, xn, xc` instead of `and xd, xn, #C` when
  `C` is a valid AArch64 bitmask immediate (a rotated run of
  consecutive 1s at one of esize=2/4/8/16/32/64). Same for
  `ORR`, `EOR`, and `ANDS` -- and the `TST` alias (`ANDS` with
  `Rd == ZR`).
* Reuses `is_bitmask_immediate` as the encodability predicate; 0
  and the all-ones-at-width are not bitmask immediates, so those
  trivial constants naturally skip.
* The N = 1 family (`BIC`, `ORN`, `EON`, `BICS`) has no
  immediate form in AArch64 and is excluded by the decoder.
* All four are commutative; either Rn or Rm may be the MOV
  destination.
* Real-binary survey: 187 hits in Firefox's XUL (mostly single-bit
  or shifted-bit OR patterns like `orr xd, xn, #(1<<40)`), 0 in
  kubectl/docker/dyld/git/python3/openssl. Different distribution
  from the ADD/SUB-imm check because the bitmask-imm encoding
  excludes most arbitrary small constants.

### MOV #0 + use foldable to ZR
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
* Hit density is very high in XUL (4466), modest in dyld (40) and
  openssl (46); 0 in kubectl/docker/git/python3 -- Go's compiler
  is good about emitting `STR XZR` directly.

### MUL + ADD/SUB foldable to MADD/MSUB
* `mul xt, xa, xb ; add xd, xt, xc` -> `madd xd, xa, xb, xc`.
  Standard array-indexing pattern (`base + i*stride`). Same for the
  commuted ADD (`add xd, xc, xt`) and for SUB with Rm=xt
  (`sub xd, xc, xt -> msub xd, xa, xb, xc`).
* `sub xd, xt, xc` is NOT folded: MSUB computes `Ra - Rn*Rm`, not
  `Rn*Rm - Ra`. There is no AArch64 instruction matching the
  latter form in one op.
* Conservative soundness: Rd of the ADD/SUB must equal Rt (so the
  MUL's destination is overwritten and its post-MUL value is
  dead), and the accumulator operand must not equal Rt (otherwise
  the ADD reads the MUL's result twice while the MADD rewrite
  reads pre-MUL values, diverging).
* S-variants (ADDS/SUBS) skipped: MADD/MSUB have no flag-setting
  form. Widths must match (both W or both X).
* Real-binary survey hits: XUL 2, libmozinference 7, libmozglue 4,
  libgkcodecs 1; 0 in kubectl/docker/dyld/git/python3/openssl.
  Compilers reliably fuse MUL+ADD into MADD; the residual hits
  are in code paths where the optimizer didn't see the data flow.

### NEG + ADD/SUB foldable to SUB/ADD
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

### ADD + LDR foldable to register-offset LDR
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
* STR is intentionally not flagged: there is no analogous
  Rd-overwrite to prove Xt is dead after the store.
* Rn = XZR in the ADD is excluded because Rn = 31 in the LDR's
  register-offset form means SP, a semantic mismatch. Rm = XZR
  (degenerate ADD) is skipped for cleanliness.
* Real-binary survey hits: XUL 155, libgkcodecs 5; 0 in
  git/python3/openssl/dyld/libmozglue/libmozinference. Compilers
  fuse most cases via the register-offset addressing mode; the
  residual hits are in code paths where the address temporary's
  liveness wasn't fully analyzed.

### ADD + LDR foldable to immediate-offset LDR
* `add xt, xn, #a ; ldr xt, [xt, #b]` -> `ldr xt, [xn, #(a+b)]`,
  with `b == 0` the most common case. The immediate-form
  complement of the register-offset fold: same Rd-overwrite
  soundness argument, but the ADD's constant offset (plus the
  LDR's, if any) moves into the LDR's unsigned immediate slot.
* Encoding constraint: the combined byte offset must be a multiple
  of the LDR's access size and its scaled value must fit in 12
  bits. The LDR's own imm12 is already a multiple of access_size,
  so alignment is determined solely by the ADD's byte immediate.
  The ADD's `sh=1` form (`imm12 << 12`) is supported.
* Rn = SP (Rn = 31 in ADD-imm) is intentionally flagged: ADD-imm
  and LDR-uimm both encode 31 as SP, so the canonical stack-
  relative load pattern (`add xt, sp, #imm ; ldr xt, [xt]`) folds
  correctly. Rd = SP in the ADD is excluded -- folding would
  discard the observable SP update.
* SUB-immediate is not folded: the LDR unsigned-offset form has
  no negative-immediate encoding.

### LDR/STR + ADD foldable to post-indexed LDR/STR
* `ldr xt, [xn] ; add xn, xn, #imm` -> `ldr xt, [xn], #imm`. Same
  for STR and all four access sizes (B/H/W/X). The post-indexed
  encoding already expresses "load/store from `[xn]` and then bump
  `xn` by imm", so the rewrite is a literal source-to-encoding
  fold with no semantic change.
* What you actually save: 4 bytes per fold and one fetch/decode
  slot. The backend cost is typically unchanged -- most modern OoO
  cores (Apple M-series, Cortex-A76+, Neoverse N1+) crack the
  post-indexed load into two micro-ops (load and base-register
  writeback), the same backend work as the original two
  instructions. Critical-path latency is unchanged. The wins are in
  code size, I-cache footprint, and front-end bandwidth (helpful
  on decode-bound inner loops); don't expect a measurable cycle
  drop on backend-bound code. Caveat: an analogous LDP/STP +
  writeback fold (not implemented here) can be slower on Apple
  cores because LDP-with-writeback decodes into more micro-ops
  than the separate-ADD variant -- single-register LDR/STR does
  not have this issue.
* Encoding constraint: post-index uses a 9-bit signed immediate
  (-256..255). v1 only handles ADD-imm with imm in 1..255; SUB-imm
  (negative direction) and the `sh=1` form (imm >= 4096) are
  rejected. The LDR/STR must have imm12 == 0 -- a non-zero offset
  combined with a base bump matches the pre-indexed pattern, not
  post-index.
* Soundness: the ADD must be a self-update (`Rd == Rn ==` LDR/STR's
  `Rn`), since post-index can only update its own base register.
  Rt == Rn writeback is UNPREDICTABLE for loads and CONSTRAINED
  UNPREDICTABLE for stores, so that case is rejected -- except
  when Rn == 31, where Rn means SP and Rt means XZR (distinct
  registers, no conflict). `str xzr, [sp] ; add sp, sp, #imm` and
  `ldr xt, [sp] ; add sp, sp, #imm` are both flagged as the
  canonical stack-frame teardown patterns.
* `ADDS` (flag-setting) is excluded because post-index has no
  flag-setting form. Distinct from `check_add_ldr_imm_offset`,
  which catches the reversed sequence (ADD then LDR) and folds
  into the unsigned-offset form rather than post-index.

### ADD + LDR/STR foldable to pre-indexed LDR/STR
* `add xn, xn, #imm ; ldr xt, [xn]` -> `ldr xt, [xn, #imm]!`. Same
  for STR and all four access sizes (B/H/W/X). The pre-indexed
  encoding already expresses "bump `xn` by imm and then load/store
  from the new `xn`", which is exactly what the source sequence
  does.
* Same code-size and decode-slot win as the post-index check. The
  backend cost is also unchanged: most modern OoO cores crack
  pre-indexed loads into two micro-ops (address update and load),
  the same dependency chain as ADD followed by LDR.
* Encoding constraint: same 9-bit signed range as post-index; v1
  accepts ADD imm in 1..255. The LDR/STR must have imm12 == 0 --
  a non-zero offset combined with a base bump has no single
  pre-index expression that preserves both the load address and
  the final base register value.
* Soundness: the ADD must be a self-update (`Rd == Rn ==` LDR/STR's
  `Rn`). Rt == Rn writeback is rejected (UNPREDICTABLE / CONSTRAINED
  UNPREDICTABLE), except when Rn == 31 (Rn means SP, Rt means XZR;
  distinct registers).
* Cross-check interaction with [check_add_ldr_imm_offset]: when
  Rt == Rn == ADD's Rd, that earlier check fires instead and folds
  to the unsigned-offset form (no writeback). When Rt != Rn but
  rn == ADD's Rd, only this check fires. So the two checks together
  cover the full ADD + LDR/STR space without double-firing on the
  same pair.

## Compilation

armlint depends on [Capstone](https://www.capstone-engine.org/) and uses
`pkg-config` to locate it. On macOS:

```
brew install capstone
```

On Debian/Ubuntu:

```
apt install libcapstone-dev pkg-config
```

Build:

```
git clone https://github.com/gaul/armlint.git armlint
cd armlint
make all
```

Two test suites are available. `make test` runs the unit tests against
fabricated byte sequences, exercising the check registry directly.
`make integration-test` runs the snapshot suite under `fixtures/`:
each `.s` is assembled with `clang -arch arm64` and `armlint`'s
output is diffed against a checked-in `.expected` file. The
integration suite covers the Mach-O parser and the report formatting,
which the unit tests bypass; it skips cleanly on hosts without an
arm64 toolchain. After an intentional output change, regenerate the
snapshots with `make integration-test-regen` and review the diff
before committing.

## Usage

armlint is intended to be part of compiler test suites which should
`#include "armlint.h"` and link `libarmlint.a`. It can also read
arbitrary AArch64 binaries (ELF, thin Mach-O, or universal/fat Mach-O):

```
./armlint /path/to/aarch64/binary
./armlint /bin/ls
```

## References

* [Arm Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest/) - A64 instruction set
* [Arm Cortex-A optimization guides](https://developer.arm.com/documentation) - per-microarchitecture tuning notes
* [Capstone disassembly framework](https://www.capstone-engine.org/) - library to parse instructions
* [x86lint](https://github.com/gaul/x86lint) - x86-64 equivalent of asmlint

## License

Copyright (C) 2026 Andrew Gaul

Licensed under the Apache License, Version 2.0
