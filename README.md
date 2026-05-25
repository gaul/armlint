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

* suboptimal MOVZ/MOVK sequence
  - `movz w0, #0x6666 ; movk w0, #0x6666, lsl #16` instead of
    `mov w0, #0x66666666` (single bitmask-immediate ORR)
* LSL foldable into shifted-register form
  - `lsl w0, w1, #3 ; add w0, w2, w0` instead of
    `add w0, w2, w1, lsl #3`. Same for SUB, AND, ORR, EOR (and
    flag-setting variants). Conservative: v1 only flags when the
    consumer overwrites the LSL destination, guaranteeing the LSL
    result is dead.
* compare-zero branch foldable into CBZ/CBNZ
  - `cmp w0, #0 ; b.eq target` instead of `cbz w0, target`. Same for
    `b.ne` -> `cbnz`. Also matches the equivalent zero-test idioms
    `cmp Rn, xzr` (SUBS XZR, Rn, XZR) and `tst Rn, Rn`
    (ANDS XZR, Rn, Rn): all three set `Z=1` iff `Rn==0` and so fold
    identically.
  - Soundness: `CBZ`/`CBNZ` does not write NZCV, but `CMP Rn, #0`
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
* compare-zero signed-branch foldable into TBZ/TBNZ
  - `cmp wn, #0 ; b.lt target` (or `b.ge`/`b.mi`/`b.pl`) folds to
    `tbnz wn, #(datasize-1), target` (or `tbz`). After `CMP Rn, #0` /
    `CMP Rn, ZR` / `TST Rn, Rn`, `V == 0`, so `B.LT` (N != V) reduces
    to "N == 1" -- exactly a test of the sign bit. `B.MI` directly
    tests `N`; `B.GE`/`B.PL` are the inverse.
  - Range: `TBZ`/`TBNZ` use a 14-bit signed offset (~32 KB reach),
    vs. `B.cond`'s 19-bit (~1 MB). The fold is suggested only when
    the target fits in the TBZ encoding.
  - Soundness: same NZCV-liveness scan as the CMP-branch check
    above. The rewrite drops the CMP/TST, so downstream code that
    observes N/C/V before they're overwritten would see different
    values; the scan suppresses on any flag-reader. Shares the
    existing CMP/TST pending slot, which is sufficient because the
    sign-only and EQ/NE conditions are mutually exclusive at the
    same B.cond.
* TST single-bit + B.EQ/NE foldable into TBZ/TBNZ
  - `tst w0, #(1<<5) ; b.eq target` instead of `tbz w0, #5, target`.
    Same for `b.ne` -> `tbnz`. Only the immediate-form `TST` is
    matched (`ANDS XZR, Rn, #imm`) and only when the immediate is a
    single power-of-two bit.
  - Range: `TBZ`/`TBNZ` use a 14-bit signed offset (~32 KB reach),
    much shorter than `B.cond`'s 19-bit (~1 MB). The fold is
    suggested only when the target fits in the TBZ encoding.
  - Soundness: same NZCV-liveness scan as the CMP-branch check.
* bitfield op via two shifts foldable into UBFX/SBFX or UBFIZ/SBFIZ
  - `lsl wd, ws, #a ; lsr wd, wd, #b` folds depending on the
    relationship between `a` and `b`:
    - `b >= a`: extraction. `ubfx wd, ws, #(b-a), #(datasize-b)`.
      With `asr` it folds to `sbfx` (sign-extending).
    - `b < a`: insertion. `ubfiz wd, ws, #(a-b), #(datasize-a)` --
      places `ws[datasize-a-1 .. 0]` at `wd[datasize-b-1 .. a-b]` with
      bits below `a-b` zeroed. With `asr` it folds to `sbfiz`
      (sign-extending the high bits from `ws[datasize-a-1]`).
    - Same for X-form.
  - Compilers occasionally leave the two-shift form when bit-tracking
    can't prove the LSL invariant; armlint flags such pairs as a
    missed combine.
  - v1 requires the consumer's `Rd` and `Rn` to equal the LSL's `Rd`
    so the LSL result is dead after the rewrite.
* shift-and-mask bitfield extraction foldable into UBFX
  - `lsr wd, ws, #n ; and wd, wd, #((1<<w)-1)` extracts bits
    `ws[n+w-1 .. n]`; equivalent to `ubfx wd, ws, #n, #w` (capping
    `w` at `datasize-n` when the mask is wider than the LSR-fillable
    bits). Same for X-form.
  - Mask must be a contiguous run of low bits with no rotation
    (`immr=0` and `(N, imms)` encoding `S+1=w` ones at the
    appropriate element size); rotated/non-contiguous masks like
    `#0x6` are correctly skipped.
* redundant zero-extension after a producer that already zeroed those bits
  - Generalises the previous "redundant UXTW after W-form ALU" rule
    to size-aware producer/consumer pairs. The check tracks the
    threshold `P` at which the producer guarantees `Rt[63:P] == 0`:
    32 for W-form data-processing or `LDR Wt` / `LDRSB Wt` / `LDRSH Wt`,
    16 for `LDRH Wt`, 8 for `LDRB Wt`. A consumer that clears bits
    above `C` is redundant when `P <= C`.
  - Recognised consumers: `UXTB / UXTH / UXTW` (W- or X-form UBFM
    aliases with `immr=0`, `imms ∈ {7,15,31}`, `N=sf`), AND-imm
    with mask `0xff` / `0xffff` / `0xffffffff` (both forms in W and
    X register variants), and `MOV Wd, Wd` (`ORR Wd, WZR, Wd` with
    `Rm = Rd`; the W-form register MOV writes back through the W
    register and so clears X[63:32], giving `C = 32`).
  - Example flags: `add w0,w1,w2 ; uxtw x0,w0`, `ldrh w0,[x1] ; uxth
    w0,w0`, `ldrb w8,[x9] ; and w8,w8,#0xff`. Counter-example (`P >
    C`, not flagged): `ldr w0,[x1] ; uxth w0,w0` -- LDR W loads 32
    valid bits, so UXTH would actually clear bits 31..16.
  - v1 still requires `Rd == Rn == producer.Rd` so the consumer is
    purely dead. Producer set covers all W-form DP classes (`ADD/SUB`
    immediate/shifted/extended, logical immediate, `MOVZ/MOVN/MOVK`,
    bitfield `SBFM/BFM/UBFM`, `EXTR`, logical shifted register,
    `ADC/SBC`, conditional select, DP-3/2/1-source) plus integer
    loads with `Wt` destination in any addressing mode.
* `MOV Xd, Xd` is a literal no-op
  - The X-form register MOV alias (`ORR Xd, XZR, Xm, LSL #0`) with
    `Rm = Rd` reads `Xd` and writes the same 64 bits back; the
    instruction has no architectural effect and can be removed. Modern
    optimisers almost never emit this, but it shows up occasionally in
    hand-written assembly and in legacy object code.
  - The W-form `MOV Wd, Wd` is NOT a no-op: writing through `Wd`
    clears `X[63:32]`. It is handled instead as a consumer of the
    redundant-zero-extension check above, where it fires only when a
    preceding producer already zeroed those bits.
* redundant sign-extension after a producer that already replicated the sign
  - Mirror of the zero-extension framework above. The check tracks two
    thresholds `(S, W)`: the producer guarantees `Rd[W-1:S] =
    sign(Rd[S-1])`. A consumer `SXTB / SXTH / SXTW` with thresholds
    `(S_c, W_c)` is redundant iff `S_p <= S_c` AND `W_p == W_c` AND
    `Rd == Rn == producer.Rd`.
  - Recognised producers: `SXTB / SXTH / SXTW` (SBFM aliases with
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
  - `W_p == W_c` (not `<=`) because a W-form consumer writes back
    through `Wd` and zeros `X[63:32]`, which differs from an X-form
    producer's sign-extended upper half. Example flagged: `ldrsb w0,
    [x1] ; sxtb w0, w0`; `ldrsh x0, [x1] ; sxth x0, w0`; `ldrsb w0,
    [x1] ; sxth w0, w0` (S_p=8 subsumes S_c=16 within W=32).
    Counter-example: `ldrsb w0, [x1] ; sxtb x0, w0` -- producer left
    `X[63:32] = 0`, consumer would set those bits to sign of byte;
    not redundant.
  - Same producer state also feeds a "dead sign-extension" path: if
    the next instruction is a zero-ext consumer (`UXTB`/`UXTH`/`UXTW`,
    `AND` with low-mask, or `MOV Wd, Wd`) that clears bits `>= C_c`
    with `C_c <= S_p`, the consumer overwrites every sign-extended
    bit and the sign-extension is dead. No width-matching constraint
    is needed -- when widths mismatch, the W-form auto-zero of
    `X[63:32]` covers the upper half. Example flagged: `sxtb w0, w1 ;
    uxtb w0, w0` (replace with `uxtb w0, w1`); `ldrsb w0, [x1] ;
    uxtb w0, w0` (replace with `ldrb w0, [x1]`); `ldrsw x0, [x1] ;
    uxtw x0, w0` (replace with `ldr w0, [x1]`).
* self-op identities (`AND/ORR/EOR/SUB/BIC/ORN/EON Rd, Rs, Rs`)
  - `AND Rd, Rs, Rs` and `ORR Rd, Rs, Rs` collapse to `MOV Rd, Rs`
    (identity). `EOR Rd, Rs, Rs`, `SUB Rd, Rs, Rs`, and `BIC Rd, Rs,
    Rs` (= `Rs AND NOT Rs`) collapse to `MOV Rd, XZR` (zero). `ORN
    Rd, Rs, Rs` (= `Rs OR NOT Rs`) and `EON Rd, Rs, Rs` (= `Rs XOR
    NOT Rs`) collapse to `MOV Rd, #-1` / `MOVN Rd, #0` (all-ones).
    Both W- and X-form.
  - The flag-setting variants `ANDS Rd, Rs, Rs`, `SUBS Rd, Rs, Rs`,
    and `BICS Rd, Rs, Rs` are deliberately NOT flagged: writing `Rd`
    while setting flags is the user's intent (combined zero-test +
    register copy or register zero).
  - `Rd = 31` (result discarded) and `Rn = 31` (`ZR` source, not a
    real self-op) are excluded.
  - On uarches with move elimination, `MOV Rd, Rs` is zero-cycle
    while `AND/ORR Rd, Rs, Rs` goes through the ALU. `EOR Rd, Rs, Rs`
    is the canonical x86 zero idiom that occasionally bleeds into
    AArch64 toolchain output; the canonical AArch64 form is `MOV Rd,
    XZR` (eight occurrences observed in dyld at the time of writing).
* adjacent LDR/STR foldable into LDP/STP
  - Two unsigned-offset `LDR Wt, [Rn, #imm12*4]` (or X-form,
    scale 8) to consecutive scaled offsets fold into a single
    `LDP Wt1, Wt2, [Rn, #imm7*4]`. Analogous for stores ->
    `STP`. Both W- and X-form supported; load+load and store+store
    only (no mixing).
  - v1 supports only the unsigned-offset form. The scaled imm12
    guarantees natural alignment to the access size, which the LDP
    encoding requires. `LDUR` (unscaled) and pre-/post-indexed forms
    are deferred: their byte offsets aren't constrained to be a
    multiple of the access size, and `LDP/STP` on unaligned
    addresses has implementation-defined behaviour on AArch64
    (some cores fault even when single `LDR/STR` works under
    `SCTLR_EL1.A = 0`).
  - Constraints checked: same base register `Rn`; same access size
    (both W or both X); same direction (load/load or store/store);
    consecutive offsets (`imm12_2 = imm12_1 + 1` in scaled units);
    `Rt1 != Rt2` (LDP/STP requires distinct destinations); for
    loads, the first instruction's `Rt != Rn` (else the first load
    clobbers the base before the second load reads it). The LOWER
    of the two imm12s must also fit LDP's signed-7-bit imm7 (i.e.,
    be at most 63 for non-negative unsigned-offset sources).
  - Reverse-order pairs (`ldr Rt2, [Rn, #imm+1] ; ldr Rt1, [Rn,
    #imm]` -- higher offset first) are also coalesced, into a
    `ldp Rt1, Rt2, [Rn, #imm]` with the Rt operands ordered by
    ascending address. The load-aliasing concern is about source
    order, not address order, so the constraint is on the FIRST
    instruction in source order regardless of which offset it
    targets. Reverse-order pairs are common in Go-compiled
    binaries (~24% of total LDP/STP coalesce findings in kubectl).
  - Four consecutive LDR/STRs fold into TWO non-overlapping
    LDP/STPs (after firing, the state resets so the second LDR
    isn't also used as the first of a new pair).
  - Atomicity caveat: a single LDP is NOT atomic across its two
    halves (AArch64 doesn't guarantee single-copy atomicity for
    pairs), but neither are two separate LDRs. So the rewrite
    doesn't change ordering or atomicity guarantees -- acquire /
    release variants use different opcodes.
  - Adjacent unsigned-offset `LDRSW Xt, [Rn, #imm12*4]` pairs fold
    analogously into a single `LDPSW Xt1, Xt2, [Rn, #imm7*4]`. Same
    constraints (same base, consecutive offsets, distinct Rts, first
    `Rt != Rn`, first imm12 <= 63), with the added requirement that
    the kind matches: a pending `LDR` does not pair with an `LDRSW`
    (different opcode, different sign-extension semantics). LDPSW is
    always 64-bit destination, load-only, 4-byte transfer. LLVM is
    aggressive about emitting LDPSW directly, so LLVM-built system
    binaries show 0 hits; Go-compiled binaries (`kubectl`, `docker`,
    ...) commonly leave un-coalesced LDRSW pairs.
* BFXIL synthesis via AND-AND-ORR
  - `AND Rd, Rd, #~mask ; AND Rt, Rs, #mask ; ORR Rd, Rd, Rt` (with
    `mask = (1<<w)-1`, the two ANDs in either order, and the ORR's
    second-and-third operands in either order) is equivalent to a
    single `BFXIL Rd, Rs, #0, #w`. Both W- and X-form. The check
    detects the 3-instruction window with strict adjacency.
  - The high-mask `AND Rd, Rd, #~mask` is identified by the
    bitmask-immediate encoding `immr = imms + 1` (S =
    `datasize-w-1`, R = `datasize-w`, esize = datasize). The
    low-mask consumer reuses the existing `decode_and_imm_lowmask`
    decoder. The ORR is logical-shifted-register with LSL #0.
  - Aliasing constraints needed for the BFXIL rewrite to be
    semantically equivalent: `Rt != clear.Rd` (else the isolate
    clobbers the cleared register in place), `Rt != Rs` (else the
    isolate modifies the source -- BFXIL leaves the source
    unchanged), and `Rs != clear.Rd` (the degenerate case where
    Rs is the just-cleared register yields the wrong result -- the
    original sequence zeros Rd's low bits, but BFXIL Rd, Rd, ... is
    a no-op).
  - Modern compilers fuse this pattern themselves; 0 hits in the
    system-binary sample. Useful for hand-written assembly and
    legacy object code.
* CSEL same-operand identity (`CSEL Rd, Rn, Rn, cond`)
  - When the CSEL's `Rn == Rm`, both branches produce `Rn`, so the
    cond is irrelevant and the instruction is equivalent to `MOV Rd,
    Rn`. The CSEL also reads NZCV for no reason. Both W- and X-form.
  - Only `CSEL` (op2 = 00) is flagged. The other members of the
    conditional-select family -- `CSINC`, `CSINV`, `CSNEG` -- have
    different "else" branches (Rn+1, ~Rn, -Rn) and are NOT identities
    when `Rn == Rm`. The decoder enforces `(op & 0x7FE00C00) ==
    0x1A800000`, which fixes op2 = 00.
  - `Rd = 31` (result discarded) and `Rn = 31` (`ZR` source) are
    excluded for consistency with the other self-op identity check.
* ADD/SUB #0 is redundant
  - The non-flag-setting `ADD Rd, Rn, #0` or `SUB Rd, Rn, #0` is a
    no-op when `Rd == Rn` and is equivalent to `MOV Rd, Rn` when
    `Rd != Rn`. Modern toolchains usually emit the `MOV` (ORR-alias)
    form directly, but the explicit `ADD #0` shows up occasionally in
    real code, notably as a way to set up a function argument from a
    callee-saved register.
  - The `ADDS`/`SUBS` flag-setting variants are not flagged: writing
    `Rd` and setting `Z = (Rn == 0)` may both be wanted. The SP
    encoding (`Rd = 31` or `Rn = 31`) is also excluded because that's
    the canonical `MOV (to/from SP)` alias and the only way to spell
    `MOV X0, SP` / `MOV SP, X0`.
  - The `Rd == Rn` case is further suppressed when immediately
    preceded by `ADR`/`ADRP` with the same `Rd`: that's a
    page-relative addressing pair (`adrp x8, page ; add x8, x8,
    #pageoff`) where the linker happened to resolve `pageoff` to 0.
    Removing the `ADD` requires re-linking, not an assembler rewrite,
    so it's not actionable.
* redundant zero-CMP/TST after a flag-setting ALU
  - `adds/subs/ands/bics/adcs/sbcs Rd, ... ; cmp Rd, #0 ; b.eq/b.ne L`
    -- the S-variant ALU already set `Z = (Rd == 0)`, so the `CMP/TST`
    is recomputing the same `Z`. The `B.EQ/B.NE` can read the
    S-variant's flags directly; the `CMP/TST` is dead.
  - v1 requires the full three-instruction window: S-variant
    immediately followed by `CMP Rd, #0` / `CMP Rd, ZR` / `TST Rd, Rd`,
    immediately followed by `B.EQ`/`B.NE`. The same forward
    NZCV-liveness scan as the CMP+B.cond check confirms that
    downstream code does not observe N/C/V (which the S-variant sets
    differently from the `CMP`).
  - Combines with the CMP+B.cond -> CBZ/CBNZ check above: both fire
    on the matching pattern, giving the user a choice between
    dropping the `CMP` (and keeping the `B.cond`) or folding the
    `CMP`+`B.cond` pair into a `CBZ`/`CBNZ`. Both rewrites have
    identical downstream behaviour.

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
