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
* TST single-bit + B.EQ/NE foldable into TBZ/TBNZ
  - `tst w0, #(1<<5) ; b.eq target` instead of `tbz w0, #5, target`.
    Same for `b.ne` -> `tbnz`. Only the immediate-form `TST` is
    matched (`ANDS XZR, Rn, #imm`) and only when the immediate is a
    single power-of-two bit.
  - Range: `TBZ`/`TBNZ` use a 14-bit signed offset (~32 KB reach),
    much shorter than `B.cond`'s 19-bit (~1 MB). The fold is
    suggested only when the target fits in the TBZ encoding.
  - Soundness: same NZCV-liveness scan as the CMP-branch check.
* redundant zero-extension after a producer that already zeroed those bits
  - Generalises the previous "redundant UXTW after W-form ALU" rule
    to size-aware producer/consumer pairs. The check tracks the
    threshold `P` at which the producer guarantees `Rt[63:P] == 0`:
    32 for W-form data-processing or `LDR Wt` / `LDRSB Wt` / `LDRSH Wt`,
    16 for `LDRH Wt`, 8 for `LDRB Wt`. A consumer that clears bits
    above `C` is redundant when `P <= C`.
  - Recognised consumers: `UXTB / UXTH / UXTW` (W- or X-form UBFM
    aliases with `immr=0`, `imms ∈ {7,15,31}`, `N=sf`) and AND-imm
    with mask `0xff` / `0xffff` / `0xffffffff` -- both forms in W and
    X register variants.
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

## License

Copyright (C) 2026 Andrew Gaul

Licensed under the Apache License, Version 2.0
