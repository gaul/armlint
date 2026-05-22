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
    `b.ne` -> `cbnz`. v1 matches only the canonical `CMP Rn, #0`
    encoding (SUBS XZR, Rn, #0); does not catch `cmp Rn, xzr` or
    `tst Rn, Rn` (other zero-test idioms).
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
