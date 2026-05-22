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
