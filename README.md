# armlint

armlint examines AArch64 machine code to find suboptimal instruction
sequences. For example, building the constant `0x66666666` as

```asm
movz w0, #0x6666
movk w0, #0x6666, lsl #16
```

is two instructions where one would do, because `0x66666666` is encodable
as an AArch64 logical (bitmask) immediate:

```asm
mov w0, #0x66666666     ; orr w0, wzr, #0x66666666
```

armlint helps compiler writers and assembly authors generate tighter
code, and documents corners of the A64 instruction set.

## Design and limitations

armlint is a peephole analyzer. It decodes each 32-bit A64 instruction
directly from the binary and matches it by mask and value, resolving
aliases (for example `MUL` is `MADD` with a zero accumulator) so that
both spellings of a pattern are caught. It then looks for a short window
of adjacent instructions that a shorter or cheaper encoding can replace.

The overriding rule is soundness: armlint emits a finding only when the
rewrite provably preserves the architectural result. For a tool that
suggests code changes, a false positive is the worst failure, so it errs
toward false negatives -- a missed opportunity is cheaper than a wrong
one. Each check documents the exact conditions under which its rewrite is
equivalent; the constraints below are the ones they share.

* **Strict adjacency.** A producer and its consumer must be consecutive;
  an unrelated instruction between them suppresses the finding. armlint
  does not reorder code or look through intervening instructions.
* **Liveness is proved structurally, not analyzed.** A
  producer-into-consumer fold fires only when the consumer overwrites the
  producer's destination register, proving the intermediate value is
  dead. There is no general-purpose register liveness pass.
* **MOV-chain folds assume the constant is dead.** Folds that absorb a
  materialized constant -- `MUL`/`MNEG`/`UDIV` by a constant, `MOV` +
  `ADD`/`AND`/`ORR`/`EOR`, `MOV #0` -- report a saving only if the
  constant register feeds nothing else, which armlint cannot confirm
  without a liveness pass. The consumer rewrite itself stays valid
  regardless.
* **Flag liveness uses a bounded forward scan.** The branch- and
  flag-folding checks drop a `CMP`/`TST` only after a bounded scan of the
  fall-through path confirms that no later instruction reads N/C/V before
  they are overwritten. Every NZCV reader is recognized -- the integer
  conditionals (`B.cond`, `CSEL`/`CSINC`/..., `CCMP`/`CCMN`, `ADC`/`SBC`)
  and the floating-point ones (`FCSEL`, `FCCMP`/`FCCMPE`) -- and an
  unconditional branch on the path (whose destination the scan cannot
  see) ends it conservatively. The scan does not follow the folded
  branch's own taken edge, so these folds assume N/C/V is dead at every
  branch target. That holds for compiled code, where the flags are
  defined within a basic block, but not for hand-written assembly that
  deliberately keeps a flag live into a branch target.

Findings are *opportunities*, not guaranteed speedups: some -- the pre-
and post-indexed addressing folds -- are code-size and front-end wins
that are backend-neutral. Each check's notes say what its rewrite
actually saves.

## Implemented analyses

Each row links to its full description -- mechanics, soundness, and what
the rewrite saves -- in [analyses.md](analyses.md).

| Pattern | Rewrite |
| --- | --- |
| [`movz`/`movn` + `movk` (over-long constant)](analyses.md#suboptimal-movzmovk-sequence) | bitmask-immediate `mov`, or minimal `movz`/`movn` + `movk` chain |
| [`lsl`/`lsr`/`asr`/`ror` + `add`/`sub`/`and`/`orr`/`eor`](analyses.md#shift-foldable-into-shifted-register-form) | `add Rd, Rn, Rm, <shift> #n` |
| [`sxtw`/`uxtb`/`sxtb` + `add`/`sub`](analyses.md#extend-foldable-into-shiftedextended-register-form) | `add Rd, Rn, Wm, sxtw` |
| [`cmp #0` + `b.eq`/`b.ne`/`b.hi`/`b.ls`](analyses.md#compare-zero-branch-foldable-into-cbzcbnz) | `cbz`/`cbnz` |
| [`cmp #0` + `b.lt`/`b.ge`/`b.mi`/`b.pl`](analyses.md#compare-zero-signed-branch-foldable-into-tbztbnz) | `tbnz`/`tbz Rn, #(msb)` |
| [`tst #(1<<k)` + `b.eq`/`b.ne`](analyses.md#tst-single-bit--beqne-foldable-into-tbztbnz) | `tbz`/`tbnz Rn, #k` |
| [`lsl` + `lsr`/`asr`](analyses.md#bitfield-op-via-two-shifts-foldable-into-ubfxsbfx-or-ubfizsbfiz) | `ubfx`/`sbfx`/`ubfiz`/`sbfiz` |
| [`lsr` + `and #mask`](analyses.md#shift-and-mask-bitfield-extraction-foldable-into-ubfx) | `ubfx` |
| [`and #mask` + `lsr`](analyses.md#mask-and-shift-bitfield-extraction-foldable-into-ubfx) | `ubfx` |
| [`and #mask` + `lsl` (or `lsr` + `lsl`)](analyses.md#mask-and-shift-left-foldable-into-ubfiz-or-shift-round-trip-into-a-clearing-and) | `ubfiz` (or clearing `and`) |
| [zeroing producer + `uxtb`/`uxth`/`uxtw`/`and`](analyses.md#redundant-zero-extension-after-a-producer-that-already-zeroed-those-bits) | drop the zero-extension |
| [`mov xd, xd`](analyses.md#mov-xd-xd-is-a-literal-no-op) | remove (architectural no-op) |
| [sign-extending producer + `sxtb`/`sxth`/`sxtw`](analyses.md#redundant-sign-extension-after-a-producer-that-already-replicated-the-sign) | drop the sign-extension |
| [`and`/`orr`/`eor`/`sub`/`bic`/`orn`/`eon` with `Rs, Rs`](analyses.md#self-op-identities-andorreorsubbicorneon-rd-rs-rs) | `mov` / zero / all-ones |
| [`ldr`+`ldr` / `str`+`str` (consecutive)](analyses.md#adjacent-ldrstr-foldable-into-ldpstp) | `ldp`/`stp` (integer or FP/SIMD, and `ldpsw`) |
| [`and` + `and`/`ubfiz` + `orr` (clear/isolate/merge)](analyses.md#bfxil-and-bfi-bitfield-insert-synthesis) | `bfxil`/`bfi` |
| [`csel Rd, Rn, Rn, cond`](analyses.md#csel-same-operand-identity-csel-rd-rn-rn-cond) | `mov Rd, Rn` |
| [`add`/`sub Rd, Rn, #0`](analyses.md#addsub-0-is-redundant) | `mov Rd, Rn`, or remove |
| [`adds`/`subs`/`ands` + `cmp #0` + `b.eq`/`b.ne`](analyses.md#redundant-zero-cmptst-after-a-flag-setting-alu) | drop the redundant `cmp`/`tst` |
| [`mov #2^N` + `mul`](analyses.md#mul-by-constant-foldable-to-shiftadd) | `lsl`, or `add Rd, Ra, Ra, lsl #N` |
| [`mov #C` + `mneg`](analyses.md#mneg-by-constant-foldable-to-negsub) | `neg`, or shifted `neg`/`sub` |
| [`mov #2^N` + `udiv`](analyses.md#udiv-by-constant-foldable-to-shift) | `lsr` |
| [`mov #C` + `add`/`sub`](analyses.md#mov--addsub-foldable-to-immediate-form) | `add`/`sub Rd, Rn, #C` |
| [`mov #C` + `and`/`orr`/`eor`/`ands` or `bic`/`orn`/`eon`/`bics`](analyses.md#mov--andorreorands-or-bicorneonbics-foldable-to-bitmask-immediate) | `and`/`orr`/`eor`/`ands Rd, Rn, #C` (`#~C` for the inverting forms) |
| [`mov #0` + `str`/`add`/`and` use](analyses.md#mov-0--use-foldable-to-zr) | use `wzr`/`xzr` |
| [`mul` + `add`/`sub`](analyses.md#mul--addsub-foldable-to-maddmsub) | `madd`/`msub` (or `mneg`) |
| [`smull`/`umull` + `add`/`sub`](analyses.md#smullumull--addsub-foldable-to-smaddlumaddl) | `smaddl`/`umaddl`/`smsubl`/`umsubl` |
| [`neg` + `add`/`sub`](analyses.md#neg--addsub-foldable-to-subadd) | `sub`/`add` |
| [`mvn` + `and`/`orr`/`eor`/`ands`](analyses.md#mvn--andorreor-foldable-to-bicorneon) | `bic`/`orn`/`eon`/`bics` |
| [`add` + `ldr [xt]`](analyses.md#add--ldr-foldable-to-register-offset-ldr) | `ldr [xn, xm{, lsl #s}]` |
| [`sxtw` + `ldr [xn, xt]`](analyses.md#sxtw--register-offset-ldr-foldable-into-the-load) | `ldr [xn, ws, sxtw {#s}]` |
| [`ldrb`/`ldrh`/`ldr` (or `ldrsb`/`ldrsh Wt`) + `sxtb`/`sxth`/`sxtw`](analyses.md#load--sign-extend-foldable-to-ldrsbldrshldrsw) | `ldrsb`/`ldrsh`/`ldrsw` (`Xt` for the re-widened sign loads) |
| [`add #a` + `ldr [xt]` (incl. `mov xt, sp`)](analyses.md#add--ldr-foldable-to-immediate-offset-ldr) | `ldr [xn, #a]` / `ldr [sp]` |
| [`ldr`/`ldp [xn]` + `add`/`sub xn`](analyses.md#ldrstr-or-ldpstp--addsub-foldable-to-post-indexed-form) | `ldr [xn], #±imm` / `ldp [sp], #imm` (post-index) |
| [`add`/`sub xn` + `ldr`/`stp [xn]`](analyses.md#addsub--ldrstr-or-ldpstp-foldable-to-pre-indexed-form) | `ldr [xn, #±imm]!` / `stp [sp, #-imm]!` (pre-index) |

## Compilation

armlint depends on [Capstone](https://www.capstone-engine.org/) and uses
`pkg-config` to locate it. On macOS:

```sh
brew install capstone
```

On Debian/Ubuntu:

```sh
apt install libcapstone-dev pkg-config
```

Build:

```sh
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
`#include "armlint.h"` and link `libarmlint.a`. Disassemble the
just-emitted machine code with `check_instructions`; its return value is
the number of opportunities found, which a test can assert is zero:

```c
#include "armlint.h"   // also includes <capstone/capstone.h>

// code/code_len: the AArch64 bytes to check (e.g. a function the
// compiler just emitted); base_addr is the address they load at.
// Returns the opportunity count (0 == clean), or -1 on a decode error.
int lint(const uint8_t *code, size_t code_len, uint64_t base_addr)
{
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return -1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    armlint_summary *summary = armlint_summary_create();
    int findings = check_instructions(
        handle, code, code_len, base_addr, /*verbose=*/true, summary);
    armlint_summary_print(summary);   // optional by-type tally

    armlint_summary_destroy(summary);
    cs_close(&handle);
    return findings;
}
```

The `summary` is optional -- pass `NULL` to skip the by-type tally --
and `verbose` controls whether each opportunity is printed as it is
found. armlint can also read arbitrary AArch64 binaries (ELF, thin
Mach-O, or universal/fat Mach-O) directly:

```sh
./armlint /path/to/aarch64/binary
./armlint /bin/ls
```

By default armlint prints only a summary: the opportunities grouped by
type and sorted by prevalence, so it is clear which to look at first,
followed by a total and the number of instructions scanned. A large
binary can have hundreds of thousands of opportunities, so the
per-opportunity detail is suppressed unless requested:

```console
$ ./armlint /bin/ls
Optimization opportunities by type:
      39  ADD + LDR foldable to pre-indexed LDR
      36  ADD + LDR foldable to immediate-offset LDR
       1  adjacent STRs foldable into STP

76 optimization opportunities in 4153 instructions
```

Pass `-v` to also print each opportunity -- its one-line summary plus
the offending instructions, as shown below -- ahead of the summary:

```console
$ ./armlint -v /bin/ls
ADD + LDR foldable to immediate-offset LDR at offset: 0x60: -> ldr w8, [x8, #0x2c] (2 instructions)
  add x8, x8, #0x2c
  ldr w8, [x8]
...
```

The process exits non-zero when any opportunity is found, so armlint
can gate a compiler test suite.

## References

* [Arm Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest/) - A64 instruction set
* [Arm Cortex-A optimization guides](https://developer.arm.com/documentation) - per-microarchitecture tuning notes
* [Capstone disassembly framework](https://www.capstone-engine.org/) - library to parse instructions
* [x86lint](https://github.com/gaul/x86lint) - x86-64 equivalent of armlint

## License

Copyright (C) 2026 Andrew Gaul

Licensed under the Apache License, Version 2.0
