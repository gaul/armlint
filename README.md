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
equivalent; the constraints below are the ones they share, and
[analyses.md's appendix](analyses.md#appendix-folds-rejected-for-soundness)
collects the near-miss folds that are deliberately never matched (FP
contraction, `fcsel` -> `fmax`, the SDIV remainder, and friends) with
the argument against each.

* **Strict adjacency for matching; bounded lookahead for proof.** The
  instructions of a matched pattern must be consecutive -- an
  unrelated instruction between a producer and its consumer
  suppresses the finding -- and armlint does not reorder code or
  match through intervening instructions. Emission, though, is not
  confined to the pattern window: as the following bullets describe,
  many findings are held back while a bounded forward scan (16
  instructions) walks the fall-through path past the consumer to
  prove a register or the flags dead, so an instruction well after
  the pair can also suppress a finding. The scan only gates emission
  -- it never widens a match, so every reported rewrite still
  replaces only the adjacent instructions shown.
* **Liveness is proved structurally, or by a bounded forward scan.** A
  producer-into-consumer fold fires when the consumer overwrites the
  producer's destination register, proving the intermediate value is
  dead. Folds whose saving is a deleted write with no such overwrite
  defer instead: a bounded forward scan of the fall-through path must
  see the register overwritten before any read or control transfer.
  This is how the address folds admit stores and loads into a fresh
  register -- `add x8, sp, #32 ; str x0, [x8]` folds to
  `str x0, [sp, #0x20]` only once `x8` provably dies -- and how the
  producer folds (shift, funnel, extend, `MUL`/`SMULL`, `NEG`, `MVN`)
  admit consumers that write a register other than the producer's:
  `lsl w8, w1, #3 ; add w9, w2, w8` folds to
  `add w9, w2, w1, lsl #3` under the same proof.
  The single-bit and CSET branch folds additionally require the folded
  branch's taken edge to land inside that proven-clean span -- a
  general-purpose register, unlike NZCV, is routinely live into a
  branch target, so no block-locality assumption is made for it.
* **MOV-chain folds verify the constant dies.** Folds that absorb a
  materialized constant -- `MUL`/`MNEG`/`UDIV` by a constant, `MOV` +
  `ADD`/`AND`/`ORR`/`EOR`/`CCMP`/`FMOV`, `MOV #0`, the register-offset
  and MOVI-zeroing folds -- report only once the consumer's own
  overwrite or the forward scan proves the constant register dead. The
  consumer rewrite itself stays valid regardless.
* **Flag liveness uses a bounded forward scan.** The branch- and
  flag-folding checks drop a `CMP`/`TST` only after a bounded scan of the
  fall-through path confirms that no later instruction reads N/C/V before
  they are overwritten. Every NZCV reader is recognized -- the integer
  conditionals (`B.cond`, `CSEL`/`CSINC`/..., `CCMP`/`CCMN`, `ADC`/`SBC`)
  and the floating-point ones (`FCSEL`, `FCCMP`/`FCCMPE`) -- and any
  branch off the path whose destination the scan cannot see -- an
  unconditional `B`, or a conditional `CBZ`/`CBNZ`/`TBZ`/`TBNZ` (which do
  not themselves touch NZCV but whose taken target may still observe it)
  -- ends it conservatively. The scan does not follow the folded
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
the rewrite saves -- in [analyses.md](analyses.md). Candidate checks
not yet implemented live in [TODO.md](TODO.md).

| Pattern | Rewrite |
| --- | --- |
| [`movz`/`movn` + `movk` (over-long constant)](analyses.md#suboptimal-movzmovk-sequence) | bitmask-immediate `mov`, or minimal `movz`/`movn` + `movk` chain |
| [`lsl`/`lsr`/`asr`/`ror` + `add`/`sub`/`and`/`orr`/`eor`](analyses.md#shift-foldable-into-shifted-register-form) | `add Rd, Rn, Rm, <shift> #n` |
| [`lsl`/`lsr` + shifted `orr`/`eor`/`add` (funnel/rotate)](analyses.md#funnel-shift-foldable-into-extr-or-ror) | `extr Rd, Rhi, Rlo, #lsb` (or `ror` when both halves match) |
| [`sxtw`/`uxtb`/`sxtb` + `add`/`sub`](analyses.md#extend-foldable-into-shiftedextended-register-form) | `add Rd, Rn, Wm, sxtw` |
| [`cmp`/`cmn`/`tst` zero-test + `b.eq`/`b.ne` (`b.hi`/`b.ls` after `cmp`)](analyses.md#compare-zero-branch-foldable-into-cbzcbnz) | `cbz`/`cbnz` |
| [`cmp`/`cmn`/`tst` zero-test + `b.lt`/`b.ge`/`b.mi`/`b.pl`](analyses.md#compare-zero-signed-branch-foldable-into-tbztbnz) | `tbnz`/`tbz Rn, #(msb)` |
| [`tst #(1<<k)` + `b.eq`/`b.ne`](analyses.md#tst-single-bit--beqne-foldable-into-tbztbnz) | `tbz`/`tbnz Rn, #k` |
| [`tst #(1<<k)` + `cset`/`csetm`](analyses.md#tst-single-bit--csetcsetm-foldable-into-ubfxsbfx) | `ubfx`/`sbfx Rd, Rn, #k, #1` |
| [single-bit `and`/`ubfx`/`lsr #31` + `cbz`/`cbnz`](analyses.md#single-bit-test--cbzcbnz-foldable-into-tbztbnz) | `tbz`/`tbnz Rs, #k` |
| [`cset` + `cbz`/`cbnz`](analyses.md#cset--cbzcbnz-foldable-into-bcond) | `b.<cond>` / `b.<inverse cond>` |
| [`cset` + `eor #1`](analyses.md#cset--cbzcbnz-foldable-into-bcond) | `cset <inverse cond>` |
| [`cset` + `neg`](analyses.md#cset--cbzcbnz-foldable-into-bcond) | `csetm` |
| [`lsl` + `lsr`/`asr`](analyses.md#bitfield-op-via-two-shifts-foldable-into-ubfxsbfx-or-ubfizsbfiz) | `ubfx`/`sbfx`/`ubfiz`/`sbfiz` |
| [`lsr` + `and #mask`](analyses.md#shift-and-mask-bitfield-extraction-foldable-into-ubfx) | `ubfx` |
| [`and #mask` + `lsr`](analyses.md#mask-and-shift-bitfield-extraction-foldable-into-ubfx) | `ubfx` |
| [`and #mask`/`uxtb`/`uxth`/`uxtw`/`mov` + `lsl` (or `lsr` + `lsl`)](analyses.md#mask-and-shift-left-foldable-into-ubfiz-or-shift-round-trip-into-a-clearing-and) | `ubfiz` (or clearing `and`) |
| [zeroing producer + `uxtb`/`uxth`/`uxtw`/`and`](analyses.md#redundant-zero-extension-after-a-producer-that-already-zeroed-those-bits) | drop the zero-extension |
| [`mov xd, xd`](analyses.md#mov-xd-xd-is-a-literal-no-op) | remove (architectural no-op) |
| [sign-extending producer + `sxtb`/`sxth`/`sxtw`](analyses.md#redundant-sign-extension-after-a-producer-that-already-replicated-the-sign) | drop the sign-extension |
| [`and`/`orr`/`eor`/`sub`/`bic`/`orn`/`eon` with `Rs, Rs`](analyses.md#self-op-identities-andorreorsubbicorneon-rd-rs-rs) | `mov` / zero / all-ones |
| [`ldr`+`ldr` / `str`+`str` (consecutive)](analyses.md#adjacent-ldrstr-foldable-into-ldpstp) | `ldp`/`stp` (integer or FP/SIMD, and `ldpsw`) |
| [`str wzr`+`str wzr` (consecutive zero stores)](analyses.md#adjacent-zero-stores-foldable-into-str-xzr) | `str`/`stur xzr` |
| [`stp wzr, wzr` (W-form)](analyses.md#stp-wzr-wzr-foldable-into-str-xzr) | `str`/`stur xzr` |
| [`movi #0` + vector `cmeq`/`cmge`/`cmgt` (or FP `fcm*`)](analyses.md#zeroing-movi-then-vector-compare-foldable-to-compare-with-zero) | `cmeq`/`cmge`/`cmgt`/`cmle`/`cmlt Vd, X, #0` (drop the `movi`) |
| [`and` + `and`/`ubfiz` + `orr` (clear/isolate/merge)](analyses.md#bfxil-and-bfi-bitfield-insert-synthesis) | `bfxil`/`bfi` |
| [`csel Rd, Rn, Rn, cond`](analyses.md#csel-same-operand-identity-csel-rd-rn-rn-cond) | `mov Rd, Rn` |
| [`fcsel Vd, Vn, Vn, cond`](analyses.md#fcsel-same-operand-identity-fcsel-vd-vn-vn-cond) | `fmov Vd, Vn` |
| [`add`/`sub Rd, Rn, #0`](analyses.md#addsub-0-is-redundant) | `mov Rd, Rn`, or remove |
| [`adds`/`subs`/`ands` + `cmp #0` + `b.eq`/`b.ne`](analyses.md#redundant-zero-cmptst-after-a-flag-setting-alu) | drop the redundant `cmp`/`tst` |
| [`add`/`sub`/`and`/`bic` + `cmp #0` + `b.eq`/`b.ne`](analyses.md#addsubandbic--zero-cmp-foldable-to-s-variant) | `adds`/`subs`/`ands`/`bics` (drop the `cmp`/`tst`) |
| [`sub` + `cmp` / `add` + `cmn` of the same operands (either order)](analyses.md#sub--cmp-of-identical-operands-foldable-to-subs) | `subs`/`adds` (flag-exact; drop the compare) |
| [`subs`/`adds` + `cmp`/`cmn` of its own operands](analyses.md#subsadds--cmpcmn-of-identical-operands-redundant-compare) | drop the compare (flags already set) |
| [`cmp #0` + `cset`/`csetm` of `lt`/`mi`](analyses.md#compare-zero-sign-csetcsetm-foldable-into-lsrasr) | `lsr`/`asr Rd, Rn, #(msb)` (the sign bit; drop the compare) |
| [`mov #2^N` + `mul`](analyses.md#mul-by-constant-foldable-to-shiftadd) | `lsl`, or `add Rd, Ra, Ra, lsl #N` |
| [`mov #C` + `mneg`](analyses.md#mneg-by-constant-foldable-to-negsub) | `neg`, or shifted `neg`/`sub` |
| [`mov #2^N` + `madd`/`msub`](analyses.md#mov--maddmsub-foldable-to-shifted-addsub) | `add`/`sub Rd, Ra, Rn, lsl #N` |
| [`mov #2^N` + `udiv`](analyses.md#udiv-by-constant-foldable-to-shift) | `lsr` |
| [`mov #2^N` + `udiv` + `msub` (remainder)](analyses.md#remainder-by-power-of-two-foldable-to-and) | `and Rd, Rn, #(2^N-1)` |
| [`mov #C` + `add`/`sub`](analyses.md#mov--addsub-foldable-to-immediate-form) | `add`/`sub Rd, Rn, #C` (sign-crossed `add`↔`sub`, `cmp`↔`cmn` for `#-C`) |
| [`mov #C` + `and`/`orr`/`eor`/`ands` or `bic`/`orn`/`eon`/`bics`](analyses.md#mov--andorreorands-or-bicorneonbics-foldable-to-bitmask-immediate) | `and`/`orr`/`eor`/`ands Rd, Rn, #C` (`#~C` for the inverting forms) |
| [`mov #C` + `ccmp`/`ccmn`](analyses.md#mov--ccmpccmn-foldable-to-immediate-form) | `ccmp`/`ccmn Rn, #C, #nzcv, cond` (sign-crossed for `#-C`) |
| [`mov #1` + `csel`](analyses.md#mov-1--csel-foldable-to-csinccset) | `csinc Rd, Rn, wzr, cc` (`cset` when the other operand is ZR) |
| [`mov #-1` + `csel`](analyses.md#mov-1--csel-foldable-to-csinccset) | `csinv Rd, Rn, wzr, cc` (`csetm` when the other operand is ZR) |
| [`mov #C` + `lsl`/`lsr`/`asr`/`ror` (register amount)](analyses.md#mov--variable-shift-foldable-to-immediate-shift) | immediate-form shift, amount `C mod 32`/`64` |
| [`mov #bits`/`#C` + `fmov`/`scvtf`/`ucvtf` from GPR](analyses.md#mov--fmovscvtfucvtf-foldable-to-fmov-immediate) | `fmov Sd`/`Dd, #imm` |
| [`fmov`/`scvtf`/`dup` of `wzr`/`xzr` (or `mov #0` + transfer)](analyses.md#fpvector-zeroing-via-gpr-foldable-to-movi) | `movi dN, #0` / `movi vN.T, #0` |
| [`sxtw`/`mov w, w` + `scvtf`/`ucvtf Xn`](analyses.md#widening-extend--scvtfucvtf-foldable-to-w-form-conversion) | `scvtf`/`ucvtf` of `Wn` |
| [`ldr w8` + `scvtf`/`ucvtf` from GPR](analyses.md#load--scvtfucvtf-via-gpr-foldable-to-fp-load--convert) | `ldr s0` + FP-side convert (no cross-file transfer) |
| [`ldr`/`ldrsw` (literal) of an encodable constant](analyses.md#ldr-literal-foldable-to-movfmov-immediate) | `mov #imm` / `fmov #imm8` / `movi`+`mvni` for Q (no memory access) |
| [`adr` + `ldr [x8]`/`br x16`](analyses.md#adr--single-use-of-its-target-foldable-to-the-direct-form) | `ldr Rt, <literal>` / `b L` |
| [`cmp` + `csel` (max/min shape)](analyses.md#cssc-synthesis-feature-gated--m-cssc) | `smax`/`smin`/`umax`/`umin` (`-m cssc`) |
| [`cmp #0` + `cneg`](analyses.md#cssc-synthesis-feature-gated--m-cssc) | `abs` (`-m cssc`) |
| [`rbit` + `clz`](analyses.md#cssc-synthesis-feature-gated--m-cssc) | `ctz` (`-m cssc`) |
| [NEON popcount round trip](analyses.md#cssc-synthesis-feature-gated--m-cssc) | `cnt Xd, Xn` (`-m cssc`) |
| [`fmul` + in-place `fneg`](analyses.md#fmul--fneg-foldable-to-fnmul) | `fnmul` (bit-exact in every rounding mode) |
| [`mov #0` + `str`/`add`/`and`/`csel`/`ccmp` use](analyses.md#mov-0--use-foldable-to-zr) | use `wzr`/`xzr` |
| [`mov #C` + `ldr`/`str [xn, xc]`](analyses.md#mov--register-offset-ldrstr-foldable-to-immediate-offset) | `ldr`/`str [xn, #C]` (or `ldur`/`stur`) |
| [`mul` + `add`/`sub`](analyses.md#mul--addsub-foldable-to-maddmsub) | `madd`/`msub` (or `mneg`) |
| [`smull`/`umull` + `add`/`sub`](analyses.md#smullumull--addsub-foldable-to-smaddlumaddl) | `smaddl`/`umaddl`/`smsubl`/`umsubl` |
| [`neg` + `add`/`sub`](analyses.md#neg--addsub-foldable-to-subadd) | `sub`/`add` |
| [`neg` + `csel`](analyses.md#neg--addsub-foldable-to-subadd) | `csneg` (inverted cond for the then slot) |
| [`mvn` + `csel`](analyses.md#mvn--andorreor-foldable-to-bicorneon) | `csinv` (inverted cond for the then slot) |
| [`add #1` + `csel`](analyses.md#add-1--csel-foldable-to-csinc) | `csinc` (inverted cond for the then slot) |
| [`mvn` + `and`/`orr`/`eor`/`ands`](analyses.md#mvn--andorreor-foldable-to-bicorneon) | `bic`/`orn`/`eon`/`bics` |
| [`add` + `ldr`/`str [xt]`](analyses.md#add--ldr-foldable-to-register-offset-ldr) | `ldr`/`str [xn, xm{, lsl #s}]` |
| [`sxtw` + `ldr`/`str [xn, xt]`](analyses.md#sxtw--register-offset-ldr-foldable-into-the-load) | `ldr`/`str [xn, ws, sxtw {#s}]` |
| [`ldrb`/`ldrh`/`ldr` (or `ldrsb`/`ldrsh Wt`) + `sxtb`/`sxth`/`sxtw`](analyses.md#load--sign-extend-foldable-to-ldrsbldrshldrsw) | `ldrsb`/`ldrsh`/`ldrsw` (`Xt` for the re-widened sign loads) |
| [`add #a` + `ldr`/`str [xt]` (incl. `mov xt, sp`)](analyses.md#add--ldr-foldable-to-immediate-offset-ldr) | `ldr`/`str [xn, #a]` / `ldr [sp]` |
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
        handle, code, code_len, base_addr, /*verbose=*/true, summary,
        /*features=*/0);   // or ARMLINT_FEATURE_CSSC etc.
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
./armlint -m cssc /bin/ls   # also suggest CSSC instructions
```

`-m <feature>` enables checks whose rewrites use ISA-extension
instructions the target must support; `cssc` (Armv8.9/9.4 Common
Short Sequence Compression: `smax`/`smin`/`umax`/`umin`, `abs`,
`ctz`) is the first.

By default armlint prints only a summary: the opportunities grouped by
type and sorted by prevalence, so it is clear which to look at first,
followed by a total and the number of instructions scanned. A large
binary can have hundreds of thousands of opportunities, so the
per-opportunity detail is suppressed unless requested:

```console
$ ./armlint /bin/ls
Optimization opportunities by type:
      38  ADD + LDR foldable to immediate-offset LDR

38 optimization opportunities in 4153 instructions
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

* [Arm A-profile A64 Instruction Set Architecture](https://developer.arm.com/documentation/ddi0602/latest/) - per-instruction reference, including alias conditions
* [Arm Cortex-A optimization guides](https://developer.arm.com/documentation) - per-microarchitecture tuning notes
* [Apple Silicon CPU Optimization Guide](https://developer.apple.com/documentation/apple-silicon/cpu-optimization-guide) - Apple M-series tuning notes
* [Encoding of immediate values on AArch64](https://dinfuehr.com/blog/encoding-of-immediate-values-on-aarch64/) - the bitmask-immediate scheme explained
* [Capstone disassembly framework](https://www.capstone-engine.org/) - library to parse instructions
* [x86lint](https://github.com/gaul/x86lint) - x86-64 equivalent of armlint

## License

Copyright (C) 2026 Andrew Gaul

Licensed under the Apache License, Version 2.0
