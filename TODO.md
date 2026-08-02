# TODO: candidate analyses

The research-backed backlog of checks considered but not yet
implemented. Implemented checks are documented in
[analyses.md](analyses.md); patterns that will never be implemented
(with the soundness argument against each) are in its
[rejected-folds appendix](analyses.md#appendix-folds-rejected-for-soundness).
Sources: the Arm Software Optimization Guides (Neoverse N1/V2), the
Apple Silicon CPU Optimization Guide, and gaps noted while building
the existing checks.

## Flag-fold leftovers

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| zero-CMP→S-variant: `b.mi`/`b.pl` consumers | same | N agrees exactly after a zero compare (V = 0); v1 of the check consumes EQ/NE only |
| zero-CMP→S-variant: `adc`/`sbc` producers | `adcs`/`sbcs` | Excluded in v1: they read the carry the deleted compare set; needs a separate flag argument |
| sign CSET/CSETM: GE/PL complements | `lsr`+`eor #1` / `mvn`+`asr` | 2-for-2, no size win (frees NZCV only); v1 of the sign-shift fold flags LT/MI |
| sign CSET/CSETM: `tst Rn, Rn` / `cmn Rn, #0` producers | `lsr`/`asr` | Same N/V pinning as `cmp Rn, #0`; rarer zero-test spellings |
| `add x0, x0, #a ; add x0, x0, #b` | one `add`/`sub` | Coalesce adjacent same-register immediate adjustments; skip the canonical imm12 + imm12<<12 pair the assembler splits. 2026-07 sweep: 15,350 adjacent dep pairs of this shape in librustc_driver (313 rustup, 12 go), many with a changed destination (`add x8, x8, #0xec0 ; add x0, x8, #0x28`) -- generalize via the dead-producer scan |

## Branches and dead code

The largest untouched family; none of these need liveness machinery.

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| `b.cond`/`cbz`/`tbz` `+8` over `b L` | `b.!cond L` | Implemented in 119c22e and reverted: sound (103/103 byte-verified), but clang/Mach-O emits the pair for conditional tail calls -- Mach-O has no conditional-branch relocation, so the spelling is forced and unfixable by recompiling. Issue #7 has the /bin/bash census (12/12 tail calls) and reinstatement options: opt-in/informational class, or suppress cross-symbol transfers via LC_FUNCTION_STARTS and keep only intra-function pairs |
| constant-condition `b.cond` after zero-test | `b` or delete | `cmp Rn, #0` pins C = 1, V = 0, so `b.hs` is always-taken and `b.lo`/`b.vs` never; `cbz wzr` always; `b.al` always; `cmp x, x` pins Z |
| side-effect-free write to ZR destination | delete | Non-S ALU, MADD family, CSEL family, bitfield ops with Rd = 31; loads excluded (memory side effects) |
| pure write immediately clobbered | delete the first | Same destination written twice with no intervening read; covers duplicated instructions |

## One-for-one canonicalizations

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| `and xd, xn, #0xffffffff` / `ubfx xd, xn, #0, #32` | `mov wd, wn` | Zero-latency rename on Neoverse; neutral elsewhere |
| ZR-operand ALU spellings (`orr wd, wn, wzr`, `add wd, wn, wzr`, `mul xd, xn, xzr`, `eor wd, wn, wzr`, ...) | `mov` / `neg` / `mvn` / `mov #0` | The docs' "further simplification left to the reader" after the MOV #0 → ZR findings; enumerate the alias table |
| `lsl #0`, `extr Rd, Rn, Rn, #0`, full-width `ubfx` | `mov` | Degenerate-immediate spellings of a register copy |
| `umov wd, vn.s[0]` | `fmov wd, sn` | Apple guide §4.5.2 (cheaper port usage); value-identical |

## SIMD & FP

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| `dup vT, vN.e[i]` + `fmul`/`fmla`/`mul`/`mla` | by-element form | Deletes the DUP; by-element cost parity measured on Firestorm; H-lane forms need Vm <= 15 |
| `eor`/`sub vd, vn, vn` | `movi vd.2d, #0` | Ported-x86 idiom; also `and`/`orr` self → `mov`, `mov vd.16b, vd.16b` = pure no-op |
| `movi`/`mvni` + vector `and`/`orr`/`bic` | the immediate forms | AND folds via the complemented BIC immediate; needs the vector-register scan for the dead constant |
| non-zero `dup` from a MOV chain | `movi` expanded imm | `q_movi_spelling` already classifies the patterns; wire it to a DUP-from-GPR producer |
| `fmov s1, w0 ; fmov w2, s1` round trips | direct `mov w2, w0` | Both directions; defers on the middle register (FP scan for one direction, GPR for the other) |
| `fcvtzs w8, s0 ; str w8, [xn]` | `fcvtzs s1, s0 ; str s1` | Store twin of the load+convert fold; needs a scratch FP register choice plus the FP scan (now available) |
| MOVI + vector-compare fresh destination | compare with #0 | The documented v1 limitation of the existing check; the FP scan now unblocks it |

## Binary-aware

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| `adrp` + `add` → `adr` (target within ±1MB) | shorter form | Actionability caveat: linker-resolved relocations make this a relink-level suggestion; likely opt-in. 2026-07 sweep: the most frequent dependent pair in every corpus -- 59.7k go, 42.5k rustup, 642k librustc_driver |
| `adrp` + `ldr Sd/Dd/Qd` from a literal pool | `fmov #imm8` / `movi` when the pointed-to constant encodes | 24.3k `adrp`+`ldr d` pairs in librustc_driver; needs reading the target section's bytes at the resolved address -- same relink caveat and infrastructure as the rows above |
| BR fold for general registers (`adr x8, L ; br x8`) | `b L` | v1 folds x16/x17 only (veneer-scratch ABI argument); the general case needs liveness at the TARGET, a new scan mode |
| mov-wide address chains → `adr`/`adrp`+`add`; `mov`+`blr` → `bl` | shorter form | Same actionability caveat as adrp+add |

## Feature-gated (`-m` knob exists)

| Item | Notes |
| --- | --- |
| FP16 lift | `-m fp16`: relax the `type <= 1` gates in the fmov/fcsel/fmul/cvtf checks |
| LSE leftovers | `-m lse` folds the fetch-op, exchange, and converging CAS retry loops; remaining: diverging-exit CAS (LLVM's CLREX tail -- needs a second suggested branch and a two-path death argument), immediate-comparand and CBNZ-as-compare zero-expected shapes (zero of each in gh), byte/half CAS via the extended-register compare (`cmp w8, w1, uxtb`), cmp+csel MIN/MAX loops (`ldsmax` family), ST-forms for unused results, bitmask-immediate logic operands |
| PAuth epilogue leftovers | v1 of `-m pauth` folds `autiasp`/`autibsp` + `ret` only; the general-encoding `autia x30, sp` producer and the one-shot `autiasp` + `br x30` → `retaa` (its first step now lands via the `br x30` → `ret` fold) remain |

## Microarch/informational (candidates for the `-a` audit class)

| Item | Notes |
| --- | --- |
| Split fusion pairs (cmp+b.cond, aese+aesmc same-dest, adrp+add) | Informational: "these should be adjacent"; per-core tables from the SOGs |
| Render `mov xd, #0` (not `mov xd, xzr`) and `movi v0.2d, #0` (not `movi d0, #0`) | Apple eliminates only those spellings at rename; rendering tweaks to existing checks |
| Loaded value as base not offset (`[x9, x8]` → `[x8, x9]` when x8 was just loaded) | Apple guide §4.6.7: 1 cycle of address-generation latency |
| PAC audit v2: non-SP LR stores (jmp_buf/context saves), jump-table classification to auto-dismiss benign raw `br`, auto-arm on arm64e slices | v1 (`-a pac`) covers SP-based spills and flags every raw BR/BLR uniformly |
| LDP/STP synthesized through a scratch ADD (`add x27, xN, #big ; ldp x3, x4, [x27]`) → two plain `ldr`/`str` with the offset folded in | Size-neutral 2-for-2 that drops the ADD from the address dependency chain and frees the scratch; gc emits it whenever a pair offset exceeds ±504 or is 8-misaligned (~13k in go), LLVM for big Q-register spill offsets (~9k in librustc_driver); requires the split offsets to encode (scaled imm12, or LDUR/STUR range) |

## Window candidates (2026-07 corpus sweep)

First `pairscan`/`defuse` sweep over macOS Mach-O binaries: `go` 1.26.5
(1.47M insns), `rustup` (1.62M), and `librustc_driver` stable (25.9M).
The defuse distance histograms show d1 dominating every sole-use
producer family, confirming strict adjacency as the right default; the
populations below are the real beyond-adjacency mass.

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| Same-address reload: second `ldr`/`ldrb`/`ldrh` of an untouched `[Rn, #d]` with no store/call/barrier between | reuse the first value (delete the reload, or copy the first destination) | ~18.2k in librustc_driver (d4-7 dominant), ~830 rustup, ~320 go. Signature shape: chained keyword-compare arms clobber the loaded register to materialize the next `ccmp` constant, then reload both fields. Deletion cannot meet the hard soundness bar -- a plain LDR may be a relaxed atomic, so a concurrent writer is architecturally visible -- so this is opt-in/informational class material |
| Zero-CMP → S-variant with a 1-2 instruction gap | as the adjacent fold | go `cmp0\|and`: 72 at d2, 10 at d3 vs 42 at d1 -- gc's non-adjacent tail rivals the adjacent population; same flag-liveness scan, wider match |

## Infrastructure

| Item | Notes |
| --- | --- |
| Multi-slot deferral | The single pending_mz/pending_fp slots drop the earlier finding when two deferrals overlap; false-negative-only, documented in `defer_dead_mov` |
| Target-side liveness | Scan at a known branch target (buffer access exists); unlocks the general-register BR fold |
| Hybrid `mov`/`orr`+`movk` constant chains | Docs-acknowledged deferral in the MOV-chain machinery |
| LDUR / writeback pair coalescing; load+sext at other addressing modes | Docs-acknowledged deferrals of the coalescer and sext folds |
