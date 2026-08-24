# TODO: candidate analyses

The research-backed backlog of checks considered but not yet
implemented. Implemented checks are documented in
[analyses.md](analyses.md); patterns that will never be implemented
(with the soundness argument against each) are in its
[rejected-folds appendix](analyses.md#appendix-folds-rejected-for-soundness).
Sources: the Arm Software Optimization Guides (Neoverse N1/V2), the
Apple Silicon CPU Optimization Guide, and gaps noted while building
the existing checks.

Population figures marked **2026-08 sweep** come from
`tools/shapescan.py` over six macOS Mach-O binaries totalling 28.4M
instructions: OpenSSL 3.6.3 `libcrypto` (561k), `/usr/lib/dyld`
arm64e (162k), `go` 1.26.7 (1.47M), `librustc_driver` stable (26.0M),
`/bin/bash` arm64e (118k) and `/usr/bin/ssh` arm64e (113k).
librustc_driver is 91% of that total, so read the per-binary numbers,
not just the sum. Every encoding mask the sweep uses is verified
against the assembler by `shapescan.py --selftest`, and each non-zero
population below was spot-checked against real disassembly -- both
steps caught mask and modelling errors that had inflated earlier
counts by one to three orders of magnitude.

## Flag-fold leftovers

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| zero-CMP→S-variant: `b.mi`/`b.pl` consumers | same | N agrees exactly after a zero compare (V = 0); v1 of the check consumes EQ/NE only |
| zero-CMP→S-variant: `adc`/`sbc` producers | `adcs`/`sbcs` | Excluded in v1: they read the carry the deleted compare set; needs a separate flag argument |
| sign CSET/CSETM: GE/PL complements | `lsr`+`eor #1` / `mvn`+`asr` | 2-for-2, no size win (frees NZCV only); v1 of the sign-shift fold flags LT/MI |
| sign CSET/CSETM: `tst Rn, Rn` / `cmn Rn, #0` producers | `lsr`/`asr` | Same N/V pinning as `cmp Rn, #0`; rarer zero-test spellings |
| `add x0, x0, #a ; add x0, x0, #b` | one `add`/`sub` | **The strongest remaining candidate.** 2026-08 sweep: 77,681 adjacent dependent pairs; gating on the sum actually encoding (imm12, or a multiple of 4096 for the `lsl #12` form) leaves 47,754, of which **19,845 also kill the temp structurally** -- the consumer overwrites the register it read, so no liveness machinery is needed at all -- and 27,909 need the dead-producer scan. Per binary (structural / scan): librustc_driver 19,778 / 26,337, go 14 / 1,266, dyld 31 / 168, ssh 3 / 36, libcrypto 11 / 85, bash 8 / 17. Sign crossing falls out for free (`sub x8, x29, #0x100 ; add x8, x8, #0x30` -> `sub x8, x29, #0xd0`). Note the compiler's own split of a wide constant emits `lsl #12` **first** (`add x8, x8, #0x1, lsl #12 ; add x8, x8, #0x20`); the sum-encodability gate rejects those without needing a special case. These are interior pointers into stack objects -- 64% of the foldable chains are sp/x29-relative and the second immediate is a field offset (median 16 bytes, 97% under 256) -- so the two constants are born in different compiler phases and never meet a folding peephole: see the mechanism note below |

### Why the add/sub immediate chains exist

The two immediates are born in different compiler phases and never
meet a folding peephole afterwards. The first (`add x8, sp, #0x320`)
is a stack-object address: its offset is not a constant until
`PrologEpilogInserter` assigns the frame layout, which happens after
instruction selection and register allocation. The second
(`add x8, x8, #0x8`) is a field offset from the IR's `getelementptr`,
constant from the start. LLVM's `LocalStackSlotAllocation` deliberately
materializes a frame base register so that later frame references can
be a base-plus-delta pair -- and when a base register ends up with a
single use, the pair collapses to one `add`, but nothing revisits it.

Evidence: 64% of the foldable chains are sp/x29-relative, the second
immediate is a field offset (median 16 bytes, 97% under 256), and in
every instance inspected the result is stored straight into another
stack slot -- an interior pointer being spilled. Reproduced with
clang -O2: interior pointers into a stack array emit exactly
`add x20, sp, #0x8 ; add x0, x20, #0x188`, while a plain
`&local.field`, where both constants are visible at instruction
selection, folds into a single `add`. That contrast is the direct
evidence that it is the late frame-layout path that misses the fold.

This also explains the distribution. rustc's frames are large and full
of interior pointers (enum payloads, iterator and future state, `&mut`
borrows into locals) that get spilled, which is exactly when frame
base registers appear; go, bash and ssh have small frames and yield
14, 8 and 3 chains respectively.

## Branches and dead code

Cheap to implement -- none of these need liveness machinery -- but the
2026-08 sweep found the family is close to empty in real code. Kept
here with measured populations so it is not re-investigated.

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| `b.cond`/`cbz`/`tbz` `+8` over `b L` | `b.!cond L` | Implemented in 119c22e and reverted: sound (103/103 byte-verified), but clang/Mach-O emits the pair for conditional tail calls -- Mach-O has no conditional-branch relocation, so the spelling is forced and unfixable by recompiling. 2026-08 sweep: **2,437** (2,270 librustc_driver, 84 libcrypto, 59 go). Issue #7 has the /bin/bash census (12/12 tail calls) and reinstatement options: opt-in/informational class, or suppress cross-symbol transfers via LC_FUNCTION_STARTS and keep only intra-function pairs (the function-starts/nlist parsing now exists in main.c -- symbolized findings use it -- so the suppression needs only the boundary check) |
| constant-condition `b.cond` after zero-test | `b` or delete | `cmp Rn, #0` pins C = 1, V = 0, so `b.hs` is always-taken and `b.lo`/`b.vs` never; `cbz wzr` always; `b.al` always; `cmp x, x` pins Z. 2026-08 sweep: **13** across 28.4M instructions (all in librustc_driver), counting `b.al`/`b.nv` and ZR-operand `cbz`/`cbnz`/`tbz`/`tbnz` |
| side-effect-free write to ZR destination | delete | Non-S ALU, MADD family, CSEL family, bitfield ops with Rd = 31; loads excluded (memory side effects). 2026-08 sweep: **0** across 28.4M instructions -- compilers do not emit these |
| pure write immediately clobbered | delete the first | Same destination written twice with no intervening read; covers duplicated instructions. 2026-08 sweep: **10** across 28.4M instructions. A first pass reported 6,424 -- all of them BFM aliases (`bfi`/`bfxil`), which merge into their destination and so read it. Any implementation must treat BFM as read-modify-write; `UBFM`/`SBFM` do overwrite |

## One-for-one canonicalizations

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| `and xd, xn, #0xffffffff` / `ubfx xd, xn, #0, #32` | `mov wd, wn` | Zero-latency rename on Neoverse; neutral elsewhere. 2026-08 sweep: **56** |
| ZR-operand ALU spellings (`orr wd, wn, wzr`, `add wd, wn, wzr`, `mul xd, xn, xzr`, `eor wd, wn, wzr`, ...) | `mov` / `neg` / `mvn` / `mov #0` | The docs' "further simplification left to the reader" after the MOV #0 → ZR findings; enumerate the alias table. 2026-08 sweep: **90**, all in librustc_driver |
| `lsl #0`, `extr Rd, Rn, Rn, #0`, full-width `ubfx` | `mov` | Degenerate-immediate spellings of a register copy. 2026-08 sweep: **0** |
| `umov wd, vn.s[0]` | `fmov wd, sn` | Apple guide §4.5.2 (cheaper port usage); value-identical. 2026-08 sweep: **484** (464 libcrypto, 20 go, 0 elsewhere), counting the `.s[0]` and `.d[0]` forms. The cheapest check on this list: one instruction, no liveness argument, no pair state |

## SIMD & FP

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| `dup vT, vN.e[i]` + `fmul`/`fmla`/`mul`/`mla` | by-element form | Deletes the DUP; by-element cost parity measured on Firestorm; H-lane forms need Vm <= 15. 2026-08 sweep: **0** adjacent dependent pairs. Not a mask artifact -- the instructions are there (121 by-element `dup` in librustc_driver, 92 vector `mul` in ssh), the pairs are not |
| `eor`/`sub vd, vn, vn` | `movi vd.2d, #0` | Ported-x86 idiom; also `and`/`orr` self → `mov`, `mov vd.16b, vd.16b` = pure no-op. 2026-08 sweep: **353** (315 libcrypto, 28 go, 10 dyld), counting the `mov vd.16b, vd.16b` no-op with the collapsing ops. Careful: `orr Vd, Vn, Vn` with Rd != Rn IS the canonical vector `MOV` spelling and must not be flagged -- counting it inflated a first pass to 2,158 |
| `movi`/`mvni` + vector `and`/`orr`/`bic` | the immediate forms | AND folds via the complemented BIC immediate; needs the vector-register scan for the dead constant. 2026-08 sweep: **40**. The MOVI mask must pin bits 28..19; a looser one also matches `ushll`/`shll` and reported 1,662 |
| non-zero `dup` from a MOV chain | `movi` expanded imm | `q_movi_spelling` already classifies the patterns; wire it to a DUP-from-GPR producer |
| `fmov s1, w0 ; fmov w2, s1` round trips | direct `mov w2, w0` | Both directions; defers on the middle register (FP scan for one direction, GPR for the other). 2026-08 sweep: **0** adjacent, in either direction -- though the halves are common on their own (45,564 FP-to-GPR `fmov` in librustc_driver), so a windowed match might find some |
| `fcvtzs w8, s0 ; str w8, [xn]` | `fcvtzs s1, s0 ; str s1` | Store twin of the load+convert fold; needs a scratch FP register choice plus the FP scan (now available). 2026-08 sweep: **6** |
| MOVI + vector-compare fresh destination | compare with #0 | The documented v1 limitation of the existing check; the FP scan now unblocks it |

## Binary-aware

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| `adrp` + `add` → `adr` (target within ±1MB) | shorter form | Actionability caveat: linker-resolved relocations make this a relink-level suggestion; likely opt-in. The pair is the most frequent dependent pair in every corpus (2026-07 sweep: 59.7k go, 42.5k rustup, 642k librustc_driver) but **most of those targets are nowhere near ADR's ±1MB reach**. 2026-08 sweep, resolving each target and range-checking it: 43,434 of 753,648 pairs qualify (5.8%) -- 18,138 of 652,138 in librustc_driver (2.8%), 4,992 of 59,943 in go (8.3%), and essentially all of them in the small binaries (dyld 5,164, ssh 7,937, bash 4,966). Still the largest single population here, but a 17x smaller prize than the raw pair count suggests |
| `adrp` + `ldr Sd/Dd/Qd` from a literal pool | `fmov #imm8` / `movi` when the pointed-to constant encodes | 24.3k `adrp`+`ldr d` pairs in librustc_driver; needs reading the target section's bytes at the resolved address -- same relink caveat and infrastructure as the rows above |
| BR fold for general registers (`adr x8, L ; br x8`) | `b L` | v1 folds x16/x17 only (veneer-scratch ABI argument); the general case needs liveness at the TARGET, a new scan mode |
| mov-wide address chains → `adr`/`adrp`+`add`; `mov`+`blr` → `bl` | shorter form | Same actionability caveat as adrp+add |

## Feature-gated (`-m` knob exists)

| Item | Notes |
| --- | --- |
| FP16 lift | `-m fp16`: relax the `type <= 1` gates in the fmov/fcsel/fmul/cvtf checks |
| LSE leftovers | `-m lse` folds the fetch-op, exchange, and converging CAS retry loops; remaining: diverging-exit CAS (LLVM's CLREX tail -- needs a second suggested branch and a two-path death argument), immediate-comparand and CBNZ-as-compare zero-expected shapes (zero of each in gh), byte/half CAS via the extended-register compare (`cmp w8, w1, uxtb`), cmp+csel MIN/MAX loops (`ldsmax` family), ST-forms for unused results, bitmask-immediate logic operands |
| PAuth epilogue leftovers | v1 of `-m pauth` folds `autiasp`/`autibsp` + `ret` only; the general-encoding `autia x30, sp` producer and the one-shot `autiasp` + `br x30` → `retaa` (its first step now lands via the `br x30` → `ret` fold) remain |
| CMPBR leftovers | `-m cmpbr` folds `cmp` + `b.cond` into `CB<cc>`. Remaining: `CBB<cc>`/`CBH<cc>`, whose byte/halfword compare only pays by also deleting an explicit `uxtb`/`uxth`/`sxtb`/`sxth` ahead of the compare -- a 3-for-1 or 4-for-1 fold needing the extend's own liveness argument (LLVM does not emit them either, llvm#135617). Also open: non-adjacent pairs, and a comparand materialized by a MOV chain rather than written as an immediate |
| SHA3 leftovers | `-m sha3` folds the two-instruction shapes, `eor`+`eor` -> `EOR3` and `bic`+`eor` -> `BCAX`. Remaining: `XAR` ((Vn EOR Vm) rotated right per 64-bit lane) and `RAX1` (Vn EOR ROL(Vm, 1)), which fold three or more instructions because a NEON lane rotate is itself a shift pair (`ushr`+`sli`, or `shl`+`usra`) -- libcrypto has 58 adjacent `eor`+`ext`, 49 `eor`+`shl` and 31 `eor`+`ushr` pairs to mine. Also open: the fresh-destination deferrals (35 of libcrypto's 106 candidate pairs), which need the vector-liveness whitelist widened past loads and scalar FP |

## Microarch/informational (candidates for the `-a` audit class)

| Item | Notes |
| --- | --- |
| Split fusion pairs (cmp+b.cond, aese+aesmc same-dest, adrp+add) | Informational: "these should be adjacent"; per-core tables from the SOGs |
| Render `mov xd, #0` (not `mov xd, xzr`) and `movi v0.2d, #0` (not `movi d0, #0`) | Apple eliminates only those spellings at rename; rendering tweaks to existing checks |
| Loaded value as base not offset (`[x9, x8]` → `[x8, x9]` when x8 was just loaded) | Apple guide §4.6.7: 1 cycle of address-generation latency |
| PAC audit v2: non-SP LR stores (jmp_buf/context saves; rare -- 0 in bash/dyld, lives in libsystem_c), the compact `ldrb`-scaled jump-table variant (`adr` + `ldrb` + `add …, lsl #2` + `br`; seen in Homebrew arm64 libcapstone, unmatched by the ldrsw classifier) | Auto-arm on arm64e slices: **done** for both `-a pac` and `-m pauth`. Jump-table classification for the dominant `ldrsw` idiom: **done** (jt_advance in check_pac_raw_indirect empties the arm64e raw-BR worklist). Zero-discriminator forward edges: **done** (check_pac_zero_disc_indirect flags `braaz`/`blraaz`/`brabz`/`blrabz`; census ssh 109, sshd 39, zsh 443, ls 2, bash 85, dyld 169) |
| LDP/STP synthesized through a scratch ADD (`add x27, xN, #big ; ldp x3, x4, [x27]`) → two plain `ldr`/`str` with the offset folded in | Size-neutral 2-for-2 that drops the ADD from the address dependency chain and frees the scratch; gc emits it whenever a pair offset exceeds ±504 or is 8-misaligned, LLVM for big Q-register spill offsets; requires the split offsets to encode (scaled imm12, or LDUR/STUR range). 2026-08 sweep: **16,838**, overwhelmingly a Go phenomenon -- 13,587 in go against 3,176 in librustc_driver and under 40 in every other binary, and almost all of them gc's fixed `x27` scratch (`add x27, x27, #0xa80 ; ldp x3, x4, [x27]`). The ADD is in place, so the fold needs the dead-producer scan to prove the scratch's new value unused |

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
| Target-side liveness | NZCV at a branch target is **done**: `nzcv_dead_at_target` walks the scanned buffer for the CMPBR fold, which cannot make the block-locality assumption the other branch folds make. The register-side twin (scan for a GPR at a known target) is still open and unlocks the general-register BR fold. The NZCV scan refuses rather than chases -- a `cbz`/`b` at the target ends it, which is 10 of the 16 pairs it rejects in /bin/ls |
| Hybrid `mov`/`orr`+`movk` constant chains | Docs-acknowledged deferral in the MOV-chain machinery |
| LDUR / writeback pair coalescing; load+sext at other addressing modes | Docs-acknowledged deferrals of the coalescer and sext folds |
