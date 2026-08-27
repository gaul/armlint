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

`--selftest` verifies masks in both directions. The collision half
catches a mask that is too loose, which fails loudly by reporting an
absurd number. The recall half catches a mask that is too narrow,
which fails silently: it reports a plausible small number, and nothing
looks wrong. Every population below is therefore an undercount until
some reference instruction proves each spelling of its shape is
matched -- both register widths, scaled and unscaled addressing,
integer and SIMD&FP register classes. The recall half was added after
the LDUR/STUR blindness in the LDP/STP coalescer (a77f2fa) showed the
same class of error could sit in the scanners; it immediately found
six such masks here, one of which had been undercounting by 3.9x.

Neither half catches a mask that leaks into **unallocated** encoding
space. The collision half asks whether a mask matches some *other
reference instruction*, and an unallocated word is in nobody's
reference set, so the mask passes and the scanner reports data as
code. That is what put six phantom sites into the dead-write row
below. Two habits follow: pin the bits that separate a class from the
unallocated slots inside it, not just from its neighbours, and prefer
a `MASKS` registry entry to an inline mask -- `--selftest` only ever
sees the registry, so anything built inline (as `_pure_writer`'s set
was) is unverified by construction.

Where a candidate needed operand conditions finer than one shape mask
can carry, it has its own scanner held to the same discipline:
`tools/addpairscan.py` splits the ADD + LDP/STP family into the half
that folds 2-for-1 and the half whose offset overflows the pair's
imm7, applies each half's own encodability condition, reports which
register the split would free, and carries its own `--selftest`.

## Coverage gaps in shipped checks

The `--selftest` discipline above proves a *scanner's* masks cover
every spelling of their shape. It says nothing about which spellings
and register classes a *check's* decoder chain accepts, and that is a
separate hole with the same failure mode: a check reports a plausible
number off a fraction of its own population, and nothing looks wrong.
Two of the three rows below were found only by measuring a shipped
check against the shape it claims to cover, the same way a77f2fa's
LDUR blindness was.

The first two were measured by lowering `check_add_ldr_str_multi_fold`'s
minimum-uses threshold from 2 to 1 and re-running the corpus, which
reuses that check's real deadness proof and side-entry gate instead of
approximating them. That yields **10,493** single-use sites against the
**8,428** `check_add_ldr_imm_offset` reports, and the residue splits
cleanly by what the older check cannot see:

```
int      adjacent   5529      covered
fp-pair  adjacent   2340      covered (its pair arm reads both files)
int-pair adjacent    226      covered
fp       adjacent   1782  <-  single SIMD&FP access: integer-only
gapped   (all)       616  <-  strict adjacency refuses these
```

Both arrows are now shipped, and the two predictions behaved
differently in a way worth keeping. The gapped row came in at exactly
616 because it was measured through the same check that now reports
it -- same window, same deadness proof, same gate -- so the model and
the implementation were the same code. The SIMD&FP row came in at
1,830 against 1,782 because it was measured through that check but
implemented in the other one, whose strict adjacency needs no
un-clobbered-source condition where a window does. A prediction is
exact only when it is made by the machinery that will realize it.

The third row was measured a third way -- by counting the encoding
shape in the corpus, with no deadness proof applied -- and its 225 was
never a prediction of findings, only of candidates. It shipped as 18,
which is right: its already-covered twin realizes 199 of 3,235, and
the two rates agree to within two points. All three rows are now
closed. What the class had in common is worth keeping: every one was a
check reporting a plausible number off a fraction of its own
population, with nothing in the output to say so, and every one was
found by measuring a shipped check against the shape it claims rather
than by reading it.

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| ~~Single SIMD&FP access under `check_add_ldr_imm_offset`~~ | ~~as the integer fold~~ | **Done, 2026-08-27: +1,830 findings** (predicted 1,782; the overshoot is this check's adjacency, which needs no un-clobbered-source condition where the multi-use fold's window does). The same bug as the LDUR blindness, one register class over: the check decoded both *spellings* of its consumer since 986f735, but only the integer *class*. Its own pair arm already read both files, which is what made the single-access omission an oversight rather than a decision. Cost 18 ADD + LDP findings to the single deferral slot -- see the multi-slot row above |
| ~~Non-adjacent single use of an ADD base~~ | ~~as the adjacent fold~~ | **Done, 2026-08-27: +616 findings**, the predicted count exactly (270 integer single, 224 SIMD&FP pair, 118 SIMD&FP single, 4 integer pair) and no other check's count moved by one. `check_add_ldr_imm_offset` clears its pending slot on any non-matching instruction, so it holds the sole use sitting DIRECTLY after the ADD and nothing else; `check_add_ldr_str_multi_fold` already scanned a window, and relaxing its minimum from two uses to one -- refusing only the adjacent sole use, which is the other check's -- was the whole change. **553 of the 616 are gapped by exactly one instruction**, and in 412 of those the gap is itself a load or store: a scheduler covering the address latency with independent work. Splitting by position rather than by outcome leaves a narrow false negative -- an adjacent sole use whose deferral the other check loses to an evicted slot is not picked up here as a second chance -- which is the right trade against reporting a site twice |
| ~~`mov #0` + unscaled store under `check_mov_zero_to_xzr`~~ | ~~`stur xzr, [...]`~~ | **Done, 2026-08-27: +18 findings** (817 -> 835), all in librustc_driver. (Later corrected to +11 on a base of 525 when `insn_writes_no_gpr` stopped a compare counting as a kill; the ratio below is unaffected.) The 225 figure was a candidate pool, not a prediction: the store arm realizes 199 findings off the 3,235 unsigned-offset candidates it already saw, 6.2%, and the new spelling realizes 18 off 225, 8.0% -- the same rate, which is the point. What was missing was the spelling, not a different deadness story, and what still gates both is the forward liveness scan proving the zero register dead. The dominant shape is LLVM clearing trailing bytes off a frame pointer (`movz w14, #0 ; sturb w14, [x12, #-3]`), where a negative displacement leaves the assembler no choice; in librustc_driver the unrolled clear emits `sturb` at -3, -2, -1 then `strb` at 0, so the check had been reporting the last of four |

## Flag-fold leftovers

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| zero-CMP→S-variant: `b.mi`/`b.pl` consumers | same | N agrees exactly after a zero compare (V = 0); v1 of the check consumes EQ/NE only |
| zero-CMP→S-variant: `adc`/`sbc` producers | `adcs`/`sbcs` | Excluded in v1: they read the carry the deleted compare set; needs a separate flag argument |
| sign CSET/CSETM: GE/PL complements | `lsr`+`eor #1` / `mvn`+`asr` | 2-for-2, no size win (frees NZCV only); v1 of the sign-shift fold flags LT/MI |
| sign CSET/CSETM: `tst Rn, Rn` / `cmn Rn, #0` producers | `lsr`/`asr` | Same N/V pinning as `cmp Rn, #0`; rarer zero-test spellings |
| Dead flag writes: the call/return arms | delete the compare | The [dead-compare check](analyses.md#compare-whose-flags-are-overwritten-unread) proves deadness only by a later NZCV overwrite. Two more stoppers are sound for compiler-generated code and refused today because the argument is about a callee rather than about code in front of the scanner: a `bl` and a `ret`, past which the PCS leaves NZCV undefined. Survey of the 28.5M corpus: **77** compares die at a call and **29** at a return, against the 175 the overwrite arm proved there (armlint reports 315, having no need of the survey's side-entry caution). Reinstating them needs either a whitelist of AAPCS-compiled regions or an argument that hand-written assembly cannot reach the site -- `_OUTLINED_FUNCTION_*` tails are the dominant `ret` shape and are safe by construction (LLVM's outliner only outlines NZCV-dead ranges), while go's runtime and OpenSSL's bignum are exactly the code that would break it |
| Dead flag writes: the S-variant half | drop the `s` | **Measured and rejected.** The mirror of the dead-compare check for an `adds`/`subs`/`ands`/`bics`/`adcs` whose destination is still live and whose flags are equally dead: **773** across the corpus (742 by overwrite, 21 at a call, 10 at a return), five times the deletable half and the larger population by far. It fails the actionability bar anyway. The rewrite is 1-for-1 at the same encoding size, and `adds` costs the same latency and the same port as `add` on every AArch64 core -- N/Z/C/V fall out of the adder, so the only marginal cost is a rename slot and a physical flag register, well below anything measurable. Same shape as the sign-CSET GE/PL row above: frees NZCV, saves nothing. Would be informational class at best |
| ADD/SUB immediate chain leftovers | wider match | The adjacent fold is **done** (check_add_sub_imm_chain; see [analyses.md](analyses.md#addsub-immediate-chain-foldable-to-one) for the mechanism and the corpus figures). Of librustc_driver's 46,115 candidate chains armlint reports 26,929; the remaining 18,585 are suppressed by the side-entry gate or by a liveness scan that cannot prove the intermediate dead. Still open: non-adjacent chains, and chains through a register copy |

## Branches and dead code

Cheap to implement -- none of these need liveness machinery -- but the
2026-08 sweep found the family is close to empty in real code. Kept
here with measured populations so it is not re-investigated.

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| `b.cond`/`cbz`/`tbz` `+8` over `b L` | `b.!cond L` | Implemented in 119c22e and reverted: sound (103/103 byte-verified), but clang/Mach-O emits the pair for conditional tail calls -- Mach-O has no conditional-branch relocation, so the spelling is forced and unfixable by recompiling. 2026-08 sweep: **2,437** (2,270 librustc_driver, 84 libcrypto, 59 go). Issue #7 has the /bin/bash census (12/12 tail calls) and reinstatement options: opt-in/informational class, or suppress cross-symbol transfers via LC_FUNCTION_STARTS and keep only intra-function pairs (the function-starts/nlist parsing now exists in main.c -- symbolized findings use it -- so the suppression needs only the boundary check) |
| constant-condition `b.cond` after zero-test | `b` or delete | `cmp Rn, #0` pins C = 1, V = 0, so `b.hs` is always-taken and `b.lo`/`b.vs` never; `cbz wzr` always; `b.al` always; `cmp x, x` pins Z. 2026-08 sweep: **13** across 28.4M instructions (all in librustc_driver), counting `b.al`/`b.nv` and ZR-operand `cbz`/`cbnz`/`tbz`/`tbnz` |
| side-effect-free write to ZR destination | delete | Non-S ALU, MADD family, CSEL family, bitfield ops with Rd = 31; loads excluded (memory side effects). 2026-08 sweep: **0** across 28.4M instructions -- compilers do not emit these |

## One-for-one canonicalizations

| Pattern | Rewrite | Notes |
| --- | --- | --- |
| ~~`and xd, xn, #0xffffffff` / `ubfx xd, xn, #0, #32`~~ | ~~`mov wd, wn`~~ | **Done** (check_and_lo32_mov; see [analyses.md](analyses.md#low-32-zero-extension-foldable-to-mov-wd-wn)). 40 findings of the 56 swept candidates (30 librustc_driver, 6 libcrypto, 4 go): 3 are ZR-source zero materializations, and the 13 in-place ones are deliberately excluded because the rewrite would read `mov wd, wd`, which looks deletable but is a real truncation -- check_redundant_zext owns the in-place cases that really are deletable |
| ZR-operand ALU spellings (`orr wd, wn, wzr`, `add wd, wn, wzr`, `mul xd, xn, xzr`, `eor wd, wn, wzr`, ...) | `mov` / `neg` / `mvn` / `mov #0` | The docs' "further simplification left to the reader" after the MOV #0 → ZR findings; enumerate the alias table. 2026-08 sweep: **90**, all in librustc_driver |
| `lsl #0`, `extr Rd, Rn, Rn, #0`, full-width `ubfx` | `mov` | Degenerate-immediate spellings of a register copy. 2026-08 sweep: **0** |
| ~~`umov wd, vn.s[0]`~~ | ~~`fmov wd, sn`~~ | **Done** (check_umov_lane0_fmov; see [analyses.md](analyses.md#umov-of-lane-0-foldable-to-fmov)). 484 always-live sites (464 libcrypto, 20 go), plus a halfword arm under the new `-m fp16` knob that is four times larger again -- 1,780 sites, 1,775 of them in librustc_driver, folding `umov wd, vn.h[0]` to the FEAT_FP16 `fmov wd, hn`. Two things the sweep figure hid: the `.s[0]`/`.d[0]` forms disassemble as `mov`, not `umov`, because MOV is their preferred alias, so the check must match encodings; and the win is port usage, not size |

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
| ~~`adrp` + `ldr Sd/Dd/Qd` from a literal pool~~ | ~~`fmov #imm8` / `movi`~~ | **Closed, 2026-08 sweep: 35 encodable of 42,324 FP pool loads (0.08%).** The premise was wrong, not just the count. Resolving every target and decoding the bytes shows librustc_driver's 24,333 `ldr d` loads from `__TEXT,__const` are not doubles at all -- they are 8-byte struct/tuple blobs moved through the FP register file (one target decodes to the ASCII `cc_excep`). Of the genuine FP constants, LLVM already materializes every encodable one via FMOV/MOVI, so the pool holds only what does not encode: 0 of 25,241 `ldr d` and 32 of 17,042 `ldr q` corpus-wide |
| BR fold for general registers (`adr x8, L ; br x8`) | `b L` | v1 folds x16/x17 only (veneer-scratch ABI argument); the general case needs liveness at the TARGET, a new scan mode |
| mov-wide address chains → `adr`/`adrp`+`add`; `mov`+`blr` → `bl` | shorter form | Same actionability caveat as adrp+add |

## Feature-gated (`-m` knob exists)

| Item | Notes |
| --- | --- |
| FP16 lift | The `-m fp16` knob now **exists** (added with the lane-0 UMOV fold, whose halfword arm it gates). Still open: relaxing the `type <= 1` gates in the fmov/fcsel/fmul/cvtf checks so the half-precision forms of those folds report under it too |
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
| LDP/STP synthesized through a scratch ADD (`add x27, xN, #big ; ldp x3, x4, [x27]`) → two plain `ldr`/`str` with the offset folded in | Size-neutral 2-for-2 that drops the ADD from the address dependency chain and frees the scratch; gc emits it whenever a pair offset exceeds ±504 or is 8-misaligned, LLVM for big Q-register spill offsets; requires the split offsets to encode (scaled imm12, or LDUR/STUR range). 2026-08 sweep, re-measured: **17,565** sites whose combined offset overflows the pair's imm7 (10,659 go, 6,825 librustc_driver, under 80 elsewhere). shapescan's total for the whole family was **16,838** until the `--selftest` recall half showed its `ldp`/`stp` masks pinned V = 0 and so saw no SIMD&FP pair at all -- exactly the Q-register spill this row names. Corrected it is **26,340** (librustc_driver 3,176 -> 12,296, a 3.9x undercount), which reconciles with addpairscan's independent split to the site: 8,775 in range + 17,565 overflow = 26,340. The old figure was visibly impossible -- a family total below its own overflow half -- and went unquestioned for two days. The in-range half of this family -- 8,775 sites that fold 2-for-**1** rather than 2-for-2 -- turned out to be the bigger prize and is now **done** (check_add_ldr_imm_offset's pair arm; see [analyses.md](analyses.md#add--ldpstp-foldable-to-immediate-offset-ldpstp)). What remains here is only the out-of-range residue, and re-measuring it in 2026-08 cut it hard and changed the conclusion. **17,565 is a candidate pool, not an opportunity count**: addpairscan's split bucket is simply `~fits`, and applies none of the encodability condition this row's own prose names. Adding it, and a check that the scratch is actually dead: **14,818** sites where both split offsets encode, of which **4,307** also leave the scratch untouched afterward (a crude 8-instruction field-match proxy, so a lower bound -- the true figure is between 4,307 and 14,818, and only armlint's own liveness scan can settle it). addpairscan now applies the encodability test and reports both figures side by side (`split 2->2 (encodable)` against `split 2->2 (unconditioned)`), so the older number stays explainable rather than looking like a disagreement. **The scratch register is what kills it.** In go it is `x27` -- gc's `REGTMP`, reserved for the assembler and never allocatable -- in **90%** of the encodable candidates addpairscan reports, rising to **100%** of the 3,788 that also pass the scratch-dead filter. Freeing it buys nothing, so half the justification does not apply to the overwhelming majority. librustc_driver's 517 do use ordinary allocatable scratch (x8/x9/x10/x12) and are mostly the `ldp q` spill shape (308), where the win is real. What is left everywhere else is about one cycle of address-dependency latency against **2 uops instead of 1** -- LDP/STP is a single uop on the cores that matter -- and for the store half that trade is strictly bad, since nothing waits on a store. Stays informational; do not promote to a default check on the strength of the 17,565 |

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

## Investigated and closed (2026-08 sweep)

Candidates measured and rejected, recorded so they are not
re-investigated. Several looked large before the operand conditions
were applied, and the dead-write row is the sharper warning: it looked
large, then small, then wrong, and only the third pass showed most of
what was left was a constant table being read as code.

| Pattern | Rewrite | Measured |
| --- | --- | --- |
| Interleaved copy `ldr Rt,[Rn,#a] ; str Rt,[Rm,#b] ; ldr Rt2,[Rn,#a+s] ; str Rt2,[Rm,#b+s]` | `ldp`/`stp` (4 -> 2) | **27** across 28.4M instructions (10 Q, 12 X/W cross-base, 5 X same-base). The strict-adjacency LDP/STP coalescer cannot see these -- the load/store interleave hides both same-direction pairs -- and the pair count that motivated the look was large (`ldr x,[sp+i] ; str x,[sp+i]` is the 11th most frequent dependent pair in librustc_driver at 29,271). But LLVM's `AArch64LoadStoreOptimizer` has already paired essentially all of them; what remains adjacent-and-interleaved is noise. Would also have needed an alias argument for the cross-base majority, since the rewrite moves the second load ahead of the first store |
| `sub sp, sp, #N ; stp Xt, Xt2, [sp]` | `stp Xt, Xt2, [sp, #-N]!` | **0 of 79,127** pairs. Only 2 have the zero pair-offset that pre-indexing requires, and neither has an `N` that encodes in imm7. Compilers already use the writeback prologue where it applies (`stp x29, x30, [sp, #-16]!`); where they emit the separate `sub sp`, the callee-saves sit at a non-zero offset by design and no pre-index expression exists. The pair count looks inviting -- 74,761 in librustc_driver alone -- and is entirely unfoldable |
| pure write immediately clobbered | delete the first | **4** across 28.4M instructions, all in go, and **2** of those are direct-branch targets that the side-entry gate would reject -- so 2 realizable findings corpus-wide. Two modelling errors had to come out first. A first pass reported 6,424, every one a BFM alias (`bfi`/`bfxil`), which merges into its destination and so reads it; `UBFM`/`SBFM` do overwrite. Pinning that gave **10**, of which **6 were not instructions**: the word `0x5A827999` -- SHA-1's round constant K1, four copies in the literal pool at the head of libcrypto's and dyld's `__text` -- matched because the CSEL mask left `op2` (bits 11..10) free, and `op2 = 1x` is unallocated. Capstone refuses the word, so armlint skips it as data and could never have reported those; mask fixed. The two survivors are both toolchain-forced: an unreachable trap block (two `adrp`+`add` addresses discarded, then `mov x0, xzr ; str x0, [x0]` to force a fault) and go's frame-pointer-chain shim (`sub x29, sp, #0x8 ; mov x29, xzr`). Not a model floor either -- adding ADRP to the pure-writer set, which is sound and was missing, gives 25 sites, still all go, 22 of them gated, 3 surviving. Zero anywhere LLVM generated the code, which is what dead-code elimination and register allocation are for; this is a go-assembler template artifact, not a general lint |
| Unscaled (`LDUR`/`STUR`) consumers in the writeback folds | `ldr Rt, [Rn], #a` / `ldr Rt, [Rn, #a]!` | **0 and 0.** `check_ldr_str_add_post_indexed` and `check_add_ldr_str_pre_indexed` decode only the unsigned-offset spelling of their access, the same blindness `check_add_ldr_imm_offset` had -- but here it is unreachable, so there is nothing to fix. A writeback fold needs the access's own displacement to be zero, and no assembler spells a zero offset `LDUR`: it uses `LDR`. Measured on the corpus with the real operand conditions applied, both populations are empty |
| Writeback and register-offset stores under `check_mov_zero_to_xzr` | `str xzr, [...]` | **5 and 10** candidate sites across the corpus, about one realized finding at the store arm's rate. The ZR substitution is sound in both -- only Rt changes, so the base update and the index are irrelevant to it -- and both are refused only because the arm reuses decoders built to answer a different question (is this address interchangeable with a plain base-plus-offset one?). A real false negative, and too small to spend a decoder on |

## Infrastructure

| Item | Notes |
| --- | --- |
| Multi-slot deferral | The single pending_mz/pending_fp slots drop the earlier finding when two deferrals overlap; false-negative-only, documented in `defer_dead_mov`. **Now measured**: teaching the ADD fold the SIMD&FP register class added 1,830 findings and cost **18** ADD + LDP ones, all in librustc_driver, every one an FP access opening a deferral that evicts a pair finding still waiting on its kill two instructions later. A queue would need the advancer to emit more than one finding per instruction, which the check signature does not currently allow |
| ~~Multi-use base: fold every access off one ADD, then delete it~~ | **Done, 2026-08: `check_add_ldr_str_multi_fold`, 3,804 findings across 28.4M instructions** (3,188 at two or more uses, and 616 more once the sole gapped use was let in -- see the coverage-gaps row above). Teaching `check_add_ldr_imm_offset` the unscaled spelling made the whole candidate population visible to it but turned only **126** of the 9,124 encodable ADD + LDUR/STUR sites into findings. The gap was never blindness, it was the deadness tier: the immediate tier is a load into its own base, 21.3% of the encodable *scaled* population and 1.4% of the unscaled one. The unscaled spelling appears where the offset is negative or off the access-size grid -- a field access off a base the ADD does not consume, and at 10.2% of unscaled sites the very next instruction is another access off the same base against 4.4% of scaled ones. So the fold those wanted was N-for-1: when *every* use of the ADD's Rd is an access whose combined offset encodes, all of them rebase and the ADD is deleted. Two things the adjacency folds never needed: a forward scan proving there is no other use, and a watch on the ADD's *source*, which the rewritten accesses read at their own offsets (SP included, where `arm64_gpr_num` returns -1 and the liveness scan is blind). 2,644 of the sites are stack frames, one LLVM shape -- `LocalStackSlotAllocation` inserting a virtual base register off a pre-layout offset estimate that turns out to fit |
| Register-side liveness sweep over SVE/SME | The exhaustive `classify_reg_liveness` cross-check (ARMLINT_LIVENESS_SWEEP) excludes the SVE and SME vector spaces. Under Capstone 6 the property reports **~20M** violations there -- the SME outer-product, gather/scatter and ZA-tile families, plus the FEAT_LSE128/FEAT_THE 128-bit atomics -- every one a genuine disagreement about an instruction armlint does not model. None is reachable today: Capstone 5, the shipped dependency, does not decode them, so the driver skips those words as data and flushes state. The scalar members of the same spaces ARE modelled and swept (SVE INCB/DECB and CLASTA/CLASTB read the GPR they write, LDG replaces only Xt's tag), because 5 does decode those and they appear in hand-written crypto. Widening the scope is v6-migration work and wants the register model extended first, not the exclusion deleted |
| Target-side liveness | NZCV at a branch target is **done**: `nzcv_dead_at_target` walks the scanned buffer for the CMPBR fold, which cannot make the block-locality assumption the other branch folds make. The register-side twin (scan for a GPR at a known target) is still open and unlocks the general-register BR fold. The NZCV scan refuses rather than chases -- a `cbz`/`b` at the target ends it, which is 10 of the 16 pairs it rejects in /bin/ls |
| ~~Hybrid `mov`/`orr`+`movk` constant chains~~ | **Closed, 2026-08 sweep: 10 shortenable chains across 1.96M.** The docs-acknowledged deferral in the MOV-chain machinery ("the reported minimum is an upper bound on the true one") is an upper bound that never binds. Modelling the hybrid minimum -- the whole value as a bitmask immediate, or a bitmask immediate differing in exactly one halfword plus a MOVK -- over every maximal MOVZ/MOVN+MOVK chain finds 10 sites where it beats the pure move-wide minimum, all in go, all 3 insns -> 2. LLVM's `expandMOVImm` already tries the ORR+MOVK forms; gc's assembler does not. Of the corpus's 80,904 multi-instruction chains (47,334 of length 2, 1,974 of 3, 31,596 of 4), **zero** are shortenable by the pure move-wide rule armlint already applies |
| ~~LDUR pair coalescing~~; writeback pair coalescing; load+sext at other addressing modes | **LDUR closed, 2026-08.** The coalescer decoded only the unsigned-offset spelling, so any pair whose displacement the assembler chose to encode unscaled was invisible -- and JSC's arm64 MacroAssembler emits `LDUR`/`STUR` for every offset under 256, which is most of them. Normalizing both spellings to signed byte offsets, and making the imm7 test explicit (an unscaled offset need not be a multiple of the transfer size, which the scaled imm12 used to guarantee for free), takes a 54.7M-instruction JavaScriptCore JIT corpus from **215,635 to 718,415** findings, all of the difference in five classes: LDP 6,601 -> 247,440, STP 121 -> 118,019, reverse LDP 237 -> 93,772, reverse STP 24 -> 48,883, zero-store STR xzr 0 -> 1,649. Adjacent loads are now the corpus's largest class by a factor of four. Writeback forms stay deferred -- they update the base, so they are not interchangeable with a plain pair -- as do the sext folds |
