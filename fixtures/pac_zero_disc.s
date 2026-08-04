// Integration fixture for the PAC audit's zero-discriminator rung
// (-a pac via the sidecar). BRAAZ/BLRAAZ and their B-key twins
// authenticate against the constant-zero modifier -- on arm64e the
// C-ABI signing for every plain function pointer -- so any pointer
// signed with the same key and discriminator zero substitutes; each
// is flagged as a worklist item. The register-diversified forms and
// the SP-diversified signed returns are the upgrade targets and stay
// clean. A raw br rides along to show the full ladder: raw (proves
// nothing) under one finding class, zero-discriminator (proves the
// key) under the other. The .arch directive covers the Armv8.3
// encodings on both host assemblers; no x30 spill here, so the
// LR-spill half of the audit is silent.

    .arch   armv8.3-a
    .text
    .globl  _main
    .p2align 2
_main:
    // The four zero-discriminator forms: flagged, one finding each.
    braaz   x16
    blraaz  x8
    brabz   x0
    blrabz  x1

    // Register-diversified authenticated branches: clean, including
    // the SP modifier spelling (diversified by SP, not zero).
    braa    x16, x17
    blraa   x2, x3
    blrab   x4, x5
    braa    x16, sp

    // Signed returns are SP-diversified by construction: clean.
    retaa
    retab

    // The rung below: a raw indirect branch, flagged by the
    // unauthenticated-BR/BLR check instead.
    br      x9
    ret
