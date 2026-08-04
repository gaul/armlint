// Integration fixture for the PAC raw-BR audit's jump-table
// classifier (-a pac via the sidecar). The clang switch idiom --
// adrp/add of a table base, an ldrsw of a signed offset indexed off
// it, an adr for the PC-relative base, an add combining them, then br
// -- computes its target from a read-only table, not a corruptible
// pointer, so the audit auto-dismisses it. A bare br and a raw blr
// carry no such provenance and stay on the worklist. No x30 spill
// here, so the LR-spill half of the audit is silent.

    .text
    .globl  _main
    .p2align 2
_main:
    // A recognized jump table: dismissed, no finding. Emit ADRP via
    // .long to avoid Mach-O/ELF relocation-syntax differences
    // (`@PAGE` is Mach-O-only); the classifier keys on encodings, not
    // relocations, so a literal page-0 ADRP plus a plain immediate
    // ADD is the same idiom.
    .long   0x90000011              // adrp x17, page0
    add     x17, x17, #0x18
    ldrsw   x16, [x17, x16, lsl #2]
    adr     x17, .
    add     x16, x17, x16
    br      x16

    // A bare indirect branch with no idiom: flagged (unknown target
    // provenance -- could be a veneer, an unrecognized table, or a
    // hazard).
    br      x9

    // A raw indirect call: flagged, and never a jump table.
    blr     x10
    ret
