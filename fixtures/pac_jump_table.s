// Integration fixture for the PAC raw-BR audit's jump-table
// classifier (-a pac via the sidecar). The clang switch idiom --
// adrp/add of a table base, an ldrsw of a signed offset indexed off
// it, an adr for the PC-relative base, an add combining them, then br
// -- computes its target from a read-only table, not a corruptible
// pointer, so the audit auto-dismisses it. A bare br and a raw blr
// carry no such provenance and stay on the worklist. No x30 spill
// here, so the LR-spill half of the audit is silent.
//
// Darwin-only, via the arm64 .arch sidecar: the table base is
// materialized with the Mach-O operand syntax _main@PAGE /
// _main@PAGEOFF, which clang rejects when targeting ELF ("invalid
// symbol kind for ADRP relocation"). The ELF spelling of the same
// pair is adrp x17, sym + add x17, x17, :lo12:sym, and the two are
// mutually exclusive in one source file. The classifier itself is
// architecture-neutral -- it matches encodings, not relocations --
// so nothing about it is Mach-O-specific; only this fixture's way of
// writing the address is. Giving Linux its own coverage of the
// classifier needs a second fixture in ELF syntax.

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
