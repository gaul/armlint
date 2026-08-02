// Integration fixture for the -a pac audit checks
// (check_pac_lr_spill, check_pac_raw_indirect). The .arch directive
// is for GNU as, whose default -march rejects the v8.3 instructions
// (retaa/retab, braaz/blraaz).

    .arch armv8.3-a
    .text
    .globl  _main
    .p2align 2
_main:
    // A signed prologue: no findings.
    pacibsp
    stp     x29, x30, [sp, #-16]!
    ldp     x29, x30, [sp], #16
    retab

    // Signed with callee-saved pairs before the LR pair: the window
    // covers the whole prologue.
    paciasp
    stp     x20, x19, [sp, #-32]!
    stp     x29, x30, [sp, #16]
    ldp     x29, x30, [sp, #16]
    ldp     x20, x19, [sp], #32
    retaa

    // 1) An unsigned LR spill.
    stp     x29, x30, [sp, #-16]!
    ldp     x29, x30, [sp], #16
    ret

    // 2) The STR spelling.
    str     x30, [sp, #8]
    ret

    // 3) A control transfer between the signing and the spill ends
    //    the straight-line prologue: conservatively unsigned.
    pacibsp
    cbz     x0, 1f
    stp     x29, x30, [sp, #-16]!
    ldp     x29, x30, [sp], #16
1:
    ret

    // Authenticated indirects: no findings.
    braaz   x16
    blraaz  x8

    // 4) A raw indirect call.
    blr     x8

    // 5) A raw indirect branch.
    br      x9
