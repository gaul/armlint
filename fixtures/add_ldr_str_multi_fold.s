// Integration fixture for check_add_ldr_str_multi_fold.
//
// Every positive here ends with an instruction that overwrites the
// base, since that overwrite is what proves the ADD's result dead and
// releases the finding.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical: two loads, the second one killing the base.
    add     x8, x0, #0x120
    ldr     x1, [x8]                // -> ldr x1, [x0, #0x120]
    ldr     x8, [x8, #16]           // -> ldr x8, [x0, #0x130]

    // 2) Rd == Rn. Deleting the ADD leaves the source holding its old
    //    value, which is exactly what the rebased accesses want; this
    //    is the dominant shape in real code.
    add     x10, x10, #0x458
    ldr     x11, [x10]              // -> ldr x11, [x10, #0x458]
    ldr     w10, [x10, #8]          // -> ldr w10, [x10, #0x460]

    // 3) Two stores. Nothing overwrites the base on the spot, so the
    //    finding waits for the trailing mov.
    add     x8, x1, #16
    str     x0, [x8]                // -> str x0, [x1, #0x10]
    str     x2, [x8, #24]           // -> str x2, [x1, #0x28]
    mov     x8, #1

    // 4) Mixed spellings. Which one the assembler picked for an
    //    access says nothing about whether its sum folds, and the
    //    output spelling is chosen from the sum alone -- here one
    //    lands on the access-size grid and the other does not.
    add     x8, x0, #0x120
    ldur    x1, [x8, #-8]           // -> ldr x1, [x0, #0x118]
    ldr     x8, [x8, #8]            // -> ldr x8, [x0, #0x128]

    // 5) A sum the unsigned-offset form cannot express at all.
    add     x8, x0, #16
    ldur    x1, [x8, #-24]          // -> ldur x1, [x0, #-8]
    ldr     x8, [x8, #8]            // -> ldr x8, [x0, #0x18]

    // 6) The stack-zeroing shape: a frame base every store could have
    //    reached from SP itself. The ADD's immediate is off the
    //    16-byte grid, which is why these had to be spelled STUR --
    //    rebasing puts all four back on it.
    add     x8, sp, #0x2a8
    movi    v0.2d, #0
    stur    q0, [x8, #0x68]         // -> str q0, [sp, #0x310]
    stur    q0, [x8, #0x78]         // -> str q0, [sp, #0x320]
    stur    q0, [x8, #0x88]         // -> str q0, [sp, #0x330]
    stur    q0, [x8, #0x98]         // -> str q0, [sp, #0x340]
    mov     x8, #2

    // 7) Pair uses. The pair forms have no unsigned-offset spelling,
    //    so their range test is the signed imm7 one.
    add     x9, sp, #0x38
    stp     xzr, xzr, [x9]          // -> stp xzr, xzr, [sp, #0x38]
    stp     xzr, xzr, [x9, #32]     // -> stp xzr, xzr, [sp, #0x58]
    mov     x9, #3

    // 8) An integer pair load naming the base among its destinations
    //    kills it on the spot: the no-writeback form reads the base
    //    once before writing either destination.
    add     x8, x0, #0x40
    ldr     x1, [x8]                // -> ldr x1, [x0, #0x40]
    ldp     x8, x9, [x8, #32]       // -> ldp x8, x9, [x0, #0x60]

    // 9) More uses than a finding has lines for: the rest are
    //    counted and summarized rather than rendered.
    add     x9, sp, #0x100
    stp     xzr, xzr, [x9]          // -> stp xzr, xzr, [sp, #0x100]
    stp     xzr, xzr, [x9, #32]     // -> stp xzr, xzr, [sp, #0x120]
    stp     xzr, xzr, [x9, #64]     // -> stp xzr, xzr, [sp, #0x140]
    stp     xzr, xzr, [x9, #96]     // -> stp xzr, xzr, [sp, #0x160]
    stp     xzr, xzr, [x9, #128]    // -> stp xzr, xzr, [sp, #0x180]
    mov     x9, #12

    // Negatives:
    // N1) One use. That is check_add_ldr_imm_offset's fold, reported
    //     there; this check stays silent so no site is reported
    //     twice. (An FP store, which that check does not cover, so
    //     this block is silent entirely.)
    add     x8, x1, #16
    str     q0, [x8]
    mov     x8, #4

    // N2) Two uses, but the second one's sum has no encoding: 0xfff0
    //     plus 16, scaled by 16, is 4096 -- one past imm12.
    add     x8, x1, #16
    str     q0, [x8]
    str     q1, [x8, #0xfff0]
    mov     x8, #5

    // N3) A use that is not a rebasable access: the ADD has to
    //     survive for it, so nothing is saved.
    add     x8, x1, #16
    str     q0, [x8]
    str     q1, [x8, #32]
    add     x9, x8, #1
    mov     x8, #6

    // N4) A store OF the base reads the sum the fold deletes.
    add     x8, x1, #16
    str     q0, [x8]
    str     x8, [x8, #24]
    mov     x8, #7

    // N5) A pre-indexed use. Same encoding group as LDUR, but it
    //     writes the sum back to the base, so deleting the ADD would
    //     drop an observable update.
    add     x8, x1, #16
    str     q0, [x8]
    ldr     x5, [x8, #8]!
    mov     x8, #8

    // N6) The ADD's SOURCE moves between the uses. Every rebased
    //     access reads it at its own offset instead of at the ADD, so
    //     the second store would land somewhere else entirely.
    add     x8, x0, #16
    str     q0, [x8]
    mov     x0, #5
    str     q1, [x8, #32]
    mov     x8, #9

    // P) A source clobber AFTER the last use costs nothing: both
    //    stores read the source before it moved, so both still rebase
    //    and the ADD still dies.
    add     x8, x0, #16
    str     q0, [x8]                // -> str q0, [x0, #0x10]
    str     q1, [x8, #32]           // -> str q1, [x0, #0x30]
    mov     x0, #5
    mov     x8, #13

    // N7) The same with SP as the source. arm64_gpr_num maps SP to
    //     -1, so the register-liveness scan is blind to it and the
    //     stack adjustment has to be caught from the encoding.
    add     x8, sp, #16
    str     q0, [x8]
    sub     sp, sp, #32
    str     q1, [x8, #32]
    mov     x8, #10

    // P) The control for N7: the same fragment with a flag-setting
    //    compare in that slot, where Rd = 31 is the zero register and
    //    not SP, folds.
    add     x8, sp, #16
    str     q0, [x8]                // -> str q0, [sp, #0x10]
    cmp     x0, #32
    str     q1, [x8, #32]           // -> str q1, [sp, #0x30]
    mov     x8, #11

    // N8) Straight-line code ends before the base is proven dead:
    //     uses in a later block are not ours to see.
    add     x8, x1, #16
    str     q0, [x8]
    str     q1, [x8, #32]

    ret
