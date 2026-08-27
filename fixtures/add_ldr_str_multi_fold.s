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

    // P) A SOLE use, one instruction past the ADD. One use pays as
    //    well as many -- the ADD goes either way -- and the only
    //    question is whose finding it is.
    //    check_add_ldr_imm_offset clears its pending slot on anything
    //    that is not the consumer, so it never sees this one. Most
    //    real sites look like this: the scheduler covered the address
    //    latency with an unrelated instruction.
    add     x8, x1, #16
    mov     x9, #7
    str     q0, [x8]                // -> str q0, [x1, #0x10]
    mov     x8, #4

    // P) The same across a wider gap, on the shape that dominates the
    //    corpus: a frame base whose one consumer is a pair store,
    //    with the values it stores materialized in between.
    add     x8, sp, #0x1d0
    mov     x0, #7
    mov     x1, #9
    stp     x0, x1, [x8, #16]       // -> stp x0, x1, [sp, #0x1e0]
    mov     x8, #14

    // Negatives:
    // N1) A sole use ADJACENT to the ADD. That is the whole of
    //     check_add_ldr_imm_offset's reach and its finding, so this
    //     check stays silent and the site is never reported twice.
    //     The block is not silent -- the other check's finding is in
    //     this file's tally -- which is what makes this an ownership
    //     case rather than a claim the fold fails.
    add     x8, x1, #16
    str     q0, [x8]
    mov     x8, #15

    // N2) A sole gapped use whose gap moves the ADD's source. The
    //     rebased store would read x1 at its own offset, and x1 is no
    //     longer what the ADD added to.
    add     x8, x1, #16
    mov     x1, #7
    str     q0, [x8]
    mov     x8, #16

    // N3) Two uses, but the second one's sum has no encoding: 0xfff0
    //     plus 16, scaled by 16, is 4096 -- one past imm12.
    add     x8, x1, #16
    str     q0, [x8]
    str     q1, [x8, #0xfff0]
    mov     x8, #5

    // N4) A use that is not a rebasable access: the ADD has to
    //     survive for it, so nothing is saved.
    add     x8, x1, #16
    str     q0, [x8]
    str     q1, [x8, #32]
    add     x9, x8, #1
    mov     x8, #6

    // N5) A store OF the base reads the sum the fold deletes.
    add     x8, x1, #16
    str     q0, [x8]
    str     x8, [x8, #24]
    mov     x8, #7

    // N6) A pre-indexed use. Same encoding group as LDUR, but it
    //     writes the sum back to the base, so deleting the ADD would
    //     drop an observable update.
    add     x8, x1, #16
    str     q0, [x8]
    ldr     x5, [x8, #8]!
    mov     x8, #8

    // N7) The ADD's SOURCE moves between the uses. Every rebased
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

    // N8) The same with SP as the source. arm64_gpr_num maps SP to
    //     -1, so the register-liveness scan is blind to it and the
    //     stack adjustment has to be caught from the encoding.
    add     x8, sp, #16
    str     q0, [x8]
    sub     sp, sp, #32
    str     q1, [x8, #32]
    mov     x8, #10

    // P) The control for N8: the same fragment with a flag-setting
    //    compare in that slot, where Rd = 31 is the zero register and
    //    not SP, folds.
    add     x8, sp, #16
    str     q0, [x8]                // -> str q0, [sp, #0x10]
    cmp     x0, #32
    str     q1, [x8, #32]           // -> str q1, [sp, #0x30]
    mov     x8, #11

    // N9) Straight-line code ends before the base is proven dead:
    //     uses in a later block are not ours to see.
    add     x8, x1, #16
    str     q0, [x8]
    str     q1, [x8, #32]

    ret
