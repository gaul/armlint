// Integration fixture for check_add_sub_imm_chain.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: the canonical shape -- a stack-object address plus a
    // field offset. The consumer overwrites the temp, so it dies
    // structurally and the pair emits on the spot.
    add     x11, sp, #0x130
    add     x11, x11, #0x81         // -> add x11, sp, #0x1b1

    // Positive: the kinds mix; sub then add renders whichever of
    // ADD/SUB carries the sum.
    sub     x8, x29, #0x100
    add     x8, x8, #0x30           // -> sub x8, x29, #0xd0

    // Positive: add then sub, crossing back to a plain ADD.
    add     x12, x13, #0x30
    sub     x12, x12, #0x10         // -> add x12, x13, #0x20

    // Positive: cancelling adjustments leave a register copy.
    add     x14, x15, #0x40
    sub     x14, x14, #0x40         // -> mov x14, x15

    // Positive: the W form folds the same way.
    add     w16, w17, #4
    add     w16, w16, #8            // -> add w16, w17, #0xc

    // Positive: two shifted adjustments whose sum is still a multiple
    // of 4096, so the shifted form still carries it.
    add     x18, x19, #0x1, lsl #12
    add     x18, x18, #0x1, lsl #12 // -> add x18, x19, #0x2000

    // Positive: a fresh destination defers to the register-liveness
    // scan, which the MOVZ below commits.
    add     x9, x10, #4
    add     x0, x9, #8              // -> add x0, x10, #0xc
    mov     x9, #1

    // Negative: the compiler's own split of a wide constant is already
    // minimal -- 0x1000 + 0x20 is neither an imm12 nor a multiple of
    // 4096, so the sum encodes neither way.
    add     x20, x20, #0x1, lsl #12
    add     x20, x20, #0x20

    // Negative: widths must agree; a W-form sum is zero-extended
    // before an X-form consumer reads it.
    add     w21, w22, #4
    add     x21, x21, #8

    // Negative: an ADDS producer's NZCV write would be lost.
    adds    x23, x24, #4
    add     x23, x23, #8

    // Negative: an ADDS consumer's flags depend on the intermediate
    // the fold erases, even though its result would be right.
    add     x25, x26, #4
    adds    x25, x25, #8

    // Negative: a producer writing SP never opens -- the stack pointer
    // is never dead, so the first adjustment cannot be deleted.
    add     sp, sp, #0x10
    add     sp, sp, #0x20

    // Negative: the temp stays live past the pair, so the deferred
    // finding never commits.
    add     x27, x28, #4
    add     x1, x27, #8
    ret

    // Negative: side entry -- the branch lands on the consumer, so the
    // path entering there never ran the first adjustment and the
    // folded constant would be wrong.
    cbz     x0, 1f
    add     x2, x3, #4
1:
    add     x2, x2, #8
    ret
