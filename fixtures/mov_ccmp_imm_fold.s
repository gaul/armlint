// Integration fixture for check_mov_ccmp_imm_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: the constant folds into CCMP's unsigned 5-bit
    // immediate; the constant register dies at the following
    // overwrite, so the deferred finding emits.
    mov     x8, #5
    ccmp    x0, x8, #0, ne
    mov     x8, #1

    // Positive: W-form at the immediate's top boundary.
    mov     w9, #31
    ccmp    w1, w9, #4, eq
    mov     w9, #0

    // Positive: CCMN folds the same way.
    mov     x10, #12
    ccmn    x2, x10, #8, lt
    mov     x10, #0

    // Negative: 32 exceeds the unsigned 5-bit immediate.
    mov     x11, #32
    ccmp    x3, x11, #0, ne
    mov     x11, #0

    // Negative: the constant is the compare's LEFT operand; only Rm
    // has an immediate slot.
    mov     x12, #5
    ccmp    x12, x4, #0, ne
    mov     x12, #0

    // Negative: the constant register is read again before dying --
    // the MOV must stay, so the deferred finding is discarded.
    mov     x13, #5
    ccmp    x5, x13, #0, ne
    add     x6, x13, #1

    ret
