// Integration fixture for check_reg_copy_chain.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) The move-resolver fan-out shape: a copy chained on the copy
    //    just made instead of the original source.
    mov     x1, x0
    mov     x24, x1

    // 2) W-width chain.
    mov     w3, w2
    mov     w5, w3

    // 3) A W read of an X copy reads the low half of the same value.
    mov     x7, x6
    mov     w8, w7

    // 4) Full-width copy-back: x10 still holds the copied value, the
    //    second copy is a no-op.
    mov     x11, x10
    mov     x10, x11

    // 5) Three-copy chain: one finding per rewritable link.
    mov     x13, x12
    mov     x14, x13
    mov     x15, x14

    // 6) FP chains, D and S.
    fmov    d2, d1
    fmov    d3, d2
    fmov    s5, s4
    fmov    s6, s5

    // Negatives:
    // 7) An X read of a W copy -- the zeroed upper half is not a
    //    property of the original source.
    mov     w17, w16
    mov     x18, x17

    // 8) Fan-out from one source is already independent.
    mov     x20, x19
    mov     x21, x19

    // 9) W copy-back also zeroes the upper half -- skipped.
    mov     w23, w22
    mov     w22, w23

    // 10) A D read of an S copy -- upper half not guaranteed.
    fmov    s8, s7
    fmov    d9, d8

    ret
