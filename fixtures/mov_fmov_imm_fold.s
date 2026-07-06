// Integration fixture for check_mov_fmov_imm_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: single-precision 1.0f built in a GPR and transferred;
    // the constant register dies at the following overwrite, so the
    // deferred finding emits.
    mov     w8, #0x3f800000
    fmov    s0, w8
    mov     w8, #1

    // Positive: double-precision 1.0 via an X transfer.
    mov     x9, #0x3ff0000000000000
    fmov    d1, x9
    mov     x9, #0

    // Positive: SCVTF of a small constant.
    mov     w10, #5
    scvtf   d2, w10
    mov     w10, #0

    // Positive: UCVTF folds the same way.
    mov     w11, #3
    ucvtf   s3, w11
    mov     w11, #0

    // Positive: a negative constant converts to a negative immediate.
    mov     w12, #-3
    scvtf   s4, w12
    mov     w12, #0

    // Positive: a W chain feeding a 64-bit source -- the W write
    // zeroed the upper half, so the X read is the constant.
    mov     w13, #7
    scvtf   d5, x13
    mov     w13, #0

    // Negative: 0.1f's pattern is not FMOV-encodable (the fraction
    // is wider than four bits).
    mov     w14, #0xcccd
    movk    w14, #0x3dcc, lsl #16
    fmov    s6, w14
    mov     w14, #0

    // Negative: 32.0 exceeds the immediate's exponent range.
    mov     w15, #32
    scvtf   d7, w15
    mov     w15, #0

    // Negative: the constant register is read again before dying --
    // the MOV must stay, so the deferred finding is discarded.
    mov     w16, #0x3f800000
    fmov    s8, w16
    add     w1, w16, w2

    ret
