// Integration fixture for check_extend_cvtf_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: sign-extend feeding the signed conversion; the
    // extended register dies at the following overwrite, so the
    // deferred finding emits.
    sxtw    x8, w0
    scvtf   d0, x8
    mov     x8, #1

    // Positive: zero-extend feeding the unsigned conversion.
    mov     w9, w1
    ucvtf   d1, x9
    mov     x9, #1

    // Positive: zero-extend feeding the SIGNED conversion -- the
    // zero-extended 64-bit value is the unsigned 32-bit value, so
    // the rewrite crosses to UCVTF.
    mov     w10, w2
    scvtf   s2, x10
    mov     x10, #1

    // Negative: a sign-extended source cannot feed the unsigned
    // conversion (sext of a negative reads back as a huge value).
    sxtw    x11, w3
    ucvtf   d3, x11
    mov     x11, #1

    // Negative: the extended register is read again before dying --
    // the extend must stay.
    sxtw    x12, w4
    scvtf   d4, x12
    add     x1, x12, x2

    ret
