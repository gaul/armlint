// Integration fixture for check_udiv_msub_remainder.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (one temporary dies at the MSUB's destination, the
    // other at the trailing mov):
    // 1) Canonical: the MSUB overwrites the quotient.
    mov     x8, #16
    udiv    x9, x1, x8
    msub    x9, x9, x8, x1          // -> and x9, x1, #0xf
    mov     x8, #5

    // 2) The MSUB's multiply commutes.
    mov     x8, #8
    udiv    x9, x1, x8
    msub    x9, x8, x9, x1          // -> and x9, x1, #0x7
    mov     x8, #5

    // 3) The MSUB may overwrite the constant instead; the quotient
    //    dies at the trailing mov.
    mov     x8, #16
    udiv    x9, x1, x8
    msub    x8, x9, x8, x1          // -> and x8, x1, #0xf
    mov     x9, #5

    // 4) W-form, divisor 2.
    mov     w8, #2
    udiv    w9, w1, w8
    msub    w9, w9, w8, w1          // -> and w9, w1, #0x1
    mov     w8, #5

    // Negatives:
    // N1) The MSUB's accumulator is not the original dividend.
    mov     x8, #16
    udiv    x9, x1, x8
    msub    x9, x9, x8, x2
    mov     x8, #5

    // N2) A fresh MSUB destination would need both temporaries proven
    //     dead at once; conservatively skipped.
    mov     x8, #16
    udiv    x9, x1, x8
    msub    x10, x9, x8, x1
    mov     x8, #5

    // N3) Non-power-of-two divisor: a genuine divide.
    mov     x8, #6
    udiv    x9, x1, x8
    msub    x9, x9, x8, x1
    mov     x8, #5

    ret
