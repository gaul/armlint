// Integration fixture for check_ext_mul_widening.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) ART's (long) a * (long) b.
    sxtw    x0, w1
    sxtw    x1, w2
    mul     x0, x0, x1            // -> smull x0, w0, w2
    mov     w1, #1

    // 2) A field times a constant, the SXTW in place (ART's shape).
    mov     x0, #0xc
    ldr     w2, [x1, #8]
    sxtw    x2, w2
    mul     x0, x2, x0            // -> smull x0, w2, w0
    mov     w2, #2

    // 3) Unsigned, with an accumulator.
    ldr     w3, [x4]
    mov     w5, w6
    madd    x7, x3, x5, x8        // -> umaddl x7, w3, w6, x8
    mov     w5, #5

    // Negatives:
    // N1) The other operand is an arbitrary 64-bit value.
    sxtw    x9, w10
    mul     x11, x12, x9
    mov     w9, #9

    // N2) The extension is read again afterwards.
    sxtw    x13, w14
    sxtw    x15, w16
    mul     x13, x13, x15
    add     x17, x15, #1

    // N3) Data in the gap ends the region.
    sxtw    x20, w21
    .word   0xffffffff
    ldrsw   x22, [x23]
    mul     x20, x20, x22

    ret
