// Integration fixture for check_udiv_strength_reduce.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) UDIV by power-of-2 (X form) -> LSR.
    mov     x0, #8
    udiv    x3, x2, x0          // -> lsr x3, x2, #3

    // 2) W form: UDIV by power-of-2.
    mov     w0, #16
    udiv    w3, w2, w0          // -> lsr w3, w2, #4

    // 3) Larger power-of-2.
    mov     x0, #1024
    udiv    x3, x2, x0          // -> lsr x3, x2, #10

    // 4) Power-of-2 via shifted MOVZ.
    movz    x0, #1, lsl #32
    udiv    x3, x2, x0          // -> lsr x3, x2, #32

    // 5) Power-of-2 in the upper half: 0x10000.
    movz    x0, #1, lsl #16
    udiv    x3, x2, x0          // -> lsr x3, x2, #16

    // Negatives:
    // N1) Non-pow2 divisor (3).
    mov     x0, #3
    udiv    x3, x2, x0

    // N2) Non-pow2 divisor (10).
    mov     x0, #10
    udiv    x3, x2, x0

    // N3) 2^N - 1 (7) -- not folded.
    mov     x0, #7
    udiv    x3, x2, x0

    // N4) Identity (C = 1).
    mov     x0, #1
    udiv    x3, x2, x0

    // N5) UDIV is not commutative: divisor not from MOV.
    //     mov x0, #8 ; udiv x3, x0, x2 -- x2 is the divisor.
    mov     x0, #8
    udiv    x3, x0, x2

    // N6) Intervening unrelated instruction closes the chain.
    mov     x0, #8
    add     x5, x5, x6
    udiv    x3, x2, x0

    // N7) SDIV by 2^N is NOT equivalent to ASR (wrong rounding).
    mov     x0, #8
    sdiv    x3, x2, x0

    ret
