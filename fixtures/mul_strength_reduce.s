// Integration fixture for check_mul_strength_reduce.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) MUL by power-of-2 (X form) -> LSL.
    mov     x0, #8
    mul     x3, x2, x0          // -> lsl x3, x2, #3

    // 2) MUL by 2^N+1 (X form) -> ADD shifted.
    mov     x0, #3
    mul     x3, x2, x0          // -> add x3, x2, x2, lsl #1

    // 3) W form: MUL by power-of-2.
    mov     w0, #16
    mul     w3, w2, w0          // -> lsl w3, w2, #4

    // 4) Commutativity: Rn == mov_rd.
    mov     x0, #5
    mul     x3, x0, x2          // -> add x3, x2, x2, lsl #2

    // 5) Large power-of-2 via shifted MOVZ.
    movz    x0, #1, lsl #32
    mul     x3, x2, x0          // -> lsl x3, x2, #32

    // 6) 2^16+1 via MOVZ+MOVK.
    movz    x0, #1, lsl #16
    movk    x0, #1
    mul     x3, x2, x0          // -> add x3, x2, x2, lsl #16

    // Negatives:
    // N1) 2^N - 1 (not folded).
    mov     x0, #7
    mul     x3, x2, x0

    // N2) Arbitrary non-pow2/non-2^N+1.
    mov     x0, #10
    mul     x3, x2, x0

    // N3) Identity (C = 1).
    mov     x0, #1
    mul     x3, x2, x0

    // N4) MUL does not read the MOV destination (x1 vs x0).
    mov     x0, #8
    mul     x3, x2, x1

    // N5) Intervening unrelated instruction closes the chain.
    mov     x0, #8
    add     x5, x5, x6
    mul     x3, x2, x0

    // P) MADD with explicit Ra != XZR (not the MUL alias): the MOV +
    //    MADD/MSUB check's positive -- the accumulator rides along
    //    and the multiply becomes a shifted operand.
    mov     x0, #8
    madd    x3, x2, x0, x4          // -> add x3, x4, x2, lsl #3

    // N7) Both operands are the constant register (squaring it): the
    //     LSL rewrite would still read x0, so the MOV could never be
    //     deleted; the real rewrite is materializing the folded value.
    mov     x0, #8
    mul     x3, x0, x0

    ret
