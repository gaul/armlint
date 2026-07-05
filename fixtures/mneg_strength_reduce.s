// Integration fixture for check_mneg_strength_reduce.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) C = 1 -> NEG (no shift).
    mov     x0, #1
    mneg    x3, x2, x0          // -> neg x3, x2

    // 2) C = 2^N -> NEG with LSL.
    mov     x0, #8
    mneg    x3, x2, x0          // -> neg x3, x2, lsl #3

    // 3) Commutativity: Rn == mov_rd.
    mov     x0, #2
    mneg    x3, x0, x2          // -> neg x3, x2, lsl #1

    // 4) W form.
    mov     w0, #4
    mneg    w3, w2, w0          // -> neg w3, w2, lsl #2

    // 5) C = 2^N - 1 -> SUB Xd, Xn, Xn, LSL #N.
    mov     x0, #3
    mneg    x3, x2, x0          // -> sub x3, x2, x2, lsl #2

    // 6) C = 2^N - 1 (larger N).
    mov     x0, #7
    mneg    x3, x2, x0          // -> sub x3, x2, x2, lsl #3

    // 7) C = 2^N - 1 (even larger).
    mov     x0, #15
    mneg    x3, x2, x0          // -> sub x3, x2, x2, lsl #4

    // 8) Wide power-of-2 via shifted MOVZ.
    movz    x0, #1, lsl #32
    mneg    x3, x2, x0          // -> neg x3, x2, lsl #32

    // Negatives:
    // N1) 2^N + 1 (not folded for MNEG).
    mov     x0, #5
    mneg    x3, x2, x0

    // N2) 2^N + 1 (larger).
    mov     x0, #9
    mneg    x3, x2, x0

    // N3) Arbitrary.
    mov     x0, #10
    mneg    x3, x2, x0

    // N4) MSUB with explicit Ra (not MNEG alias).
    mov     x0, #8
    msub    x3, x2, x0, x4

    // Sanity: a MUL still fires from the MUL check. The trailing
    // "mov x0" overwrites the constant so the deferred MUL fold is
    // emitted (it deletes the MOV, so the fold waits until x0 is dead).
    mov     x0, #8
    mul     x3, x2, x0          // -> lsl x3, x2, #3 (from MUL check)
    mov     x0, #1

    ret
