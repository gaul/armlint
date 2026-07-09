// Integration fixture for check_mov_madd_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (the constant register dies at the trailing mov, so
    // the deferred finding emits):
    // 1) MADD: the accumulator rides along, the multiply becomes a
    //    shifted operand.
    mov     x8, #8
    madd    x0, x1, x8, x2          // -> add x0, x2, x1, lsl #3
    mov     x8, #9

    // 2) MSUB.
    mov     x8, #8
    msub    x0, x1, x8, x2          // -> sub x0, x2, x1, lsl #3
    mov     x8, #9

    // 3) The multiply commutes: the chain may sit in the Rn slot.
    mov     x8, #16
    madd    x0, x8, x1, x2          // -> add x0, x2, x1, lsl #4
    mov     x8, #9

    // 4) A multiplier of 1 folds to the plain ADD.
    mov     x8, #1
    madd    x0, x1, x8, x2          // -> add x0, x2, x1
    mov     x8, #9

    // 5) W-form.
    mov     w8, #4
    msub    w0, w1, w8, w2          // -> sub w0, w2, w1, lsl #2
    mov     w8, #9

    // 6) Structural kill: the MAC overwrites the constant register.
    mov     x8, #32
    madd    x8, x1, x8, x2          // -> add x8, x2, x1, lsl #5

    // Negatives:
    // N1) Non-power-of-two multiplier.
    mov     x8, #6
    madd    x0, x1, x8, x2
    mov     x8, #9

    // N2) The accumulator is the constant register: the rewrite
    //     would still read it.
    mov     x8, #8
    madd    x0, x1, x8, x8
    mov     x8, #9

    // N3) Fresh destination with no later kill: the constant is
    //     never proven dead.
    mov     x9, #8
    madd    x0, x1, x9, x2

    ret
