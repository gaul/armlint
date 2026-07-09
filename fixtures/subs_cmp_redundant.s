// Integration fixture for check_subs_cmp_redundant.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives: the flag-setting producer already computed exactly
    // these flags; the compare recomputes the same NZCV and is
    // dropped outright.
    // 1) SUBS + CMP.
    subs    x0, x1, x2
    cmp     x1, x2                  // -> drop

    // 2) ADDS + swapped CMN (commutative sum).
    adds    x0, x5, x6
    cmn     x6, x5                  // -> drop

    // 3) Immediate form, W width.
    subs    w0, w1, #16
    cmp     w1, #16                 // -> drop

    // 4) Adjacent duplicate compares (the producer is itself a
    //    compare).
    cmp     x3, x4
    cmp     x3, x4                  // -> drop the second

    // Negatives:
    // N1) The compare reads the producer's destination: that is the
    //     result, not the original operand.
    subs    x1, x1, x2
    cmp     x1, x2

    // N2) Different operands: a genuine second compare.
    subs    x0, x1, x2
    cmp     x1, x3

    ret
