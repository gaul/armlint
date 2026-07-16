// Integration fixture for check_cmp_cset_sign.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (each pair is followed by a fresh compare, whose
    // NZCV overwrite commits the deferred finding):
    // 1) X-form boolean: shift the sign bit down.
    cmp     x1, #0
    cset    x0, lt                  // -> lsr x0, x1, #63
    cmp     x9, #0

    // 2) W form.
    cmp     w1, #0
    cset    w0, lt                  // -> lsr w0, w1, #31
    cmp     w9, #0

    // 3) MI reads the same bit: V = 0 after a zero compare, so
    //    LT = MI = N.
    cmp     x1, #0
    cset    x0, mi                  // -> lsr x0, x1, #63
    cmp     x9, #0

    // 4) CSETM materializes the mask instead of the bit.
    cmp     x1, #0
    csetm   x0, lt                  // -> asr x0, x1, #63
    cmp     x9, #0

    // Negatives:
    // N1) GE is the complement: lsr + eor #1 saves nothing.
    cmp     x1, #0
    cset    x0, ge
    cmp     x9, #0

    // N2) EQ reads Z, not the sign.
    cmp     x1, #0
    cset    x0, eq
    cmp     x9, #0

    // N3) A nonzero immediate is not the sign test.
    cmp     x1, #1
    cset    x0, lt
    cmp     x9, #0

    // N4) Width mismatch: an X CSETM after a W compare would need a
    //     64-bit mask no single W-form shift produces.
    cmp     w1, #0
    csetm   x0, lt
    cmp     x9, #0

    // N5) A later flag reader keeps the compare alive.
    cmp     x1, #0
    cset    x0, lt
    b.lt    1f
1:
    // 5) W CSETM of MI, committed by the RET: the function ends, so
    //    NZCV is provably dead.
    cmp     w2, #0
    csetm   w3, mi                  // -> asr w3, w2, #31
    ret
