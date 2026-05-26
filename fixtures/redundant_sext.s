// Integration fixture for check_redundant_sext.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: LDRSB Wt (S=8, W=32) + SXTB Wd, Wd -- already
    // sign-extended through bit 32.
    ldrsb   w0, [x1]
    sxtb    w0, w0

    // Positive: LDRSH Wt + SXTH Wd, Wd.
    ldrsh   w2, [x3]
    sxth    w2, w2

    // Positive: LDRSW Xt + SXTW Xd, Wd.
    ldrsw   x4, [x5]
    sxtw    x4, w4

    // Positive: SXTB Wd, Wn + SXTH Wd, Wd. The first establishes S=8,
    // the second clears bits >= 16 by sign-extending from bit 15 --
    // already sign-replicated by the first.
    sxtb    w6, w7
    sxth    w6, w6

    // Negative: width mismatch. LDRSB Wt sign-extends only through
    // bit 31; an X-form SXTB writing Xd is NOT redundant because the
    // W-form write zeroed X[63:32] (not sign-extended).
    ldrsb   w8, [x9]
    sxtb    x8, w8

    // Negative: producer is zero-extending (LDRB), consumer is
    // sign-extending -- bits >= 8 are zero, not sign-replicated.
    ldrb    w10, [x11]
    sxtb    w10, w10

    // Negative: consumer's Rn != producer's Rd.
    ldrsb   w12, [x13]
    sxtb    w12, w14

    ret
