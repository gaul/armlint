// Integration fixture for check_redundant_cmp_after_s_variant.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: SUBS sets Z = (Rd == 0); the following CMP Rd, #0
    // recomputes the same Z. Followed by B.EQ to commit the
    // deferred finding (the forward NZCV-liveness scan needs a safe
    // stopper or branch consumer).
    subs    x0, x1, x2
    cmp     x0, #0
    b.eq    1f

    // Positive: ANDS + CMP Rd, XZR + B.NE.
    ands    x3, x4, x5
    cmp     x3, xzr
    b.ne    1f

    // Positive: ADDS + TST Rd, Rd + B.EQ.
    adds    w6, w7, w8
    tst     w6, w6
    b.eq    1f

    // Negative: S-variant + CMP of a DIFFERENT register -- no
    // redundancy.
    subs    x9, x10, x11
    cmp     x12, #0
    b.eq    1f

    // Negative: non-S ALU + CMP -- the ADD does not set flags, so
    // the CMP is necessary.
    add     x13, x14, x15
    cmp     x13, #0
    b.eq    1f

1:  ret
