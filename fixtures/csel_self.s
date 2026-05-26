// Integration fixture for check_csel_self.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: CSEL Xd, Xn, Xn, cond -- both branches equal, cond
    // is ignored, equivalent to MOV Xd, Xn.
    csel    x0, x1, x1, eq

    // Positive: W-form.
    csel    w2, w3, w3, ne

    // Positive: any cond field is fine -- the fold doesn't depend on
    // which condition is chosen because both branches are equal.
    csel    x4, x5, x5, lt

    // Negative: CSEL with different Rn and Rm is a genuine select.
    csel    x6, x7, x8, eq

    // Negative: CSINC, CSINV, CSNEG with Rn == Rm are NOT identities
    // (the "else" branch transforms the value).
    csinc   x9, x10, x10, eq

    ret
