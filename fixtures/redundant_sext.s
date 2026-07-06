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

    // Negative for THIS check: width mismatch. LDRSB Wt sign-extends
    // only through bit 31; an X-form SXTB writing Xd is NOT redundant
    // because the W-form write zeroed X[63:32] (not sign-extended).
    // The pair flags under check_ldr_sext_fold instead
    // (-> ldrsb x8, [x9]).
    ldrsb   w8, [x9]
    sxtb    x8, w8

    // Negative for THIS check: producer is zero-extending (LDRB), so
    // bits >= 8 are zero, not sign-replicated, and the SXTB is doing
    // real work. The pair flags under check_ldr_sext_fold instead
    // (-> ldrsb w10, [x11]).
    ldrb    w10, [x11]
    sxtb    w10, w10

    // Negative: consumer's Rn != producer's Rd.
    ldrsb   w12, [x13]
    sxtb    w12, w14

    // Positive: general SBFX -- the extracted 8-bit field's sign is
    // already replicated through bit 31 (S = 8).
    sbfx    w15, w16, #4, #8
    sxtb    w15, w15

    // Positive: dead in-place sign-extension -- the AND keeps exactly
    // the 5 bits the SBFX extended, so the SBFX can be dropped.
    sbfx    w17, w17, #0, #5
    and     w17, w17, #0x1f

    // Negative: S = 12 > 8 -- bit 7 is field data, so the SXTB
    // narrows the field and does real work.
    sbfx    w20, w21, #4, #12
    sxtb    w20, w20

    ret
