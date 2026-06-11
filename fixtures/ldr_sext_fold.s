// Integration fixture for check_ldr_sext_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: byte load + in-place sign-extend = LDRSB.
    ldrb    w3, [x1]
    sxtb    w3, w3                  // -> ldrsb w3, [x1]

    // Positive: X-form consumer -- the sign-extension widens to 64
    // bits, so the fold is the Xt form of the load.
    ldrb    w3, [x1]
    sxtb    x3, w3                  // -> ldrsb x3, [x1]

    // Positive: halfword load at an offset.
    ldrh    w4, [x1, #2]
    sxth    w4, w4                  // -> ldrsh w4, [x1, #2]

    // Positive: word load + sxtw = LDRSW.
    ldr     w2, [sp, #4]
    sxtw    x2, w2                  // -> ldrsw x2, [sp, #4]

    // Negative: sxth after ldrb sign-extends from a bit the load
    // zeroed; not this fold.
    ldrb    w3, [x1]
    sxth    w3, w3

    // Negative: sxtb after a word load would shrink the memory access
    // from 4 bytes to 1.
    ldr     w2, [x1]
    sxtb    w2, w2

    // Negative: the sign-extend reads/writes a different register.
    ldrb    w3, [x1]
    sxtb    w5, w5

    // Positive: W-form sign-extending load re-widened to X -- the
    // pair is exactly the X-form load.
    ldrsb   w8, [x9]
    sxtb    x8, w8                  // -> ldrsb x8, [x9]

    // Positive: threshold above the access width is still exact (bits
    // 8..31 of the LDRSB result are sign copies).
    ldrsb   w8, [x9]
    sxtw    x8, w8                  // -> ldrsb x8, [x9]

    // Positive: halfword form, offset carries over.
    ldrsh   w8, [x9, #2]
    sxth    x8, w8                  // -> ldrsh x8, [x9, #2]

    // Negative: threshold below the access width -- bit 7 of a loaded
    // halfword is data, not its sign.
    ldrsh   w8, [x9]
    sxtb    x8, w8

    // Negative for THIS check: W-form consumer after the W-form
    // sign-extending load is a no-op; the redundant-sext check flags
    // it instead.
    ldrsb   w8, [x9]
    sxtb    w8, w8

    ret
