// Integration fixture for check_sub_cmp_fold. The fold is flag-exact
// (CMP is SUBS ZR of the same operands, and NZCV never depends on
// Rd), so findings emit at the pair with no liveness gating.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) SUB-first order.
    sub     x0, x1, x2
    cmp     x1, x2                  // -> subs x0, x1, x2

    // 2) CMP-first order.
    cmp     x3, x4
    sub     x0, x3, x4              // -> subs x0, x3, x4

    // 3) W-form.
    sub     w0, w1, w2
    cmp     w1, w2                  // -> subs w0, w1, w2

    // 4) Shifted operands (must match exactly).
    sub     x0, x1, x2, lsl #3
    cmp     x1, x2, lsl #3          // -> subs x0, x1, x2, lsl #3

    // 5) Immediate form.
    sub     x0, x1, #16
    cmp     x1, #16                 // -> subs x0, x1, #16

    // 6) Extended-register form.
    sub     x0, x1, w2, uxtw
    cmp     x1, w2, uxtw            // -> subs x0, x1, w2, uxtw

    // 7) CMP-first with Rd == Rn: fine, the CMP wrote nothing.
    cmp     x1, x2
    sub     x1, x1, x2              // -> subs x1, x1, x2

    // Negatives:
    // N1) SUB-first with Rd == Rn: the CMP read the difference, not
    //     the original operand.
    sub     x1, x1, x2
    cmp     x1, x2

    // N2) Reversed compare operands: subtraction is not symmetric.
    sub     x0, x5, x6
    cmp     x6, x5

    // N3) Shift amount mismatch.
    sub     x0, x1, x2, lsl #3
    cmp     x1, x2, lsl #2

    // N4) SUBS producer: the flags are already set (a redundant
    //     identical-operand CMP after SUBS is a separate,
    //     unimplemented finding).
    subs    x0, x1, x2
    cmp     x1, x2

    ret
