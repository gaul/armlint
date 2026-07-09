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

    // ADD + CMN family: CMN is ADDS ZR of the same operands, so the
    // identical bit-exact-flags argument applies.

    // P) ADD-first order.
    add     x0, x1, x2
    cmn     x1, x2                  // -> adds x0, x1, x2

    // P) CMN-first order, W-form.
    cmn     w3, w4
    add     w0, w3, w4              // -> adds w0, w3, w4

    // P) Immediate form.
    add     x0, x1, #16
    cmn     x1, #16                 // -> adds x0, x1, #16

    // P) Swapped commutative operands: cmn x6, x5 sums the same
    //    values as the ADD, so all four flags match ADDS.
    add     x0, x5, x6
    cmn     x6, x5                  // -> adds x0, x5, x6

    // P) Swapped, compare-first order (this CMN replaces the pending
    //    compare the previous one opened).
    cmn     x8, x7
    add     x0, x7, x8              // -> adds x0, x7, x8

    // N5) The swap needs plain operands: a shifted ADD sums different
    //     values than the swapped plain CMN.
    add     x0, x5, x6, lsl #1
    cmn     x6, x5

    // N6) Cross-family: ADD + CMP of the same operands compares a
    //     difference, not the sum; never folds.
    add     x0, x3, x4
    cmp     x3, x4

    ret
