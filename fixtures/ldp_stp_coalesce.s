// Integration fixture for check_ldp_stp_coalesce.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: two adjacent X-form LDRs at consecutive offsets ->
    // LDP x0, x1, [x10, #0].
    ldr     x0, [x10]
    ldr     x1, [x10, #8]

    // Positive: reverse order (higher offset first) -> LDP in
    // canonical low-first form.
    ldr     x3, [x11, #16]
    ldr     x2, [x11, #8]

    // Positive: W-form STR pair -> STP.
    str     w4, [x12]
    str     w5, [x12, #4]

    // Positive: LDRSW pair -> LDPSW.
    ldrsw   x6, [x13]
    ldrsw   x7, [x13, #4]

    // Negative: different base registers.
    ldr     x8, [x14]
    ldr     x9, [x15, #8]

    // Negative: non-consecutive offsets.
    ldr     x16, [x17]
    ldr     x18, [x17, #16]

    // Negative: width mismatch (W and X).
    ldr     w19, [x20]
    ldr     x21, [x20, #8]

    // Negative: direction mismatch (load then store).
    ldr     x22, [x23]
    str     x24, [x23, #8]

    // Positive: SIMD&FP D pair. An FP Rt numerically equal to the
    // integer base (d2 vs x2 here would be fine too) is not a base
    // clobber -- different register files.
    ldr     d0, [x2]
    ldr     d1, [x2, #8]            // -> ldp d0, d1, [x2]

    // Positive: Q store pair.
    str     q2, [x2]
    str     q3, [x2, #16]           // -> stp q2, q3, [x2]

    // Positive: S pair in reverse offset order.
    ldr     s4, [x2, #4]
    ldr     s5, [x2]                // -> ldp s5, s4, [x2]

    // Negative: FP size mismatch (D then S).
    ldr     d6, [x2]
    ldr     s7, [x2, #2]

    // Negative: B loads have no pair form.
    ldr     b0, [x2]
    ldr     b1, [x2, #1]

    // Positive: two adjacent W-form zero stores consolidate into a
    // single STR xzr rather than STP wzr, wzr.
    str     wzr, [x12, #8]
    str     wzr, [x12, #12]        // -> str xzr, [x12, #8]

    // Positive: an odd 4-byte slot needs the unscaled STUR xzr.
    str     wzr, [x12, #4]
    str     wzr, [x12, #8]         // -> stur xzr, [x12, #4]

    // Positive: a mixed pair (one wzr source) still coalesces into a
    // plain STP; the zero operand renders as wzr, not "w31".
    str     wzr, [x12]
    str     w5, [x12, #4]          // -> stp wzr, w5, [x12]

    // Positive: a repeated STORE source pairs fine -- STP has no
    // Rt1 != Rt2 restriction (only loads are CONSTRAINED
    // UNPREDICTABLE).
    str     x5, [sp]
    str     x5, [sp, #8]           // -> stp x5, x5, [sp]

    // Positive: FP repeated source.
    str     d0, [x2]
    str     d0, [x2, #8]           // -> stp d0, d0, [x2]

    // Positive: X-form zero stores span 16 bytes -- no single store
    // covers that -- so they fold to the canonical 16-byte zero
    // store.
    str     xzr, [x12]
    str     xzr, [x12, #8]         // -> stp xzr, xzr, [x12]

    // Negative: a repeated LOAD destination never folds (LDP with
    // Rt1 == Rt2 is CONSTRAINED UNPREDICTABLE).
    ldr     x5, [sp]
    ldr     x5, [sp, #8]

    ret
