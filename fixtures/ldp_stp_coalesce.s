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

    ret
