// Integration fixture for check_tst_branch.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: TST Rn, #(1<<3) ; B.EQ -> TBZ Rn, #3, target.
    tst     x0, #8
    b.eq    1f

    // Positive: TST + B.NE -> TBNZ.
    tst     x1, #0x10
    b.ne    1f

    // Positive: bit 63 (sign bit, X-form).
    tst     x2, #0x8000000000000000
    b.eq    1f

    // Positive: W-form TST with bit 31.
    tst     w3, #0x80000000
    b.ne    1f

    // Negative: multi-bit mask -- TBZ tests a single bit only.
    tst     x4, #0x3
    b.eq    1f

    // Negative: TST with non-bitmask -- skipped here because the
    // assembler rejects encoding-invalid immediates anyway.

    // Negative: branch other than B.EQ/B.NE.
    tst     x5, #8
    b.lt    1f

1:  ret
