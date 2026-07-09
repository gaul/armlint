// Integration fixture for check_fcsel_self.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives: both branches select the same bit pattern, so the
    // condition is irrelevant and the select is a register copy.
    // 1) Double precision.
    fcsel   d0, d1, d1, ne          // -> fmov d0, d1

    // 2) Single precision, another condition.
    fcsel   s2, s3, s3, lt          // -> fmov s2, s3

    // 3) Fully self-referential: still exact (both spellings rewrite
    //    d4 and zero the upper lane).
    fcsel   d4, d4, d4, eq          // -> fmov d4, d4

    // Negatives:
    // N1) Distinct operands select genuinely different values.
    fcsel   d0, d1, d2, ne

    ret
