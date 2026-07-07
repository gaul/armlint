// Integration fixture for check_tst_cset.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: bit test materialised into a bool; the TST's flags
    // die at the following compare, so the deferred finding emits.
    tst     w0, #0x10
    cset    w8, ne
    cmp     w1, w2

    // Positive: X-form high bit.
    tst     x1, #0x10000000000
    cset    x9, ne
    cmp     w1, w2

    // Positive: MI reads the sign bit the TST isolated.
    tst     w2, #0x80000000
    cset    w10, mi
    cmp     w1, w2

    // Positive: CSETM is the sign-extracting SBFX.
    tst     w3, #0x1
    csetm   w11, ne
    cmp     w1, w2

    // Negative: EQ would need an inverted extract.
    tst     w4, #0x10
    cset    w12, eq
    cmp     w1, w2

    // Negative: the flags are read again before dying -- the TST
    // must stay.
    tst     w5, #0x10
    cset    w13, ne
    b.eq    1f
1:  ret
