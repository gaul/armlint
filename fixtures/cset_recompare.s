// Integration fixture for check_cset_recompare.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: the materialized-condition select shape -- the
    // boolean is re-compared for the CSEL although the flags still
    // hold the original condition. The trailing CMP kills the
    // re-tested flags.
    cmp     w0, w1
    cset    w8, lt
    cmp     w8, #0
    csel    w2, w3, w4, eq
    cmp     w5, w6

    // Positive: NE consumer, X-width select, RET as the flags' end.
    cset    w9, hi
    cmp     w9, #0
    csel    x2, x3, x4, ne
    ret

    // Negative: an LT consumer reads the manufactured N/C/V bits.
    cset    w10, eq
    cmp     w10, #0
    csel    w2, w3, w4, lt
    cmp     w5, w6

    // Negative: a second flag reader after the select.
    cset    w11, eq
    cmp     w11, #0
    csel    w2, w3, w4, eq
    csel    w5, w6, w7, ne
    ret

    // Negative: a read-modify-write of the temp in the gap (the
    // boolean-XOR shape Rust's median3 emits) -- the zero-test
    // observes the EOR's result, not the CSET's.
    cmp     w0, w1
    cset    w12, lo
    eor     w12, w13, w12
    cmp     w12, #0
    csel    x2, x3, x4, ne
    ret

    // Negative: a CSEL merging over the temp (the three-way-compare
    // materialization) rewrites it too, though it reads only the
    // still-live flags.
    cmp     w0, w1
    cset    w12, mi
    csel    w12, w13, w12, eq
    cmp     w12, #0
    csel    x2, x3, x4, ne
    ret

    // Positive: a gap instruction that merely reads the temp leaves
    // it intact.
    cmp     w0, w1
    cset    w8, lt
    add     x1, x8, x3
    cmp     w8, #0
    csel    w2, w3, w4, eq
    cmp     w5, w6
    ret
