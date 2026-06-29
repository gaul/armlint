// Integration fixture for check_stp_wzr_to_str_xzr.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: STP wzr, wzr (signed offset, no writeback) is one
    // STR xzr. The W-form offset is 8-aligned here.
    stp     wzr, wzr, [x0, #16]    // -> str xzr, [x0, #16]

    // Positive: an odd 4-byte slot needs the unscaled STUR xzr.
    stp     wzr, wzr, [x1, #4]     // -> stur xzr, [x1, #4]

    // Positive: a negative offset also needs STUR xzr.
    stp     wzr, wzr, [x2, #-8]    // -> stur xzr, [x2, #-8]

    // Positive: SP base.
    stp     wzr, wzr, [sp]         // -> str xzr, [sp]

    // Negative: the 64-bit STP xzr, xzr zeroes 16 bytes and has no
    // single-GPR-store equivalent.
    stp     xzr, xzr, [x3]

    // Negative: only one source is the zero register.
    stp     wzr, w4, [x5]
    stp     w4, wzr, [x5, #8]

    // Negative: writeback forms update the base, so they are not
    // equivalent to a plain STR.
    stp     wzr, wzr, [x6, #16]!
    stp     wzr, wzr, [x7], #16

    ret
