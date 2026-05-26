// Integration fixture for check_lsl_lsr_to_ubfx.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: LSL + LSR with b > a -> UBFX (zero-extract).
    //   x0 = x1[59..4] zero-extended to 56 bits.
    lsl     x0, x1, #4
    lsr     x0, x0, #8              // -> ubfx x0, x1, #4, #56

    // Positive: LSL + ASR same shift -> SBFX (sign-extract). Here
    //   x2 = sign-extend(x3[55..0]) into 56 valid bits.
    lsl     x2, x3, #8
    asr     x2, x2, #8              // -> sbfx x2, x3, #0, #56

    // Positive: LSL + LSR with b < a -> UBFIZ (zero insertion).
    lsl     x4, x5, #16
    lsr     x4, x4, #4              // -> ubfiz x4, x5, #12, #48

    // Positive: W-form pair.
    lsl     w6, w7, #8
    lsr     w6, w6, #16             // -> ubfx w6, w7, #8, #16

    // Negative: consumer's Rn != LSL's Rd.
    lsl     x8, x9, #4
    lsr     x8, x10, #8

    // Negative: consumer's Rd != LSL's Rd.
    lsl     x11, x12, #4
    lsr     x13, x11, #8

    // Negative: intervening instruction expires state.
    lsl     x14, x15, #4
    add     x20, x20, #1
    lsr     x14, x14, #8

    ret
