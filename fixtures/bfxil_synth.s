// Integration fixture for check_bfxil_synth.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: 3-instruction synthesis of BFXIL.
    //   AND x3, x3, #~0xff   (clear low 8 of x3)
    //   AND x4, x5, #0xff    (isolate low 8 of x5)
    //   ORR x3, x3, x4       (combine)
    //   -> bfxil x3, x5, #0, #8
    and     x3, x3, #0xFFFFFFFFFFFFFF00
    and     x4, x5, #0xFF
    orr     x3, x3, x4

    // Positive: reversed order of the two ANDs is also accepted.
    and     x6, x7, #0xFFFF
    and     x8, x8, #0xFFFFFFFFFFFF0000
    orr     x8, x8, x6

    // Negative: ORR uses a different Rt (Rt != either isolate's Rd).
    and     x10, x10, #0xFFFFFFFFFFFFFF00
    and     x11, x12, #0xFF
    orr     x10, x10, x13

    // Negative: intervening instruction breaks adjacency.
    and     x14, x14, #0xFFFFFFFFFFFFFF00
    add     x20, x20, #1
    and     x15, x16, #0xFF
    orr     x14, x14, x15

    ret
