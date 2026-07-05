// Integration fixture for check_bfxil_synth.
//
// The BFXIL/BFI rewrite drops the isolate's temp register, so the
// finding is deferred until that temp is proven dead. Each positive
// below is followed by a "mov <temp>, #1" that overwrites the temp, so
// the deferred finding is emitted (and, since the pending-finding slot
// holds only one at a time, so that back-to-back patterns don't clobber
// each other before emitting).

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: 3-instruction synthesis of BFXIL.
    //   AND x3, x3, #~0xff   (clear low 8 of x3)
    //   AND x4, x5, #0xff    (isolate low 8 of x5 into temp x4)
    //   ORR x3, x3, x4       (combine)
    //   -> bfxil x3, x5, #0, #8
    and     x3, x3, #0xFFFFFFFFFFFFFF00
    and     x4, x5, #0xFF
    orr     x3, x3, x4
    mov     x4, #1                          // temp x4 dead

    // Positive: reversed order of the two ANDs is also accepted.
    and     x6, x7, #0xFFFF
    and     x8, x8, #0xFFFFFFFFFFFF0000
    orr     x8, x8, x6
    mov     x6, #1                          // temp x6 dead

    // Negative: ORR uses a different Rt (Rt != either isolate's Rd).
    and     x10, x10, #0xFFFFFFFFFFFFFF00
    and     x11, x12, #0xFF
    orr     x10, x10, x13

    // Negative: intervening instruction breaks adjacency.
    and     x14, x14, #0xFFFFFFFFFFFFFF00
    add     x20, x20, #1
    and     x15, x16, #0xFF
    orr     x14, x14, x15

    // Positive (BFI, lsb > 0): clear x0[15:8], isolate x1's low 8 bits
    // into position 8, combine.  -> bfi x0, x1, #8, #8
    and     x0, x0, #0xFFFFFFFFFFFF00FF
    ubfiz   x2, x1, #8, #8
    orr     x0, x0, x2
    mov     x2, #1                          // temp x2 dead

    // Positive (BFI, W-form, reversed order).  -> bfi w3, w5, #4, #4
    ubfiz   w4, w5, #4, #4
    and     w3, w3, #0xFFFFFF0F
    orr     w3, w3, w4
    mov     w4, #1                          // temp w4 dead

    // Positive (BFI, field reaching the top bit). The UBFIZ encodes as
    // LSL #56.  -> bfi x6, x7, #56, #8
    and     x6, x6, #0x00FFFFFFFFFFFFFF
    ubfiz   x8, x7, #56, #8
    orr     x6, x6, x8
    mov     x8, #1                          // temp x8 dead

    // Negative (BFI): position mismatch (clear at 8, isolate at 4).
    and     x9, x9, #0xFFFFFFFFFFFF00FF
    ubfiz   x10, x11, #4, #8
    orr     x9, x9, x10

    ret
