// Integration fixture for check_mov_logic_known_bits.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) A three-bit field tested for two of its bits: 5 is not a
    //    bitmask immediate, but with bits 3+ known clear 0xfffffffd
    //    masks the same.
    and     w8, w8, #7
    mov     w9, #5
    and     w9, w8, w9
    ret

    // 2) The TST alias, the constant register dying in the CSET.
    and     w8, w8, #7
    mov     w9, #5
    tst     w8, w9
    cset    w9, ne
    ret

    // 3) X form on a six-bit value.
    and     x8, x8, #0x3f
    mov     x9, #0x23
    and     x9, x8, x9
    ret

    // 4) BIC: ~5 has two gaps, but only bit 1 survives on three bits.
    and     w8, w8, #7
    mov     w9, #5
    bic     w9, w8, w9
    ret

    // 5) The bound from a compare's fall-through.
    cmp     w8, #8
    b.hs    9f
    mov     w9, #5
    and     w9, w8, w9
    ret

    // Negatives:
    // 6) A byte leaves bits 3..7 open: no run fits.
    ldrb    w8, [x0]
    mov     w9, #5
    and     w9, w8, w9
    ret

    // 7) Nothing known of the input.
    mov     w9, #5
    and     w9, w8, w9
    ret

    // 8) ORR has no free bits.
    and     w8, w8, #7
    mov     w9, #5
    orr     w9, w8, w9
    ret

    // 9) A side entry onto the operation.
    and     w8, w8, #7
    mov     w9, #5
1:
    and     w9, w8, w9
    cbz     x0, 1b
9:
    ret
