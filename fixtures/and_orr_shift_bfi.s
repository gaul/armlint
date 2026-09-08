// Integration fixture for check_and_orr_shift_bfi.
//
// A bitfield insert whose field reaches the top of the register needs
// no isolate: the ORR's shift truncates the merged source, so the
// in-place AND and the shifted ORR are the whole idiom. The ORR
// overwrites the masked value on the spot, so nothing defers.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: the UTF-8 continuation-byte shape, as
    // core::str::next_code_point and Gecko's decoder emit it.
    //   -> bfi w8, w10, #6, #26
    and     w8, w8, #0x3f
    orr     w8, w8, w10, lsl #6

    // Positive: X-form.  -> bfi x1, x2, #6, #58
    and     x1, x1, #0x3f
    orr     x1, x1, x2, lsl #6

    // Positive: a single-bit field at the top.  -> bfi w3, w4, #31, #1
    and     w3, w3, #0x7fffffff
    orr     w3, w3, w4, lsl #31

    // Positive: the LSR mirror.  -> bfxil w5, w6, #26, #6
    and     w5, w5, #0xffffffc0
    orr     w5, w5, w6, lsr #26

    // Negative: the AND is not in place; w7 would first have to
    // hold w9.
    and     w7, w9, #0x3f
    orr     w7, w7, w10, lsl #6

    // Negative: the ORR is not in place; w11 keeps the masked value.
    and     w11, w11, #0x3f
    orr     w12, w11, w10, lsl #6

    // Negative: mask narrower than the shift. Bit 5 is cleared here
    // but BFI would keep it.
    and     w13, w13, #0x1f
    orr     w13, w13, w10, lsl #6

    // Negative: mask wider than the shift. Bit 6 is merged here but
    // BFI would overwrite it.
    and     w14, w14, #0x7f
    orr     w14, w14, w10, lsl #6

    // Negative: the merged register is the masked one.
    and     w15, w15, #0x3f
    orr     w15, w15, w15, lsl #6

    // Negative: ASR brings in sign bits no insert expresses.
    and     w16, w16, #0x3f
    orr     w16, w16, w10, asr #6

    // Negative: ANDS -- the rewrite would lose its flags.
    ands    w19, w19, #0x3f
    orr     w19, w19, w10, lsl #6

    // Negative: the ORR is a branch target, so the AND is skipped on
    // that path.
    cbz     w17, 1f
    and     w18, w18, #0x3f
1:
    orr     w18, w18, w10, lsl #6

    ret
