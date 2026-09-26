// Integration fixture for check_lsr_and_to_ubfx.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: LSR + AND low-mask -> UBFX.
    //   x0 = (x1 >> 8) & 0xFF -> ubfx x0, x1, #8, #8.
    lsr     x0, x1, #8
    and     x0, x0, #0xFF           // -> ubfx x0, x1, #8, #8

    // Positive: wider mask, width capped at datasize - shift.
    //   x2 = (x3 >> 32) & 0xFFFFFFFF -> ubfx x2, x3, #32, #32.
    lsr     x2, x3, #32
    and     x2, x2, #0xFFFFFFFF     // -> ubfx x2, x3, #32, #32

    // Positive: W-form.
    lsr     w4, w5, #4
    and     w4, w4, #0xF            // -> ubfx w4, w5, #4, #4

    // Negative: AND mask is not a low-mask (not (1<<w)-1).
    lsr     x6, x7, #8
    and     x6, x6, #0xF0

    // Negative: consumer's Rn != LSR's Rd.
    lsr     x8, x9, #8
    and     x8, x10, #0xFF

    // Negative: intervening instruction.
    lsr     x11, x12, #8
    add     x20, x20, #1
    and     x11, x11, #0xFF

    // Positive: ASR, the field below the sign fill. JavaScript's
    // arithmetic `(x >> 8) & 0xff` as SpiderMonkey and JavaScriptCore
    // emit it.
    asr     w13, w14, #8
    and     w13, w13, #0xff         // -> ubfx w13, w14, #8, #8

    // Positive: an ASR field reaching the top is LSR -- gc's
    // Slicemask(x) & 1.
    asr     x15, x15, #63
    and     x15, x15, #0x1          // -> lsr x15, x15, #63

    // Negative: the mask keeps ASR's sign-fill bits (24 + 16 > 32).
    asr     w16, w17, #24
    and     w16, w16, #0xffff

    // Positive, out of place: the shift's result dies at the MOVZ.
    lsr     w9, w4, #24
    and     w10, w9, #0xff          // -> ubfx w10, w4, #24, #8
    movz    w9, #1

    // Negative, out of place: the shift's result is read again.
    asr     w19, w21, #16
    and     w22, w19, #0xff
    add     w23, w19, w19

    ret
