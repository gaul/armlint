// Integration fixture for check_and_known_noop.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) A tagged pointer's tag tested, then cleared: already zero.
    tst     x9, #3
    b.ne    9f
    and     x9, x9, #0xfffffffffffffffc
    ret

    // 2) A mask re-applied across unrelated work.
    and     w7, w7, #4
    adds    w6, w6, #1
    b.vs    9f
    and     w7, w7, #4
    ret

    // 3) A byte masked wider than a byte, out of place: a copy.
    ldrb    w9, [x0]
    add     x1, x1, #1
    and     w10, w9, #0x1ff
    ret

    // 4) A bound a compare set: x0 is below 100.
    cmp     x0, #100
    b.hs    9f
    and     x1, x0, #0x7f
    ret

    // 5) A bit TBNZ found clear, and a W form whose top half the load
    //    already zeroed.
    ldr     w9, [x0]
    tbnz    w9, #31, 9f
    and     w9, w9, #0x7fffffff
    ret

    // Negatives:
    // 6) Nothing known of the input.
    and     x1, x0, #0x7f
    ret

    // 7) A mask right after the mask that bounded it (the AND/extend
    //    chain's pair).
    and     w8, w9, #0x3f
    and     w10, w8, #0xff
    ret

    // 8) A W form in place over a top half nothing zeroed.
    tst     w0, #0x80
    b.ne    9f
    and     w0, w0, #0xffffff7f
    ret

    // 9) The zero-extension check_redundant_zext reports.
    ldrb    w9, [x0]
    add     x1, x1, #1
    and     w9, w9, #0xff
    ret

    // 10) A side entry onto the mask.
    tst     x9, #3
    b.ne    9f
1:
    and     x9, x9, #0xfffffffffffffffc
    cbz     x0, 1b
9:
    ret
