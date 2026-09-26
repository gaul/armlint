// Integration fixture for check_and_ext_chain.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives, in place: the consumer overwrites the producer's
    // destination, so deleting the producer needs no liveness proof.

    // P1) The consumer reads only bits the producer passed through --
    //     rustc's UTF-8 decoding, the .NET 11 post's widen-then-
    //     truncate, and SpiderMonkey's zero-extension before a mask.
    and     w8, w8, #0xff
    and     w8, w8, #0x3f               // -> and w8, w8, #0x3f
    sxtw    x0, w1
    sxtb    w0, w0                      // -> sxtb w0, w1
    mov     w2, w2
    and     w2, w2, #0xfffffff          // -> and w2, w2, #0xfffffff

    // P2) Two masks: one AND of the intersection; the second pair's
    //     intersection only encodes in the W form, which zero-extends
    //     (check_and_lo32_mov also respells its producer).
    and     w9, w20, #0xffffff00
    and     w9, w9, #0xffff             // -> and w9, w20, #0xff00
    and     x8, x21, #0xffffffff
    and     x8, x8, #0xfffffffffffffffd // -> and w8, w21, #0xfffffffd

    // P3) An ANDS keeps its flags: same value, same width.
    and     w10, w11, #0xff
    ands    w10, w10, #0xf              // -> ands w10, w11, #0xf

    // P4) An empty intersection, and an SXT re-extended at X width.
    and     w12, w13, #0xf0
    and     w12, w12, #0xf              // -> mov w12, #0
    sxtb    w14, w15
    sxtw    x14, w14                    // -> sxtb x14, w15

    // Positives, deferred: the consumer writes elsewhere, so the
    // producer's destination must be overwritten before any read.

    // P5) mov w0, w2 ; and x19, x0, #0x7fffffff (clang), then x0 dies.
    mov     w0, w2
    and     x19, x0, #0x7fffffff        // -> and x19, x2, #0x7fffffff
    mov     x0, #1

    // P6) A TST of the masked value (Rust), then w16 dies; the CSET
    //     reads the flags, which the rewrite leaves as they were.
    and     w16, w12, #0x7f
    tst     w16, #0x60                  // -> tst w12, #0x60
    cset    w18, ne
    mov     w16, #0

    // Negatives:
    // N1) An in-place consumer that changes nothing: delete it --
    //     check_redundant_zext's and check_redundant_sext's shape.
    and     w3, w3, #0xff
    and     w3, w3, #0xffff
    sxtb    w4, w5
    sxth    w4, w4

    // N2) An in-place SXT made dead by an in-place zero-extension:
    //     check_redundant_sext's dead-sign-extension arm.
    sxth    w6, w6
    uxtb    w6, w6

    // N3) The intersection does not encode (#0xf0f0f000).
    and     w7, w9, #0xf0f0f0f0
    and     w7, w7, #0xffffff00

    // N4) An ANDS producer takes its flags with it.
    ands    w17, w9, #0xff
    and     w17, w17, #0xf

    // N5) A deferred pair whose temp is read before it dies.
    mov     w0, w2
    and     x19, x0, #0x7fffffff
    add     x1, x0, #1

    // N6) A branch onto the consumer reaches it without the producer.
    and     w8, w8, #0xff
L_join:
    and     w8, w8, #0x3f
    cbnz    w8, L_join

    ret
