// Integration fixture for the -a const audit (via the sidecar .flags
// file): materialized constants whose consumers have an immediate
// form the value fits. Each is reported at once, with no liveness
// proof, as the consumer's immediate form with the chain kept; the
// summary tallies them by value. A site whose constant register the
// sibling fold proves dead is reported under both.

    .text
    .globl  _main
    .p2align 2
_main:
    // The headline shape: a zero compared from a register.
    movz    w8, #0
    cmp     w6, w8
    b.ne    9f

    // A shifted add/sub immediate (0x3cb << 12) built by two
    // instructions, and a negative one whose magnitude crosses to cmn.
    movz    w8, #0xb000
    movk    w8, #0x3c, lsl #16
    cmp     w6, w8
    b.ge    9f
    movn    w8, #0
    cmp     w2, w8
    b.eq    9f

    // A plain add, and the same of zero, which is a mov.
    movz    w8, #0xa
    add     w9, w10, w8
    movz    w8, #0
    add     w11, w12, w8

    // bitmask: the exponent-and-quiet-bit mask of a NaN test, and an
    // inverting consumer, which takes the complemented mask.
    movz    w16, #0x7ff8, lsl #16
    and     w2, w3, w16
    movz    w8, #0xff
    bic     w9, w10, w8

    // ccmp: within imm5, and sign-crossed to ccmn.
    movz    w16, #0x11
    ccmp    w7, w16, #4, ne
    movn    w16, #2
    ccmp    w7, w16, #4, ne

    // register-offset loads: a scaled offset, an unscaled one, and an
    // element index.
    movz    x1, #0x100
    ldr     x0, [x2, x1]
    movz    x1, #0x3
    ldr     x0, [x2, x1]
    movz    x1, #0x20
    ldr     x0, [x2, x1, lsl #3]

    // Negatives: a misfit is the other audit's; an intervening
    // instruction breaks adjacency.
    movz    x16, #0x100, lsl #16
    cmp     x0, x16
    b.ne    9f
    movz    w6, #0x9
    nop
    cmp     w5, w6
    cset    w0, ne
9:
    ret
