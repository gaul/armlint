// Integration fixture for check_and_lsr_to_ubfx.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical (run base == shift): mask bits [4,11], shift 4.
    and     w0, w1, #0xff0
    lsr     w0, w0, #4             // -> ubfx w0, w1, #4, #8

    // 2) Low mask, shift inside the run: bits [0,7], shift 4.
    and     w0, w1, #0xff
    lsr     w0, w0, #4             // -> ubfx w0, w1, #4, #4

    // 3) Run starts below the shift (low mask bits dropped): bits
    //    [4,11], shift 6.
    and     w0, w1, #0xff0
    lsr     w0, w0, #6             // -> ubfx w0, w1, #6, #6

    // 4) X-form: bits [8,23], shift 8.
    and     x0, x1, #0xffff00
    lsr     x0, x0, #8            // -> ubfx x0, x1, #8, #16

    // 5) Shift at top of run (width 1): bits [4,11], shift 11.
    and     w0, w1, #0xff0
    lsr     w0, w0, #11           // -> ubfx w0, w1, #11, #1

    // Negatives:
    // N1) Run above the shift (lo > n): bits [8,15], shift 4 -- the
    //     field would land above bit 0, so no single UBFX.
    and     w0, w1, #0xff00
    lsr     w0, w0, #4

    // N2) Run shifted out entirely (n > hi): bits [4,11], shift 12 --
    //     result is always 0.
    and     w0, w1, #0xff0
    lsr     w0, w0, #12

    // N3) Non-contiguous (replicated) mask 0x0f0f0f0f -- no single run.
    and     w0, w1, #0x0f0f0f0f
    lsr     w0, w0, #4

    // N4) ANDS (flag-setting) must not open the fold.
    ands    w0, w1, #0xff0
    lsr     w0, w0, #4

    // N5) LSR Rd != AND Rd (the LSR doesn't write the AND's dest).
    and     w0, w1, #0xff0
    lsr     w5, w0, #4

    // 6) A gap leaving w0 and w1 alone (ART's shape: a load between).
    and     w7, w0, #0x7f8
    ldr     x10, [x9, x10, lsl #3]
    lsr     w7, w7, #3            // -> ubfx w7, w0, #3, #8

    // N6) A gap reading the AND's result keeps the AND.
    and     w0, w1, #0xff0
    mov     w5, w0
    lsr     w0, w0, #4

    // N7) A gap writing the AND's source moves the UBFX input.
    and     w0, w1, #0xff0
    mov     w1, #1
    lsr     w0, w0, #4

    ret
