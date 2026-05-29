// Integration fixture for check_and_lsr_lsl_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives: AND low-mask + LSL -> UBFIZ.
    // 1) Canonical.
    and     w0, w1, #0xff
    lsl     w0, w0, #4             // -> ubfiz w0, w1, #4, #8

    // 2) Width capped (n + w exceeds 32).
    and     w0, w1, #0xffff
    lsl     w0, w0, #20            // -> ubfiz w0, w1, #20, #12

    // 3) X-form.
    and     x0, x1, #0xff
    lsl     x0, x0, #8             // -> ubfiz x0, x1, #8, #8

    // Positives: LSR + LSL (equal shift) -> clear low bits via AND.
    // 4) W-form.
    lsr     w0, w1, #4
    lsl     w0, w0, #4             // -> and w0, w1, #0xfffffff0

    // 5) X-form.
    lsr     x0, x1, #12
    lsl     x0, x0, #12            // -> and x0, x1, #0xfffffffffffff000

    // Negatives:
    // N1) LSR + LSL with unequal shifts: no single-instruction form.
    lsr     w0, w1, #4
    lsl     w0, w0, #6

    // N2) Non-low mask (run [4,11], not based at bit 0): the LSL would
    //     shift a mid-field, which UBFIZ cannot express.
    and     w0, w1, #0xff0
    lsl     w0, w0, #4

    ret
