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

    // Positives: zero-extension (UXT*/MOV) + LSL -> UBFIZ.
    // 6) UXTB keeps the low 8 bits (32-bit domain).
    uxtb    w0, w1
    lsl     w0, w0, #4             // -> ubfiz w0, w1, #4, #8

    // 7) UXTH keeps the low 16 bits, width capped by the shift.
    uxth    w0, w1
    lsl     w0, w0, #20            // -> ubfiz w0, w1, #20, #12

    // 8) UXTW zero-extends into the 64-bit domain.
    uxtw    x0, w1
    lsl     x0, x0, #2             // -> ubfiz x0, x1, #2, #32

    // 9) W-form MOV zero-extends like UXTW; the 64-bit LSL folds
    //    (the .NET 7 "mov w0, w0 ; lsl x0, x0, #n" shape).
    mov     w0, w0
    lsl     x0, x0, #2             // -> ubfiz x0, x0, #2, #32

    // Negatives:
    // N1) LSR + LSL with unequal shifts: no single-instruction form.
    lsr     w0, w1, #4
    lsl     w0, w0, #6

    // N2) Non-low mask (run [4,11], not based at bit 0): the LSL would
    //     shift a mid-field, which UBFIZ cannot express.
    and     w0, w1, #0xff0
    lsl     w0, w0, #4

    ret
