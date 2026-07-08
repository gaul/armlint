// Integration fixture for check_funnel_to_extr.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: LSR + ORR<< funnel. The consumer overwrites the shift's
    // Rd (x2), so the intermediate is dead. -> extr x2, x3, x1, #56.
    lsr     x2, x1, #56
    orr     x2, x2, x3, lsl #8

    // Positive: reached from the LSL side. -> extr x2, x1, x3, #56.
    lsl     x2, x1, #8
    orr     x2, x2, x3, lsr #56

    // Positive: EOR consumer (disjoint fields, so EOR == ORR == EXTR).
    // -> extr x0, x5, x1, #40.
    lsr     x0, x1, #40
    eor     x0, x0, x5, lsl #24

    // Positive: ADD consumer (likewise no carry across the field split).
    // -> extr x0, x1, x5, #40.
    lsl     x0, x1, #24
    add     x0, x0, x5, lsr #40

    // Positive: W-form (amounts sum to 32). -> extr w2, w3, w1, #24.
    lsr     w2, w1, #24
    orr     w2, w2, w3, lsl #8

    // Positive: both halves are the same register -- a rotate.
    // -> ror x0, x2, #8.
    lsr     x0, x2, #8
    orr     x0, x0, x2, lsl #56

    // Positive: in-place source shift (shift reads and writes x0) is
    // still sound. -> extr x0, x3, x0, #56.
    lsr     x0, x0, #56
    orr     x0, x0, x3, lsl #8

    // Negative: consumer writes a fresh register, so emission defers
    // on x1 -- which the next case reads before any kill, discarding
    // the deferred finding.
    lsr     x1, x5, #56
    orr     x0, x1, x2, lsl #8

    // Negative: shift amounts do not sum to the register width.
    lsr     x2, x1, #40
    orr     x2, x2, x3, lsl #8

    // Negative: same shift direction (both LSL) is not a funnel.
    lsl     x2, x1, #56
    orr     x2, x2, x3, lsl #8

    // Negative: inline ASR would sign-fill into the other field.
    lsr     x2, x1, #56
    orr     x2, x2, x3, asr #8

    // Negative: inline-shifted source == shift destination; the funnel
    // would read the shifted value, not the original register.
    lsr     x2, x1, #56
    orr     x2, x2, x2, lsl #8

    // Negative: SUB is not a bitwise funnel op.
    lsl     x2, x1, #8
    sub     x2, x2, x3, lsr #56

    // Negative: flag-setting ADDS would drop the NZCV write.
    lsl     x2, x1, #8
    adds    x2, x2, x3, lsr #56

    // Negative: a NOP separates producer and consumer.
    lsr     x2, x1, #56
    nop
    orr     x2, x2, x3, lsl #8

    // Positive (deferred): the consumer writes a fresh register, so
    // emission waits for the forward register-liveness scan -- the
    // trailing mov overwrites the shift result, proving it dead.
    lsr     x6, x5, #56
    orr     x7, x6, x8, lsl #8      // -> extr x7, x8, x5, #56
    mov     x6, #1

    ret
