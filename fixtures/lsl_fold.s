// Integration fixture for check_lsl_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: LSL feeding an ADD shifted-register form. The
    // consumer must overwrite the LSL's Rd to make the LSL value
    // dead -- here Rd of ADD == Rd of LSL == x0.
    lsl     x0, x1, #3
    add     x0, x4, x0              // -> add x0, x4, x1, lsl #3

    // Positive: LSL feeding an AND logical-shifted-register form.
    lsl     x5, x6, #4
    and     x5, x7, x5              // -> and x5, x7, x6, lsl #4

    // Positive: W-form LSL + W-form SUB.
    lsl     w8, w9, #2
    sub     w8, w11, w8             // -> sub w8, w11, w9, lsl #2

    // Negative: consumer's Rm != LSL's Rd (no fold).
    lsl     x12, x13, #3
    add     x12, x15, x16

    // Negative: consumer writes a fresh register and x17 is never
    // touched again -- the deferred finding's liveness scan expires
    // without proving the shift result dead, so nothing is emitted.
    lsl     x17, x18, #3
    add     x19, x20, x17

    // Negative: intervening instruction expires state.
    lsl     x21, x22, #3
    add     x23, x23, x23
    add     x21, x24, x21

    // Positive: LSL result in the consumer's Rn slot. ADD commutes, so
    // it folds by swapping operands.
    lsl     x0, x1, #3
    add     x0, x0, x4              // -> add x0, x4, x1, lsl #3

    // Negative: SUB with the LSL result in Rn does not commute.
    lsl     w8, w9, #2
    sub     w8, w8, w11

    // Negative: both ADD sources are the LSL dest (add wt, wt, wt). The
    // fold would read a stale pre-LSL value for the second operand, so
    // it must not fire.
    lsl     w0, w1, #3
    add     w0, w0, w0

    // Positive: LSR feeding an ADD -- the consumer's shift type
    // carries the producer's shift.
    lsr     x0, x1, #4
    add     x0, x4, x0              // -> add x0, x4, x1, lsr #4

    // Positive: ASR feeding a SUB.
    asr     w8, w9, #3
    sub     w8, w11, w8             // -> sub w8, w11, w9, asr #3

    // Positive: ROR (same-register EXTR) feeding an ORR.
    ror     w0, w1, #5
    orr     w0, w4, w0              // -> orr w0, w4, w1, ror #5

    // Negative: ROR feeding an ADD -- the arithmetic shifted-register
    // encoding reserves shift type 11 (ROR).
    ror     w0, w1, #5
    add     w0, w4, w0

    // Negative: EXTR with distinct sources is a funnel shift, not a
    // rotate.
    extr    w0, w1, w2, #5
    orr     w0, w4, w0

    // Positive (deferred): the consumer writes a fresh register, so
    // emission waits for the forward register-liveness scan -- the
    // trailing mov overwrites the shift result, proving it dead.
    lsl     x25, x26, #4
    and     x27, x28, x25           // -> and x27, x28, x26, lsl #4
    mov     x25, #1

    // Negative (deferred): the shift result is read again before
    // dying; the deferred finding is discarded.
    lsr     w8, w9, #2
    add     w10, w11, w8
    add     w12, w8, w13
    mov     w8, #1

    ret
