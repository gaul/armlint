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

    // Negative: consumer's Rd != LSL's Rd (LSL value would be alive).
    lsl     x17, x18, #3
    add     x19, x20, x17

    // Negative: intervening instruction expires state.
    lsl     x21, x22, #3
    add     x23, x23, x23
    add     x21, x24, x21

    ret
