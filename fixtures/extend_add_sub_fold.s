// Integration fixture for check_extend_add_sub_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) SXTW + ADD (Rm slot).
    sxtw    x0, w1
    add     x0, x3, x0             // -> add x0, x3, w1, sxtw

    // 2) SXTW + ADD with the extend result in Rn (ADD commutes).
    sxtw    x0, w1
    add     x0, x0, x3             // -> add x0, x3, w1, sxtw

    // 3) SXTW + SUB (Rm slot only).
    sxtw    x0, w1
    sub     x0, x3, x0             // -> sub x0, x3, w1, sxtw

    // 4) W-form SXTB + W-form ADD.
    sxtb    w0, w1
    add     w0, w3, w0             // -> add w0, w3, w1, sxtb

    // 5) W-form UXTB + W-form ADD.
    uxtb    w0, w1
    add     w0, w3, w0             // -> add w0, w3, w1, uxtb

    // 6) X-form SXTB + X-form ADD.
    sxtb    x0, w1
    add     x0, x3, x0             // -> add x0, x3, w1, sxtb

    // 7) W-form UXTB + X-form ADD: the W write zeroed bits 63..32,
    // exactly what the X-form extended-register option computes.
    uxtb    w0, w1
    add     x0, x3, x0             // -> add x0, x3, w1, uxtb

    // P) Fresh destination: the ADD leaves the extended value in x0
    // alive at the consumer, so emission defers through the forward
    // register-liveness scan -- and the next case's sxtw overwrites
    // x0, proving it dead, so the deferred finding emits.
    sxtw    x0, w1
    add     x2, x3, x0             // -> add x2, x3, w1, sxtw

    // Negatives:
    // N1) SUB with the extend result in Rn (SUB does not commute).
    sxtw    x0, w1
    sub     x0, x0, x3

    // N2) Width mismatch: W-form SIGN-extend, X-form consumer. The
    // sxtb zeroed X0's high half where the X-form sxtb option would
    // replicate the sign -- no zext-style relaxation for it.
    sxtb    w0, w1
    add     x0, x3, x0

    // N3) Independent operand is register 31: the shifted-register
    // consumer reads ZR there, but the extended-register rewrite
    // would read SP.
    uxtb    w0, w1
    add     w0, wzr, w0

    // N4) Fresh destination, but the extended value is read again
    // before dying: the deferred finding is discarded.
    sxtw    x0, w1
    add     x2, x3, x0
    add     x4, x0, x5
    mov     x0, #1

    ret
