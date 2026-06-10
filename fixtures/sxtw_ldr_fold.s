// Integration fixture for check_sxtw_ldr_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) SXTW + register-offset LDR (LSL #0).
    sxtw    x0, w1
    ldr     x0, [x3, x0]           // -> ldr x0, [x3, w1, sxtw]

    // 2) Scaled X load.
    sxtw    x0, w1
    ldr     x0, [x3, x0, lsl #3]   // -> ldr x0, [x3, w1, sxtw #3]

    // 3) Scaled W load.
    sxtw    x0, w1
    ldr     w0, [x3, x0, lsl #2]   // -> ldr w0, [x3, w1, sxtw #2]

    // 4) LDRB.
    sxtw    x0, w1
    ldrb    w0, [x3, x0]           // -> ldrb w0, [x3, w1, sxtw]

    // 5) SP base.
    sxtw    x0, w1
    ldr     x0, [sp, x0]           // -> ldr x0, [sp, w1, sxtw]

    // Negatives:
    // N1) Rt != index (the SXTW result stays live).
    sxtw    x0, w1
    ldr     x2, [x3, x0]

    // N2) Store: no Rt overwrite to prove the index dead.
    sxtw    x0, w1
    str     x0, [x3, x0]

    // N3) Base == index: folding would read the base's pre-SXTW value.
    sxtw    x0, w1
    ldr     x0, [x0, x0]

    // P) Sign-extending consumer: LDRSW still overwrites the index,
    // and its register-offset form takes the same SXTW option.
    sxtw    x0, w1
    ldrsw   x0, [x3, x0, lsl #2]    // -> ldrsw x0, [x3, w1, sxtw #2]

    // N4) PRFM's Rt is a prefetch operation, not a destination; the
    // index stays live.
    sxtw    x0, w1
    prfm    pldl1keep, [x3, x0]

    ret
