// Integration fixture for check_add_ldr_register_offset.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical X-form, LSL #0.
    add     x3, x1, x2
    ldr     x3, [x3]                // -> ldr x3, [x1, x2]

    // 2) X-form LSL #3 matches X access scale.
    add     x3, x1, x2, lsl #3
    ldr     x3, [x3]                // -> ldr x3, [x1, x2, lsl #3]

    // 3) W-form load, LSL #0.
    add     x3, x1, x2
    ldr     w3, [x3]                // -> ldr w3, [x1, x2]

    // 4) W-form load with LSL #2 matches W access scale.
    add     x3, x1, x2, lsl #2
    ldr     w3, [x3]                // -> ldr w3, [x1, x2, lsl #2]

    // 5) LDRB, LSL #0.
    add     x3, x1, x2
    ldrb    w3, [x3]                // -> ldrb w3, [x1, x2]

    // 6) LDRH with LSL #1.
    add     x3, x1, x2, lsl #1
    ldrh    w3, [x3]                // -> ldrh w3, [x1, x2, lsl #1]

    // 7) Aliasing OK: add x3, x3, x2 ; ldr x3, [x3].
    add     x3, x3, x2
    ldr     x3, [x3]                // -> ldr x3, [x3, x2]

    // Negatives:
    // N1) LSL #2 with X load (scale 3 required).
    add     x3, x1, x2, lsl #2
    ldr     x3, [x3]

    // N2) LSL #1 with W load (scale 2 required).
    add     x3, x1, x2, lsl #1
    ldr     w3, [x3]

    // N3) LDR base != ADD's Rd.
    add     x3, x1, x2
    ldr     x3, [x5]

    // N4) LDR Rt != ADD's Rd (Xt would be alive after).
    add     x3, x1, x2
    ldr     x7, [x3]

    // N5) LDR with non-zero immediate.
    add     x3, x1, x2
    ldr     x3, [x3, #8]

    // N6) SUB instead of ADD.
    sub     x3, x1, x2
    ldr     x3, [x3]

    // N7) Intervening instruction.
    add     x3, x1, x2
    add     x5, x5, x6              // unrelated
    ldr     x3, [x3]

    ret
