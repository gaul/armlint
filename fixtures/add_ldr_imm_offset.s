// Integration fixture for check_add_ldr_imm_offset.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) Canonical: add x3, x1, #16 ; ldr x3, [x3] -> ldr x3, [x1, #16].
    add     x3, x1, #16
    ldr     x3, [x3]

    // 2) W-form LDR.
    add     x3, x1, #16
    ldr     w3, [x3]

    // 3) LDRB (any byte offset works).
    add     x3, x1, #5
    ldrb    w3, [x3]

    // 4) LDRH with aligned offset.
    add     x3, x1, #6
    ldrh    w3, [x3]

    // 5) Stack-relative: ADD Rn=SP folds to LDR with SP base.
    add     x3, sp, #32
    ldr     x3, [x3]

    // 6) sh=1 form: large 4096-byte offset.
    add     x3, x1, #4096
    ldr     x3, [x3]

    // 7) Aliasing OK: add x3, x3, #16 ; ldr x3, [x3].
    add     x3, x3, #16
    ldr     x3, [x3]

    // 8) Combined offset: 16 + 8 = 24.
    add     x3, x1, #16
    ldr     x3, [x3, #8]

    // Negatives:
    // N1) Misaligned for X access (#4 not a multiple of 8).
    add     x3, x1, #4
    ldr     x3, [x3]

    // N2) Misaligned for W access (#2 not a multiple of 4).
    add     x3, x1, #2
    ldr     w3, [x3]

    // N3) Too large for X-form encoding: 0x8000 / 8 = 4096 > 4095.
    add     x3, x1, #32768
    ldr     x3, [x3]

    // N4) LDR base != ADD's Rd.
    add     x3, x1, #16
    ldr     x3, [x5]

    // N5) LDR Rt != ADD's Rd (would leave x3 live).
    add     x3, x1, #16
    ldr     x7, [x3]

    // N6) Combined offset out of X-form range: 0x7000 + 0x1000 = 0x8000,
    //     0x8000/8 = 4096 > 4095.
    add     x3, x1, #0x7000
    ldr     x3, [x3, #0x1000]

    // N7) SUB-imm: no negative encoding in LDR-uimm.
    sub     x3, x1, #16
    ldr     x3, [x3]

    // N8) Intervening instruction.
    add     x3, x1, #16
    add     x5, x5, x6
    ldr     x3, [x3]

    ret
