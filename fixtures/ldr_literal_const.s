// Integration fixture for check_ldr_literal_const.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives: the pooled value has a single-instruction
    // materialisation.
    // 1) W constant, MOVZ-encodable.
    ldr     w0, L_w                 // -> mov w0, #0x2a

    // 2) X constant, bitmask-immediate.
    ldr     x1, L_x                 // -> mov x1, #0xaaaaaaaaaaaaaaaa

    // 3) FP single, FMOV-imm8-encodable.
    ldr     s0, L_s                 // -> fmov s0, #1.0

    // 4) FP double.
    ldr     d1, L_d                 // -> fmov d1, #1.5

    // Negatives:
    // N1) Two independent halfwords, no bitmask: a genuine pool load.
    ldr     w2, L_hard

    // N2) FP value with extra fraction bits.
    ldr     s2, L_hard

    ret

    .p2align 3
L_x:    .quad 0xaaaaaaaaaaaaaaaa
L_d:    .quad 0x3ff8000000000000
L_w:    .long 42
L_s:    .long 0x3f800000
L_hard: .long 0x12345678
