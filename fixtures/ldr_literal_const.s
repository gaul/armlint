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

    // 5) LDRSW: the materialisation is the sign-extended value
    //    (sext(0xfffffff6) = -10, MOVN-encodable at X width).
    ldrsw   x3, L_neg               // -> mov x3, #0xfffffffffffffff6

    // 6) Q constant, byte-replicated.
    ldr     q0, L_q16b              // -> movi v0.16b, #0x2a

    // 7) Q constant, per-byte 00/FF mask.
    ldr     q1, L_q2d               // -> movi v1.2d, #0xffffffff00000000

    // Negatives:
    // N1) Two independent halfwords, no bitmask: a genuine pool load.
    ldr     w2, L_hard

    // N2) FP value with extra fraction bits.
    ldr     s2, L_hard

    // N3) Q constant with unequal halves: no MOVI replicates it.
    ldr     q2, L_qhard

    ret

    .p2align 4
L_q16b: .quad 0x2a2a2a2a2a2a2a2a
        .quad 0x2a2a2a2a2a2a2a2a
L_q2d:  .quad 0xffffffff00000000
        .quad 0xffffffff00000000
L_qhard: .quad 0x0123456789abcdef
        .quad 0xfedcba9876543210
L_x:    .quad 0xaaaaaaaaaaaaaaaa
L_d:    .quad 0x3ff8000000000000
L_w:    .long 42
L_s:    .long 0x3f800000
L_neg:  .long 0xfffffff6
L_hard: .long 0x12345678
