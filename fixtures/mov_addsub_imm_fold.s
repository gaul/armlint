// Integration fixture for check_mov_add_sub_imm_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) ADD with small constant.
    mov     x0, #100
    add     x3, x2, x0          // -> add x3, x2, #100

    // 2) ADD commutativity: Rn from MOV.
    mov     x0, #5
    add     x3, x0, x2          // -> add x3, x2, #5

    // 3) W form.
    mov     w0, #50
    add     w3, w2, w0          // -> add w3, w2, #50

    // 4) ADDS.
    mov     x0, #200
    adds    x3, x2, x0          // -> adds x3, x2, #200

    // 5) SUB.
    mov     x0, #300
    sub     x3, x2, x0          // -> sub x3, x2, #300

    // 6) SUBS.
    mov     x0, #400
    subs    x3, x2, x0          // -> subs x3, x2, #400

    // 7) CMP (alias for SUBS XZR, ...).
    mov     x0, #500
    cmp     x2, x0              // -> cmp x2, #500

    // 8) CMN (alias for ADDS XZR, ...).
    mov     x0, #600
    cmn     x2, x0              // -> cmn x2, #600

    // 9) imm12 boundary: C = 0xFFF (4095) fits without shift.
    mov     x0, #0xFFF
    add     x3, x2, x0          // -> add x3, x2, #0xfff

    // 10) imm12 << 12: C = 0x1000 fits with sh=1.
    mov     x0, #0x1000
    add     x3, x2, x0          // -> add x3, x2, #0x1000

    // Negatives:
    // N1) C = 0x1001 doesn't fit either form.
    mov     x0, #0x1001
    add     x3, x2, x0

    // N2) SUB with Rn from MOV (would need reverse-subtract).
    mov     x0, #100
    sub     x3, x0, x2

    // N3) Shifted ADD: ADD X3, X2, X0, LSL #2.
    mov     x0, #100
    add     x3, x2, x0, lsl #2

    // N4) MOV does not feed the ADD.
    mov     x0, #100
    add     x3, x2, x1

    ret
