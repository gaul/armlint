// Integration fixture for the dead-MOV deferral across direct branches
// (reg_dead_at_target): the two-ADD fold stands in for every fold that
// deletes a MOV.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) The constant register reaches an unconditional branch alive
    //    and dies at the target (XUL's static-atom lookup).
    movz    w10, #0x88
    movk    w10, #1, lsl #16
    add     x9, x9, x10         // -> add x9, x9, #0x10, lsl #12 ; add x9, x9, #0x88
    tst     w0, #1
    csel    x9, x0, x9, eq
    b       1f
    ret
1:
    mov     w10, #5
    ret

    // 2) A conditional branch: dead on both edges.
    movz    w10, #0x88
    movk    w10, #1, lsl #16
    add     x9, x9, x10         // -> add x9, x9, #0x10, lsl #12 ; add x9, x9, #0x88
    cbz     x0, 2f
    mov     w10, #1
    ret
2:
    mov     w10, #2
    ret

    // Negatives:
    // 3) The target reads it.
    movz    w10, #0x88
    movk    w10, #1, lsl #16
    add     x9, x9, x10
    b       3f
    ret
3:
    add     x1, x1, x10
    ret

    // 4) One edge reads it.
    movz    w10, #0x88
    movk    w10, #1, lsl #16
    add     x9, x9, x10
    cbz     x0, 4f
    add     x1, x1, x10
    ret
4:
    mov     w10, #2
    ret

    // 5) The target returns: no PCS assumption.
    movz    w10, #0x88
    movk    w10, #1, lsl #16
    add     x9, x9, x10
    b       5f
    mov     w10, #1
5:
    ret
