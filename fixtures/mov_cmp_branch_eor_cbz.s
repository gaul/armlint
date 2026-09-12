// Integration fixture for check_mov_cmp_branch_eor_cbz.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) INT64_MIN -- Rust's Option<Vec>/Option<String> niche test.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.eq    1f                  // -> eor x8, x0, #0x8000000000000000 ; cbz x8, 1f
    mov     x8, #1              // constant register dead
    adds    w9, w10, w11        // NZCV dead
1:
    // 2) W form, b.ne -> cbnz, the constant in the Rn slot; one
    //    instruction settles both proofs.
    mov     w8, #0x80000000
    cmp     w8, w1
    b.ne    2f                  // -> eor w8, w1, #0x80000000 ; cbnz w8, 2f
    adds    x8, x2, x3
2:
    // 3) A two-instruction chain (0x3fffffff, nscoord_MAX); the RET
    //    proves NZCV dead once the register is.
    movz    w8, #0xffff
    movk    w8, #0x3fff, lsl #16
    cmp     w1, w8
    b.eq    3f                  // -> eor w8, w1, #0x3fffffff ; cbz w8, 3f
    mov     w8, #1
    ret
3:
    // Negatives:
    // N1) An add/sub-encodable constant is the CMP-immediate fold's
    //     (-> cmp x0, #0x64).
    mov     x8, #100
    cmp     x0, x8
    b.eq    4f
    mov     x8, #1
    adds    w9, w10, w11
4:
    // N2) Not a bitmask immediate.
    mov     x8, #0x1234
    cmp     x0, x8
    b.eq    5f
    mov     x8, #1
    adds    w9, w10, w11
5:
    // N3) An ordered condition needs the subtraction.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.lo    6f
    mov     x8, #1
    adds    w9, w10, w11
6:
    // N4) NZCV read after the branch, even with the register dead.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.eq    7f
    mov     x8, #1
    b.lt    6b
7:
    // N5) The constant register read after the branch.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.eq    8f
    add     x9, x0, x8
    adds    w9, w10, w11
8:
    // N6) A call before the register dies: no PCS assumption.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.eq    9f
    bl      _main
    mov     x8, #1
9:
    // N7) The CMP is a branch target (side entry).
    cbz     w17, 10f
    mov     x8, #0x8000000000000000
10:
    cmp     x0, x8
    b.eq    11f
    mov     x8, #1
    adds    w9, w10, w11
11:
    ret
