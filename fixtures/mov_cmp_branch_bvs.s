// Integration fixture for check_mov_cmp_branch_bvs.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) INT64_MIN -- rustc's niche for the dataless variants of a
    //    Vec- or String-carrying enum, Gecko's TimeDuration -Forever.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.eq    1f                  // -> cmp xzr, x0 ; b.vs 1f
    mov     x8, #1              // constant register dead
    adds    w9, w10, w11        // NZCV dead
1:
    // 2) W form, b.ne -> b.vc, the constant in the Rn slot; one
    //    instruction settles both proofs.
    mov     w8, #0x80000000
    cmp     w8, w1
    b.ne    2f                  // -> cmp wzr, w1 ; b.vc 2f
    adds    x8, x2, x3
2:
    // 3) INT64_MAX -- TimeDuration +Forever; the RET proves NZCV dead
    //    once the register is.
    mov     x8, #0x7fffffffffffffff
    cmp     x0, x8
    b.eq    3f                  // -> cmn x0, #1 ; b.vs 3f
    mov     x8, #1
    ret
3:
    // 4) INT32_MAX, b.ne.
    mov     w8, #0x7fffffff
    cmp     w1, w8
    b.ne    4f                  // -> cmn w1, #1 ; b.vc 4f
    mov     w8, #1
    adds    w9, w10, w11
4:
    // Negatives:
    // N1) An add/sub-encodable constant is the CMP-immediate fold's
    //     (-> cmp x0, #0x64).
    mov     x8, #100
    cmp     x0, x8
    b.eq    5f
    mov     x8, #1
    adds    w9, w10, w11
5:
    // N2) A bitmask immediate that is neither extreme (0xffffff):
    //     the general eor + cbz form, a size win that costs an issue
    //     slot on fusing cores -- TODO.md's, not this check's.
    movn    w8, #0xff00, lsl #16
    cmp     w1, w8
    b.eq    6f
    mov     w8, #1
    adds    w9, w10, w11
6:
    // N3) The W sign bit compared at X width is not INT64_MIN.
    mov     x8, #0x80000000
    cmp     x0, x8
    b.eq    7f
    mov     x8, #1
    adds    w9, w10, w11
7:
    // N4) An ordered condition needs the subtraction.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.lo    8f
    mov     x8, #1
    adds    w9, w10, w11
8:
    // N5) NZCV read after the branch, even with the register dead.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.eq    9f
    mov     x8, #1
    b.lt    8b
9:
    // N6) The constant register read after the branch.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.eq    10f
    add     x9, x0, x8
    adds    w9, w10, w11
10:
    // N7) A call before the register dies: no PCS assumption.
    mov     x8, #0x8000000000000000
    cmp     x0, x8
    b.eq    11f
    bl      _main
    mov     x8, #1
11:
    // N8) The CMP is a branch target (side entry).
    cbz     w17, 12f
    mov     x8, #0x8000000000000000
12:
    cmp     x0, x8
    b.eq    13f
    mov     x8, #1
    adds    w9, w10, w11
13:
    ret
