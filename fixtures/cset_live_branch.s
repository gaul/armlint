// Integration fixture for the branch-only CSET downgrade and the
// TBZ/TBNZ #0 consumers of check_cset_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Downgrade: the boolean is stored (still live), so the CSET must
    // stay -- the branch alone rebinds to B.cond. This is the shape a
    // compiler emits for a materialized multi-use condition.
    cmp     w0, w1
    cset    w8, lt
    cbnz    w8, 1f
    strb    w8, [x2]
1:
    // TBZ/TBNZ #0 deleting grade: bit 0 of the 0/1 temp is its truth
    // value, and the temp dies on both edges (target == kill).
    cmp     w0, w1
    cset    w9, gt
    tbnz    w9, #0, 2f
2:  mov     w9, #0

    // TBZ #0 downgrade: the temp is read again on the fall-through.
    cmp     w0, w1
    cset    w10, ne
    tbz     w10, #0, 3f
    add     w3, w10, w4
3:  mov     w10, #0

    // Negative: a bit other than 0 tests a constant-zero bit of the
    // temp, not its truth value.
    cmp     w0, w1
    cset    w11, eq
    tbnz    w11, #3, 4f
4:  mov     w11, #0

    ret
