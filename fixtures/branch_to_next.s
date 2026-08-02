// Integration fixture for check_branch_to_next.

    .text
    .globl  _main
    .p2align 2
_main:
    // 1) Unconditional branch to the very next instruction.
    b       1f
1:
    // 2) Conditional: both outcomes fall through, and the forms
    //    write no register and no flags, so the condition's value
    //    is irrelevant.
    b.eq    2f
2:
    // 3) Compare-and-branch.
    cbz     x0, 3f
3:
    // 4) Test-bit-and-branch.
    tbnz    x1, #5, 4f
4:
    add     x0, x0, x1

    // Negatives:
    // N1) BL to the next instruction still writes x30 (the
    //     get-the-PC idiom).
    bl      5f
5:
    // N2) A branch that actually skips something.
    b       6f
    add     x1, x1, x2
6:
    // N3) Branch-to-self is a spin, not a no-op.
    b       .
    ret
