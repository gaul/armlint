// Integration fixture for check_add_recompute.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) The irregexp lookahead shape: input+pos re-formed while x16,
    //    x0 and x2 are all untouched -- the checks in between only
    //    read the tracked registers (including the register-offset
    //    load through the pair) and the conditional branches leave
    //    the fall-through path's registers alone.
    add     x16, x0, x2
    ldrb    w1, [x16, #1]
    cmp     w1, #0x78
    b.ne    9f
    ldrb    w1, [x0, x2]
    cmp     w1, #0x30
    b.ne    9f
    add     x16, x0, x2
    ldrb    w1, [x16, #2]

    // 2) SUB spelling.
    sub     x5, x6, x7
    cmp     w1, #0x41
    sub     x5, x6, x7

    // Negatives:
    // 3) A write to a source register kills the tracked sum.
    add     x17, x1, x4
    movz    x1, #1
    add     x17, x1, x4

    // 4) A label on the recompute is a side entry: the entering path
    //    never executed the first ADD.
    add     x21, x22, x23
1:
    add     x21, x22, x23
    cbz     x9, 1b

    // 5) A destination that is also an input changes per execution.
    add     x3, x3, x4
    add     x3, x3, x4

    // 6) The S-variant's flag write is a second effect.
    adds    x10, x11, x12
    adds    x10, x11, x12
9:
    ret
