// Integration fixture for check_add_one_csel_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (CSINC's else-branch is an increment):
    // 1) Else slot: the condition carries over.
    add     x3, x1, #1
    csel    x3, x2, x3, lt          // -> csinc x3, x2, x1, lt

    // 2) Then slot: operands swap and the condition inverts.
    add     x3, x1, #1
    csel    x3, x3, x2, lt          // -> csinc x3, x2, x1, ge

    // 3) W-form, in-place increment (deleting the ADD leaves w1
    //    holding its original value at the select).
    add     w1, w1, #1
    csel    w1, w2, w1, eq          // -> csinc w1, w2, w1, eq

    // Negatives:
    // N1) An increment other than #1 is not CSINC.
    add     x3, x1, #2
    csel    x3, x2, x3, lt

    // N2) AL select is unconditional; excluded.
    add     x3, x1, #1
    csel    x3, x2, x3, al

    ret
