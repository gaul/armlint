// Integration fixture for check_mov_csel_fold.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives (the constant register dies at the trailing mov, so
    // the deferred finding emits):
    // 1) Constant in the then slot: the condition inverts -- the 1
    //    moves to CSINC's incrementing else branch.
    mov     x8, #1
    csel    x3, x8, x2, lt          // -> csinc x3, x2, xzr, ge
    mov     x8, #5

    // 2) Constant in the else slot: the condition carries over.
    mov     x8, #1
    csel    x3, x2, x8, lt          // -> csinc x3, x2, xzr, lt
    mov     x8, #5

    // 3) ZR surviving operand is the CSET alias: cc ? 1 : 0.
    mov     x8, #1
    csel    x3, x8, xzr, lt         // -> cset x3, lt
    mov     x8, #5

    // 4) ZR surviving operand, else slot: cc ? 0 : 1.
    mov     x8, #1
    csel    x3, xzr, x8, lt         // -> cset x3, ge
    mov     x8, #5

    // 5) W-form.
    mov     w8, #1
    csel    w3, w8, w2, hi          // -> csinc w3, w2, wzr, ls
    mov     w8, #5

    // 6) Structural kill: the select overwrites the constant register
    //    itself, so the finding emits with no separate kill.
    mov     x8, #1
    csel    x8, x8, x2, lt          // -> csinc x8, x2, xzr, ge

    // Negatives:
    // N1) Constant other than 1 has no CSINC spelling.
    mov     x8, #2
    csel    x3, x8, x2, lt
    mov     x8, #5

    // N2) AL condition: the select is unconditional (a plain MOV of
    //     the constant), and the then-slot inversion (AL <-> NV)
    //     would still be always-taken.
    mov     x8, #1
    csel    x3, x8, x2, al
    mov     x8, #5

    // N3) Fresh destination with no later kill: the constant is never
    //     proven dead, so nothing is emitted.
    mov     x9, #1
    csel    x3, x9, x2, lt

    // -- All-ones constant: CSINV's else-branch is ~ZR. --

    // 7) Else slot: the condition carries over.
    mov     x8, #-1
    csel    x3, x2, x8, lt          // -> csinv x3, x2, xzr, lt
    mov     x8, #5

    // 8) Then slot: the condition inverts.
    mov     x8, #-1
    csel    x3, x8, x2, lt          // -> csinv x3, x2, xzr, ge
    mov     x8, #5

    // 9) ZR surviving operand is the CSETM alias: cc ? -1 : 0.
    mov     w8, #-1
    csel    w3, w8, wzr, lt         // -> csetm w3, lt
    mov     w8, #5

    ret
