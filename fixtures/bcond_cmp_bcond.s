// Integration fixture for check_bcond_cmp_bcond: two conditional
// branches around a compare a CCMP can repeat. The CCMP takes the first
// branch's slot, so NZCV must die unread at the merged exit -- the
// shared target for OR, the fall-through for AND -- which the ADDS
// there do. Each block tests its own registers, so no block decides a
// later one's branch.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive, OR: w1 == 3 || w1 == 4, both to L_a.
    cmp     w1, #3
    b.eq    L_a
    cmp     w1, #4
    b.eq    L_a                         // -> ccmp w1, #0x4, #0x4, ne ; b.eq L_a
    adds    w0, w0, #1                  // overwrites NZCV

    // Positive, AND: x2 > 5 && x3 < x4, the first branch skipping the
    // second's compare and branch; the target reads the flags, which
    // only the real compare reaches.
    cmp     x2, #5
    b.le    L_b
    cmp     x3, x4
    b.lt    L_d                         // -> ccmp x3, x4, #0x0, gt ; b.lt L_d
L_b:
    adds    w0, w0, #2

    // Positive, three links: w8 in {13, 22, 29}, folding link by link.
    cmp     w8, #13
    b.eq    L_a
    cmp     w8, #22
    b.eq    L_a                         // -> ccmp w8, #0x16, #0x4, ne ; b.eq L_a
    cmp     w8, #29
    b.eq    L_a                         // -> ccmp w8, #0x1d, #0x4, ne ; b.eq L_a
    adds    w0, w0, #3

    // Positive: a CMN link, W form.
    cmp     w9, w10
    b.hi    L_a
    cmn     w9, #5
    b.hi    L_a                         // -> ccmn w9, #0x5, #0x2, ls ; b.hi L_a
    adds    w0, w0, #4

    // Positive: a zero test under GT is this fold's (no CBZ spells it).
    cmp     w11, #6
    b.eq    L_a
    cmp     w12, #0
    b.gt    L_a                         // -> ccmp w12, #0x0, #0x0, ne ; b.gt L_a
    adds    w0, w0, #5

    // Negative: the comparand is six bits.
    cmp     w13, #3
    b.eq    L_a
    cmp     w13, #32
    b.eq    L_a
    adds    w0, w0, #6

    // Negative: a shifted register has no CCMP spelling.
    cmp     x14, #5
    b.le    L_c
    cmp     x15, x16, lsl #2
    b.lt    L_a
L_c:
    adds    w0, w0, #7

    // Negative: the shared target reads the flags.
    cmp     w17, #3
    b.eq    L_d
    cmp     w17, #4
    b.eq    L_d
    adds    w0, w0, #8

    // Negative: a zero test under EQ/NE is the CBZ fold's in either
    // slot: in the second it is refused there too (the fall-through
    // reads), in the first it folds there.
    cmp     w19, #3
    b.eq    L_a
    cmp     w20, #0
    b.eq    L_a
    csel    w3, w1, w2, lt
    cmp     w21, #0
    b.ne    L_a                         // -> cbnz w21, L_a
    cmp     w24, #9
    b.eq    L_a
    adds    w0, w0, #9

    // Negative: a branch onto the compare from elsewhere.
    cmp     w22, #3
    b.eq    L_a
L_e:
    cmp     w22, #4
    b.eq    L_a
    cbz     w23, L_e
    adds    w0, w0, #10
    ret

L_d:
    csel    w5, w1, w2, eq
    ret

L_a:
    adds    w0, w0, #11
    ret
