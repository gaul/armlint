// Integration fixture for check_ccmp_chain: a CMP + CCMP chain on one
// register that a single compare decides. NZCV must die unread after
// the reader on its fall-through and, for a branch, at its target;
// the ADDS instructions overwrite it.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: rustc_ast's attribute test, x != 254 && x == 21.
    cmp     w9, #0xfe
    ccmp    w9, #0x15, #0x0, ne
    b.eq    L_a                         // -> cmp w9, #0x15 ; b.eq L_a
    adds    w0, w0, #1                  // overwrites NZCV

    // Positive: three links, x not in {13, 22} and x >= 29.
    cmp     w8, #13
    ccmp    w8, #22, #4, ne
    ccmp    w8, #29, #0, ne
    b.hs    L_a                         // -> cmp w8, #0x1d ; b.hs L_a
    adds    w1, w1, #2

    // Positive: a CSET reader.
    cmp     x8, #3
    ccmp    x8, #4, #0, ne
    cset    w0, eq                      // -> cmp x8, #0x4 ; cset w0, eq
    adds    x1, x1, x2

    // Negative: x == 3 || x == 4 is two values.
    cmp     x8, #3
    ccmp    x8, #4, #4, ne
    cset    w0, eq
    adds    x1, x1, x2

    // Negative: the fall-through reads the flags again.
    cmp     w9, #0xfe
    ccmp    w9, #0x15, #0x0, ne
    b.eq    L_a
    b.lo    L_a

    // Negative: the branch target reads them.
    cmp     w9, #0xfe
    ccmp    w9, #0x15, #0x0, ne
    b.eq    L_b
    adds    w0, w0, #1
    ret

L_b:
    b.hi    L_a
    ret

L_a:
    cmp     w2, #3
    ret
