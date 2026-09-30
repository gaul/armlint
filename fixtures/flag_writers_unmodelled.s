// Integration fixture for the NZCV and register writers Capstone 5
// reports no write for, which armlint classifies from the encoding:
// SUBPS (FEAT_MTE), the SVE predicate producers, the FEAT_MOPS stages'
// source pointer and LD64B (FEAT_LS64). The words are spelled out so
// the fixture assembles without any of those extensions.

    .text
    .globl  _main
    .p2align 2
_main:
    // Negatives:
    // 1) SUBPS rewrites the flags the first B.NE decided.
    cmp     w1, #3
    b.ne    9f
    .long   0xbac30041          // subps x1, x2, x3
    b.ne    9f
    ret

    // 2) An SVE loop test: WHILELO sets the flags for its B.FIRST.
    cmp     w1, #3
    b.ne    9f
    .long   0x25a30c41          // whilelo p1.s, w2, w3
    b.mi    9f                  // b.first
    ret

    // 3) A predicate test.
    cmp     w1, #3
    b.ne    9f
    .long   0x2550c020          // ptest p0, p1.b
    b.ne    9f                  // b.none
    ret

    // 4) A memory copy advances its source pointer: x4 is not 1 after.
    mov     x4, #1
    .long   0x19040441          // cpyfp [x1]!, [x4]!, x2!
    cbz     x4, 9f
    ret

    // 5) LD64B loads x6..x13.
    mov     x8, #1
    .long   0xf83fd046          // ld64b x6, [x2]
    cbz     x8, 9f
    ret

    // Positive:
    // 6) The flags SUBPS leaves are unknown but stable: a repeated
    //    B.NE is decided by the first.
    .long   0xbac30041          // subps x1, x2, x3
    b.ne    9f
    b.ne    9f
    ret
9:
    ret
