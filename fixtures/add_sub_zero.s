// Integration fixture for check_add_sub_zero.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) ADD #0 with Rd != Rn -- equivalent to MOV.
    add     x0, x1, #0

    // 2) ADD #0 with Rd == Rn -- pure no-op.
    add     x0, x0, #0

    // 3) SUB #0, W-form, Rd != Rn -- MOV.
    sub     w2, w3, #0

    // Negatives:
    // N1) Non-zero immediate.
    add     x0, x1, #4

    // N2) SP destination (ADD-imm with Rd=31 means SP, not ZR).
    add     sp, sp, #16

    // N3) Linker-resolved ADRP+ADD where the page offset is 0:
    //     removing the ADD requires re-linking, so it is not flagged.
    adrp    x0, _main@PAGE
    add     x0, x0, #0

    ret
