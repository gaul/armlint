// Duplicate code (-d): which functions are copies of one another, and
// which findings repeat across the copies.
//
// _twin_a and _twin_b are one function. Their MOVZ/MOVK finding counts
// once: _twin_b's is marked [repeat]. _cousin differs from them only in
// its constant, a copy up to constants whose finding repeats as well.
// _branchy_a and _branchy_b share a local branch, which keeps its
// relative encoding in the key. _loner has no copy.
//
// Every function is aligned to 16 bytes, so the NOP padding after each
// is trimmed from the key: _branchy_b, last in the section with nothing
// after it, is still _branchy_a's copy.

    .text
    .globl  _twin_a
    .p2align 4
_twin_a:
    movz    w0, #0x6666
    movk    w0, #0x6666, lsl #16
    ret

    .globl  _twin_b
    .p2align 4
_twin_b:
    movz    w0, #0x6666
    movk    w0, #0x6666, lsl #16
    ret

    .globl  _cousin
    .p2align 4
_cousin:
    movz    w0, #0x5555
    movk    w0, #0x5555, lsl #16
    ret

    .globl  _loner
    .p2align 4
_loner:
    add     x0, x0, x1
    ret

    .globl  _branchy_a
    .p2align 4
_branchy_a:
    cbz     x0, 1f
    mov     w0, #1
1:
    ret

    .globl  _branchy_b
    .p2align 4
_branchy_b:
    cbz     x0, 1f
    mov     w0, #1
1:
    ret
