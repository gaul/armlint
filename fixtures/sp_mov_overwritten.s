// Integration fixture for check_sp_mov_overwritten.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) The JIT sync-then-lower-sync shape: sp is rewritten from x20
    //    without ever being read.
    mov     sp, x20
    sub     sp, x20, #16

    // 2) Back-to-back duplicate syncs.
    mov     sp, x20
    mov     sp, x20

    // (separator: without it, 2's second sync would itself be a dead
    // link into 3's opening MOV -- the chaining the unit tests pin)
    movz    x11, #2

    // 3) Deleting the first instruction needs no side-entry gate: the
    //    branch target on the overwriter changes nothing for paths
    //    that executed the MOV, so the finding survives.
    mov     sp, x21
1:
    sub     sp, x21, #32
    cbz     x9, 1b

    // Negatives:
    // 4) The overwriter reads sp: the MOV is live.
    mov     sp, x22
    add     sp, sp, #16

    // 5) An intervening instruction breaks adjacency (a gap-tolerant
    //    variant is recorded, not done).
    mov     sp, x23
    movz    x10, #1
    sub     sp, x23, #16

    // 6) A store through sp reads the synced value.
    mov     sp, x24
    str     x0, [sp]
    ret
