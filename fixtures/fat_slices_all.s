// Integration fixture: fat_slices's universal object (arm64 + arm64e,
// see fixtures/fat_slices_all.fat) scanned with -s all, which restores
// the scan of every ARM64 slice. The literal no-op is reported once per
// slice, and the arm64e slice arms the PAC audit, so its unsigned LR
// spill is reported as well. No slice is skipped, so there is no note.

    .text
    .globl  _main
    .p2align 2
_main:
    stp     x29, x30, [sp, #-16]!
    mov     x0, x0
    ldp     x29, x30, [sp], #16
    ret
