// Integration fixture: fat_slices's universal object (arm64 + arm64e,
// see fixtures/fat_slices_arm64e.fat) scanned with -s arm64e, which
// picks one slice by its variant name. Only the arm64e slice is
// scanned: the literal no-op is reported once, the auto-armed PAC
// audit reports the unsigned LR spill, and the stderr note names the
// arm64 slice as the one skipped.

    .text
    .globl  _main
    .p2align 2
_main:
    stp     x29, x30, [sp, #-16]!
    mov     x0, x0
    ldp     x29, x30, [sp], #16
    ret
