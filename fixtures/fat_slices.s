// Integration fixture for the driver's choice of universal-binary
// slice. The sidecar fixtures/fat_slices.fat assembles this file for
// arm64 and for arm64e and joins the two objects with lipo, the shape
// of a macOS system binary that carries two compilations of one
// program (there, arm64e and arm64e.x1).
//
// By default armlint scans one ARM64 slice -- the lowest variant,
// arm64 here -- and says on stderr which it skipped. So the literal
// no-op below is reported once rather than once per slice, and the
// unsigned LR spill draws no PAC-audit finding: that audit arms itself
// only on arm64e, the slice this run skips. fat_slices_all and
// fat_slices_arm64e run the same code under -s all and -s arm64e.

    .text
    .globl  _main
    .p2align 2
_main:
    stp     x29, x30, [sp, #-16]!
    mov     x0, x0
    ldp     x29, x30, [sp], #16
    ret
