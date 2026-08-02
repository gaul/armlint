// Integration fixture for the arm64e PAC-audit auto-arm. The sidecar
// fixtures/pac_autoarm_arm64e.arch pins assembly to -arch arm64e, so
// the resulting slice carries cpusubtype CPU_SUBTYPE_ARM64E and
// armlint arms the PAC audit with NO -a flag: an arm64e binary has
// opted into the PAC ABI, which is the contract the audit assumes.
//
// The signed prologue draws no finding; the unsigned spill and the
// two raw indirect branches do. The same code built -arch arm64 stays
// silent -- every other fixture is plain arm64 and none reports a PAC
// finding -- which is why the audit must not arm there. This test runs
// only on Darwin with an arm64e-capable toolchain (skipped otherwise).

    .text
    .globl  _main
    .p2align 2

// A correctly signed prologue: PACIBSP vouches for the x30 spill in
// the same straight-line run, so no LR-spill finding. RETAB closes it.
_signed:
    pacibsp
    stp     x29, x30, [sp, #-16]!
    ldp     x29, x30, [sp], #16
    retab

// An unsigned return-address spill: no signing hint before the save,
// so a stack overwrite could steer the return -- LR-spill finding.
_unsigned:
    stp     x29, x30, [sp, #-16]!
    ldp     x29, x30, [sp], #16
    ret

// Raw indirect transfers. In fully signed code these go through the
// authenticated branches (BLRAA(Z)/BRAA(Z)); a raw BLR has no benign
// class, a raw BR may be a jump table. Both are flagged.
_main:
    blr     x9
    br      x8
