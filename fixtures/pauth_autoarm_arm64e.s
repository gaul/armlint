// Integration fixture for the arm64e -m pauth auto-arm. The sidecar
// fixtures/pauth_autoarm_arm64e.arch pins assembly to -arch arm64e,
// so the slice carries cpusubtype CPU_SUBTYPE_ARM64E and armlint arms
// the PAuth fold with NO -m flag: arm64e mandates Armv8.3 FEAT_PAuth,
// so the combined RETAA/RETAB the fold suggests are guaranteed to
// decode and run. Each split epilogue below folds to one instruction.
//
// The same code built -arch arm64 draws no finding without -m pauth
// (the target might predate FEAT_PAuth) -- every other arm64 fixture
// confirms that silence. This test runs only on Darwin with an
// arm64e-capable toolchain (skipped otherwise). No x30 spill and no
// raw indirect branch here, so the auto-armed PAC audit stays quiet
// and only the PAuth folds appear.

    .text
    .globl  _main
    .p2align 2

// AUTIBSP + RET: the B-key epilogue Apple emits, folds to RETAB.
_epilogue_b:
    autibsp
    ret

// AUTIASP + RET: the A-key form, folds to RETAA.
_main:
    autiasp
    ret
