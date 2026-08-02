// Integration fixture for check_aut_ret (-m pauth via the .flags
// sidecar: RETAA/RETAB are undefined before Armv8.3, so the fold is
// opt-in). The .arch directive is for GNU as, whose default -march
// rejects the v8.3 RETAB negative below.

    .arch armv8.3-a
    .text
    .globl  _main
    .p2align 2
_main:
    // 1) The split A-key epilogue.
    paciasp
    add     x0, x1, x2
    autiasp
    ret                     // -> retaa

    // 2) The B-key twin.
    pacibsp
    add     x0, x1, x2
    autibsp
    ret                     // -> retab

    // Negatives:
    // N1) RET through x17: the combined forms are x30-only.
    autiasp
    ret     x17

    // N2) The zero-modifier AUTIAZ has no combined return form.
    autiaz
    ret

    // N3) Adjacency broken: the AUT must immediately precede the RET.
    autiasp
    add     x0, x1, x2
    ret

    // N4) Already folded.
    pacibsp
    add     x0, x1, x2
    retab

    // N5) A shared epilogue: the RET is a branch target, so the
    //     entering path skips the authentication.
    b       1f
    autiasp
1:
    ret
