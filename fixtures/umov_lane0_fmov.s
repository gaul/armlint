// Integration fixture for check_umov_lane0_fmov, default features.
// The halfword arm needs -m fp16 and stays silent here; see
// umov_lane0_fp16 for it.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives: Sn and Dn are the low 32 and 64 bits of Vn, so lane 0
    // moves exactly the bits FMOV already reaches.
    umov    w0, v1.s[0]                 // -> fmov w0, s1
    umov    x2, v3.d[0]                 // -> fmov x2, d3

    // The assembler prefers the MOV alias for these two forms, so the
    // check has to match on the encoding rather than the mnemonic.
    // These are the same instructions written the other way.
    mov     w4, v5.s[0]                 // -> fmov w4, s5
    mov     x6, v7.d[0]                 // -> fmov x6, d7

    // Negatives:
    // N1) Any lane above 0. FMOV (general) addresses only the low
    //     element, so there is no spelling to fold to.
    umov    w8, v9.s[1]
    umov    w8, v9.s[2]
    umov    w8, v9.s[3]
    umov    x8, v9.d[1]

    // N2) Byte elements have no FMOV counterpart at any lane -- there
    //     is no FMOV Wd, Bn -- so lane 0 does not save them.
    umov    w10, v11.b[0]
    umov    w10, v11.b[5]

    // N3) Halfword lane 0 IS foldable, but only to FMOV Wd, Hn, which
    //     is FEAT_FP16. Silent without -m fp16.
    umov    w12, v13.h[0]

    // N4) Rd = ZR discards the transfer, so the instruction is dead
    //     outright; respelling it as a different dead instruction is
    //     not the advice to give.
    umov    wzr, v14.s[0]
    umov    xzr, v14.d[0]

    // N5) SMOV sign-extends rather than zero-extends, and shares no
    //     encoding with UMOV; it must not be caught by the mask.
    smov    w15, v16.h[0]
    smov    x17, v18.s[0]

    ret
