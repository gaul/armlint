// Integration fixture for check_mov_zero_to_xzr.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positives:
    // 1) STR X.
    mov     x0, #0
    str     x0, [x1]                // -> str xzr, [x1]

    // 2) STR W.
    mov     w0, #0
    str     w0, [x1]                // -> str wzr, [x1]

    // 3) STRB.
    mov     w0, #0
    strb    w0, [x1]                // -> strb wzr, [x1]

    // 4) STRH.
    mov     w0, #0
    strh    w0, [x1]                // -> strh wzr, [x1]

    // 5) STR with offset.
    mov     x0, #0
    str     x0, [x1, #16]           // -> str xzr, [x1, #16]

    // 6) STR with SP.
    mov     x0, #0
    str     x0, [sp, #8]            // -> str xzr, [sp, #8]

    // The same stores in the unscaled spelling. Only the data
    // register changes in this rewrite -- the address is copied
    // through untouched -- so which spelling the assembler picked has
    // nothing to do with it, and these are exactly the addresses the
    // unsigned-offset form cannot express.

    // 7) STUR X: a negative displacement.
    mov     x0, #0
    stur    x0, [x1, #-8]           // -> stur xzr, [x1, #-8]

    // 8) STURB off the transfer-size grid, the shape LLVM emits when
    //    it clears three trailing bytes of a struct.
    mov     w0, #0
    sturb   w0, [x1, #-3]           // -> sturb wzr, [x1, #-3]

    // 9) STURH.
    mov     w0, #0
    sturh   w0, [x1, #5]            // -> sturh wzr, [x1, #5]

    // 10) STUR W off a frame pointer, the dominant real shape.
    mov     w0, #0
    stur    w0, [x29, #-100]        // -> stur wzr, [x29, #-100]

    // 11) ADD with Rm = mov.
    mov     x0, #0
    add     x3, x2, x0              // -> add x3, x2, xzr

    // 12) SUB-from-zero (Rn = mov).
    mov     x0, #0
    sub     x3, x0, x2              // -> sub x3, xzr, x2 (= neg x3, x2)

    // 13) CMP (Rm = mov).
    mov     x0, #0
    cmp     x2, x0                  // -> cmp x2, xzr (= cmp x2, #0)

    // 14) CMN.
    mov     x0, #0
    cmn     x2, x0                  // -> cmn x2, xzr

    // 15) AND.
    mov     x0, #0
    and     x3, x2, x0              // -> and x3, x2, xzr (= MOV X3, XZR)

    // 16) ORR -> MOV alias.
    mov     x0, #0
    orr     x3, x2, x0              // -> orr x3, x2, xzr (= MOV X3, X2)

    // 17) EOR.
    mov     x0, #0
    eor     x3, x2, x0              // -> eor x3, x2, xzr (= MOV X3, X2)

    // 18) TST.
    mov     x0, #0
    tst     x2, x0                  // -> tst x2, xzr

    // Negatives:
    // N1) Non-zero MOV value.
    mov     x0, #1
    str     x0, [x1]

    // N2) STR Rt != mov_rd.
    mov     x0, #0
    str     x2, [x1]

    // N3) STR base = mov_rd (Rn=X0 means SP if replaced).
    mov     x0, #0
    str     x2, [x0]                // not a fold candidate

    // N4) ALU op not reading mov_rd.
    mov     x0, #0
    add     x3, x1, x2

    // N5) LDUR into the zeroed register. The unscaled decoder covers
    //     loads and stores in one call, so only the is_store test
    //     keeps this out -- and a load overwrites the zero rather
    //     than reading it, leaving no ZR to substitute.
    mov     x0, #0
    ldur    x0, [x1, #-8]

    // N6) Unscaled store whose base is the zeroed register: the same
    //     hole as N3, and the same guard closes it.
    mov     x0, #0
    stur    x0, [x0, #-8]

    // N7) A compare of the zeroed register READS it, however Capstone
    //     flags the operand. CMP/CMN/TST drop their XZR destination,
    //     leaving the first source in slot 0 -- where it is marked
    //     written, the slot-0 convention. Believing that flag hands
    //     back a fold that deletes the zero this compare still reads.
    mov     x0, #0
    str     x0, [x1]
    cmp     x0, #1

    // N8) The same for the register form, and for TST in the logical-
    //     immediate class, which spells its S-variant as opc = 11
    //     rather than as a separate S bit.
    mov     x0, #0
    str     x0, [x1]
    cmn     x0, x2

    mov     x0, #0
    str     x0, [x1]
    tst     x0, #8

    // P) The rule is about the compare's OPERANDS, not about compares:
    //    one that never names the zeroed register leaves the fold
    //    alone.
    mov     x0, #0
    str     x0, [x1]                // -> str xzr, [x1]
    cmp     x2, x3

    // Pointer authentication is not a kill either. PACIA/AUTDB/XPACD
    // and the rest of the data-processing (1 source) PAC group rewrite
    // their destination IN PLACE -- sign it, authenticate it, strip
    // its PAC -- so a producer deleted ahead of one would change the
    // value it signs. .arch rather than an arm64e sidecar, so the
    // fixture still builds for ELF.
    .arch armv8.3-a

    // N9) Signing the zeroed register reads it.
    mov     x0, #0
    str     x0, [x1]
    pacia   x0, x2

    // N10) So does stripping it.
    mov     x0, #0
    str     x0, [x1]
    xpacd   x0

    // P) A PAC of some other register leaves the fold alone.
    mov     x0, #0
    str     x0, [x1]                // -> str xzr, [x1]
    pacia   x3, x2

    // P) PACGA is the exception that keeps the rule scoped to the
    //    1-source group: it computes a fresh MAC into Rd from Rn and
    //    Rm, so it really is a kill and the fold commits here.
    mov     x0, #0
    str     x0, [x1]                // -> str xzr, [x1]
    pacga   x0, x1, x2

    // N11) PACIA1716 names no operands: it transforms x17 using x16 as
    //      the modifier. Capstone reports both implicitly but lists
    //      x16 as WRITTEN, which is wrong -- x16 is read-only there.
    mov     x16, #0
    str     x16, [x1]
    pacia1716
    mov     x16, #1

    // P) CSEL with the zero in the then-slot.
    mov     x0, #0
    csel    x3, x0, x2, ne          // -> csel x3, xzr, x2, ne

    // P) CSNEG with the zero in the else-slot (whole select family).
    mov     w0, #0
    csneg   w3, w2, w0, lt          // -> csneg w3, w2, wzr, lt

    // P) Register CCMP with the zero as the left operand (the Rm
    //    slot folds to the #0 immediate form via the CCMP fold
    //    instead).
    mov     x0, #0
    ccmp    x0, x2, #4, ne          // -> ccmp xzr, x2, #4, ne

    // N12) Both select slots zero: csel_self owns that shape.
    mov     x0, #0
    csel    x3, x0, x0, ne

    ret
