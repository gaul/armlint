// Integration fixture for check_bcond_over_one: a conditional branch
// over one instruction a conditional select spells. The select keeps
// the register when the branch's condition holds and otherwise does
// what the skipped instruction did; nothing writes NZCV, so no proof is
// needed beyond the side-entry gate.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: V8 Maglev's return clamp, max(argc, formal count).
    cmp     x10, x9
    b.ge    L_1
    mov     x10, x9                     // -> csel x10, x10, x9, ge
L_1:
    // Positive: SpiderMonkey's wasm baseline float compare.
    mov     w0, #1
    fcmp    s1, s0
    b.ge    L_2
    mov     w0, #0                      // -> csel w0, w0, wzr, ge
L_2:
    // Positive: the constants a select spells, and the in-place forms.
    // A W form writes Wd on the keep path too, so it needs the top
    // half of Xd known zero: the W loads ahead of w6 and w8 give it.
    cmp     w3, #4
    b.ne    L_3
    mov     x5, #1                      // -> csinc x5, x5, xzr, ne
L_3:
    ldr     w6, [sp]
    b.eq    L_4
    mov     w6, #-1                     // -> csinv w6, w6, wzr, eq
L_4:
    b.ls    L_5
    add     x7, x7, #1                  // -> cinc x7, x7, hi
L_5:
    ldr     w8, [sp, #8]
    b.mi    L_6
    neg     w8, w8                      // -> cneg w8, w8, pl
L_6:
    b.vs    L_7
    mvn     x11, x11                    // -> cinv x11, x11, vc
L_7:
    // Negative: a W form with nothing known of the top half, a
    // constant no select spells, an ADD to another register, two
    // instructions, a flag setter.
    b.ne    L_8
    mov     w12, w13
L_8:
    b.ne    L_8b
    mov     x12, #2
L_8b:
    b.ne    L_9
    add     x13, x14, #1
L_9:
    b.ne    L_10
    mov     x15, x16
    mov     x17, x18
L_10:
    b.ne    L_11
    adds    x19, x19, #1
L_11:
    // Negative: a branch onto the skipped instruction from elsewhere.
    b.ne    L_12
L_side:
    mov     x20, x21
L_12:
    cbz     w22, L_side
    ret
