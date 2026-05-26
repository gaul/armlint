// Integration fixture for check_mov_reg_self.

    .text
    .globl  _main
    .p2align 2
_main:
    // Positive: literal MOV Xd, Xd no-op.
    mov     x0, x0

    // Positive: any X-form register.
    mov     x5, x5

    // Negative: MOV Xd, Xn (different source register) -- real move.
    mov     x1, x2

    // Negative: W-form MOV Wd, Wd is handled by check_redundant_zext
    // (it zero-extends X[63:32]); not flagged here.
    mov     w3, w3

    // Negative: MOV with SP -- different encoding entirely (ADD-imm
    // with sh=0, imm12=0, Rn=31 or Rd=31).
    mov     sp, x4

    ret
