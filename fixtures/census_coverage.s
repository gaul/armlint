// Integration fixture for the -i census's per-function pac-ret
// coverage (-i via the .flags sidecar). The two .globl labels are the
// function boundaries on both host object formats; _signed opens with
// the hint-space PACIASP (and closes with AUTIASP, so the PAC tally
// is 2), _leaf never signs -- a legitimate shape, which is why
// coverage is a census line and not a finding. Expect "1 of 2".

    .text
    .globl  _signed
    .p2align 2
_signed:
    paciasp
    nop
    autiasp
    ret

    .globl  _leaf
    .p2align 2
_leaf:
    nop
    ret
