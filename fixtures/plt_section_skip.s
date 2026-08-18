// The ELF analogue of the Mach-O stub-section skip: .plt (with .iplt
// and the .plt.* variants) holds fixed-format linker trampolines
// whose shape is the psABI's business, not the compiler's. The stub
// body below is shaped to trip the LDR-literal check if the section
// were ever scanned; only the .text copy may surface a finding.
//
// ELF-only section syntax, so the .format sidecar assembles this
// fixture as ELF on every host.

    .text
    .globl  main
    .p2align 2
main:
    ldr     w0, 1f                  // -> mov w0, #0x2a: a real finding
    ret
1:
    .long   42

    .section .plt,"ax",@progbits
    .p2align 2
    ldr     w16, 1f                 // silent: PLT glue
    br      x16
1:
    .long   0x2a
