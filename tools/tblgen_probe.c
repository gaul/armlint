// tblgen_probe: one line per A64 word on stdin, giving Capstone's view of
// it next to armlint's. tools/tblgen_audit.py drives it over one word
// per instruction record of LLVM's AArch64 tablegen and compares both
// against the record's own defs and uses.
//
// Output, space separated: the word; 1 if Capstone decoded it, else 0;
// mnemonic and operands (spaces replaced by '_'); whether Capstone's
// register-access lists hold an NZCV read and an NZCV write, and its
// update_flags bit; the GPR numbers (0..30) in its read and write lists,
// each comma separated between '|' bars; armlint's classify_liveness
// as a number; and classify_word_reg_liveness for registers 0..30 as one
// letter each (U unknown, O overwrite, R read, S safe terminator, T
// unsafe terminator). Register names go through cs_reg_name so the same
// source builds against Capstone 5 and 6.
#include <capstone/capstone.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "armlint.h"

static int gpr_of(csh handle, unsigned reg)
{
    const char *name = cs_reg_name(handle, reg);
    if (name == NULL || (name[0] != 'x' && name[0] != 'w')
            || name[1] < '0' || name[1] > '9') {
        return -1;
    }
    int n = atoi(name + 1);
    return n <= 30 ? n : -1;
}

int main(void)
{
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        fprintf(stderr, "cs_open failed\n");
        return 1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(handle);
    static const char codes[] = "UORST";
    char line[256];
    while (fgets(line, sizeof line, stdin) != NULL) {
        uint32_t word = (uint32_t)strtoul(line, NULL, 16);
        char cls[32];
        for (unsigned r = 0; r < 31; r++) {
            int c = (int)classify_word_reg_liveness(word, r);
            cls[r] = c >= 0 && c < 5 ? codes[c] : '?';
        }
        cls[31] = 0;
        int liv = (int)classify_liveness(word);
        const uint8_t *code = (const uint8_t *)&word;
        size_t size = 4;
        uint64_t address = 0;
        if (!cs_disasm_iter(handle, &code, &size, &address, insn)) {
            printf("%08x 0 - - 0 0 0 | | | %d %s\n", word, liv, cls);
            continue;
        }
        int reads_nzcv = 0, writes_nzcv = 0;
        char reads[256] = "", writes[256] = "";
        cs_regs regs_read, regs_write;
        uint8_t nread = 0, nwrite = 0;
        if (cs_regs_access(handle, insn, regs_read, &nread,
                           regs_write, &nwrite) == CS_ERR_OK) {
            for (uint8_t i = 0; i < nread; i++) {
                if (regs_read[i] == ARM64_REG_NZCV) {
                    reads_nzcv = 1;
                }
                int g = gpr_of(handle, regs_read[i]);
                if (g >= 0) {
                    char buf[8];
                    snprintf(buf, sizeof buf, "%d,", g);
                    strcat(reads, buf);
                }
            }
            for (uint8_t i = 0; i < nwrite; i++) {
                if (regs_write[i] == ARM64_REG_NZCV) {
                    writes_nzcv = 1;
                }
                int g = gpr_of(handle, regs_write[i]);
                if (g >= 0) {
                    char buf[8];
                    snprintf(buf, sizeof buf, "%d,", g);
                    strcat(writes, buf);
                }
            }
        }
        char ops[160];
        strncpy(ops, insn->op_str, sizeof ops);
        ops[sizeof ops - 1] = 0;
        for (char *p = ops; *p != 0; p++) {
            if (*p == ' ') {
                *p = '_';
            }
        }
        printf("%08x 1 %s %s %d %d %d | %s | %s | %d %s\n", word,
               insn->mnemonic, ops[0] != 0 ? ops : "-", reads_nzcv,
               writes_nzcv, (int)insn->detail->arm64.update_flags,
               reads, writes, liv, cls);
    }
    cs_free(insn, 1);
    cs_close(&handle);
    return 0;
}
