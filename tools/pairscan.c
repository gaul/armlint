// pairscan: disassemble the AArch64 code in ELF files (ART OAT/odex) and
// count adjacent-instruction pairs by normalized shape, to surface frequent
// patterns worth new armlint checks.
//
// Normalization: mnemonic (b.<cc> folded to b.cc) + operand shapes.
// Register classes: w/x generic, but sp, zr, fp, lr, tr (r19, ART thread),
// mr (r20, ART marking), ip0/ip1 (r16/r17, VIXL scratch) kept distinct.
// Immediates: #0 vs #i. FP regs: s/d/q/h/b/v. Mem: [base], [base+i],
// [base+r...]; "!" appended on writeback.
//
// Pair flags: dep (second reads a register the first wrote),
// waw (second overwrites a register the first wrote without reading it).
// Pairs are skipped when the second insn is a branch target (side entry),
// when the first is an unconditional control transfer (b/br/ret), or across
// undecodable words / section boundaries.
//
// Usage: pairscan [-e SUBSTR -n MAXPRINT] <elf-file>...
//   default: print "count<TAB>tokA || tokB || flags" for all pairs (unsorted)
//   -e: additionally print example sites (file addr: textA ;; textB)

#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define HASH_BITS 22
#define HASH_SIZE (1u << HASH_BITS)

typedef struct {
    char *key;
    uint64_t count;
} entry;

static entry table[HASH_SIZE];
static uint64_t total_pairs = 0;
static const char *example_substr = NULL;
static long example_max = 20;
static long example_printed = 0;

static uint32_t hash_str(const char *s)
{
    uint32_t h = 5381;
    while (*s) h = h * 33 + (uint8_t)*s++;
    return h;
}

static void bump(const char *key)
{
    uint32_t h = hash_str(key) & (HASH_SIZE - 1);
    for (;;) {
        if (table[h].key == NULL) {
            table[h].key = strdup(key);
            table[h].count = 1;
            return;
        }
        if (strcmp(table[h].key, key) == 0) {
            table[h].count++;
            return;
        }
        h = (h + 1) & (HASH_SIZE - 1);
    }
}

// Canonical architectural slot for dependency tracking: 0-30 GPRs,
// 31 = sp, 64+n = FP/SIMD, -1 = ignore (zr, nzcv, ...).
static int reg_slot(unsigned r)
{
    if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) return (int)(r - ARM64_REG_W0);
    if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) return (int)(r - ARM64_REG_X0);
    if (r == ARM64_REG_FP) return 29;
    if (r == ARM64_REG_LR) return 30;
    if (r == ARM64_REG_SP || r == ARM64_REG_WSP) return 31;
    if (r >= ARM64_REG_B0 && r <= ARM64_REG_B31) return 64 + (int)(r - ARM64_REG_B0);
    if (r >= ARM64_REG_H0 && r <= ARM64_REG_H31) return 64 + (int)(r - ARM64_REG_H0);
    if (r >= ARM64_REG_S0 && r <= ARM64_REG_S31) return 64 + (int)(r - ARM64_REG_S0);
    if (r >= ARM64_REG_D0 && r <= ARM64_REG_D31) return 64 + (int)(r - ARM64_REG_D0);
    if (r >= ARM64_REG_Q0 && r <= ARM64_REG_Q31) return 64 + (int)(r - ARM64_REG_Q0);
    if (r >= ARM64_REG_V0 && r <= ARM64_REG_V31) return 64 + (int)(r - ARM64_REG_V0);
    return -1;
}

static const char *reg_class(unsigned r)
{
    if (r == ARM64_REG_SP || r == ARM64_REG_WSP) return "sp";
    if (r == ARM64_REG_XZR || r == ARM64_REG_WZR) return "zr";
    if (r == ARM64_REG_FP) return "fp";
    if (r == ARM64_REG_LR) return "lr";
    if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) {
        unsigned n = r - ARM64_REG_W0;
        if (n == 16) return "ip0";
        if (n == 17) return "ip1";
        if (n == 19) return "tr";
        if (n == 20) return "mr";
        if (n == 29) return "fp";
        if (n == 30) return "lr";
        return "w";
    }
    if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) {
        unsigned n = r - ARM64_REG_X0;
        if (n == 16) return "ip0";
        if (n == 17) return "ip1";
        if (n == 18) return "pr";
        if (n == 19) return "tr";
        if (n == 20) return "mr";
        return "x";
    }
    if (r >= ARM64_REG_B0 && r <= ARM64_REG_B31) return "b";
    if (r >= ARM64_REG_H0 && r <= ARM64_REG_H31) return "h";
    if (r >= ARM64_REG_S0 && r <= ARM64_REG_S31) return "s";
    if (r >= ARM64_REG_D0 && r <= ARM64_REG_D31) return "d";
    if (r >= ARM64_REG_Q0 && r <= ARM64_REG_Q31) return "q";
    if (r >= ARM64_REG_V0 && r <= ARM64_REG_V31) return "v";
    return "r?";
}

static const char *shift_name(arm64_shifter s)
{
    switch (s) {
    case ARM64_SFT_LSL: return "lsl";
    case ARM64_SFT_LSR: return "lsr";
    case ARM64_SFT_ASR: return "asr";
    case ARM64_SFT_ROR: return "ror";
    case ARM64_SFT_MSL: return "msl";
    default: return "sft";
    }
}

static const char *ext_name(arm64_extender e)
{
    switch (e) {
    case ARM64_EXT_UXTB: return "uxtb";
    case ARM64_EXT_UXTH: return "uxth";
    case ARM64_EXT_UXTW: return "uxtw";
    case ARM64_EXT_UXTX: return "uxtx";
    case ARM64_EXT_SXTB: return "sxtb";
    case ARM64_EXT_SXTH: return "sxth";
    case ARM64_EXT_SXTW: return "sxtw";
    case ARM64_EXT_SXTX: return "sxtx";
    default: return "ext";
    }
}

static void build_token(const cs_insn *insn, char *out, size_t outsz)
{
    const cs_arm64 *a = &insn->detail->arm64;
    char buf[160];
    size_t p = 0;
    // Fold conditional-branch condition codes into b.cc.
    if (insn->id == ARM64_INS_B && a->cc != ARM64_CC_INVALID &&
        a->cc != ARM64_CC_AL && a->cc != ARM64_CC_NV) {
        p += (size_t)snprintf(buf + p, sizeof buf - p, "b.cc");
    } else {
        p += (size_t)snprintf(buf + p, sizeof buf - p, "%s", insn->mnemonic);
    }
    for (int i = 0; i < a->op_count && p < sizeof buf - 24; i++) {
        const cs_arm64_op *op = &a->operands[i];
        buf[p++] = i == 0 ? ' ' : ',';
        switch (op->type) {
        case ARM64_OP_REG:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "%s", reg_class(op->reg));
            break;
        case ARM64_OP_IMM:
        case ARM64_OP_CIMM:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "%s",
                                  op->imm == 0 ? "#0" : "#i");
            break;
        case ARM64_OP_FP:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "#f");
            break;
        case ARM64_OP_MEM:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "[%s",
                                  reg_class(op->mem.base));
            if (op->mem.index != ARM64_REG_INVALID) {
                p += (size_t)snprintf(buf + p, sizeof buf - p, "+%s",
                                      reg_class(op->mem.index));
                if (op->ext != ARM64_EXT_INVALID)
                    p += (size_t)snprintf(buf + p, sizeof buf - p, ".%s",
                                          ext_name(op->ext));
                else if (op->shift.type != ARM64_SFT_INVALID)
                    p += (size_t)snprintf(buf + p, sizeof buf - p, ".%s",
                                          shift_name(op->shift.type));
            }
            if (op->mem.disp != 0)
                p += (size_t)snprintf(buf + p, sizeof buf - p, "+i");
            p += (size_t)snprintf(buf + p, sizeof buf - p, "]");
            continue;
        default:
            p += (size_t)snprintf(buf + p, sizeof buf - p, "sys");
            break;
        }
        if (op->type == ARM64_OP_REG || op->type == ARM64_OP_IMM) {
            if (op->ext != ARM64_EXT_INVALID)
                p += (size_t)snprintf(buf + p, sizeof buf - p, ".%s",
                                      ext_name(op->ext));
            else if (op->shift.type != ARM64_SFT_INVALID)
                p += (size_t)snprintf(buf + p, sizeof buf - p, ".%s",
                                      shift_name(op->shift.type));
        }
    }
    if (a->writeback && p < sizeof buf - 2)
        buf[p++] = '!';
    buf[p] = '\0';
    snprintf(out, outsz, "%s", buf);
}

// Branch-target bitset over one section (one bit per 4-byte word).
static uint8_t *mark_branch_targets(const uint8_t *code, size_t size)
{
    size_t words = size / 4;
    uint8_t *bits = calloc((words + 7) / 8, 1);
    if (!bits) return NULL;
    for (size_t i = 0; i < words; i++) {
        uint32_t w;
        memcpy(&w, code + i * 4, 4);
        int64_t off = 0;
        bool is_branch = false;
        if ((w >> 26) == 0x05 || (w >> 26) == 0x25) {           // B / BL
            off = ((int64_t)(int32_t)(w << 6) >> 6) * 4;        // imm26
            off = (int64_t)((int32_t)((w & 0x03FFFFFF) << 6)) >> 6;
            off *= 4;
            is_branch = true;
        } else if ((w & 0xFF000000) == 0x54000000) {            // B.cond/BC.cond
            off = ((int64_t)(int32_t)((w >> 5 & 0x7FFFF) << 13) >> 13) * 4;
            is_branch = true;
        } else if ((w & 0x7E000000) == 0x34000000) {            // CBZ/CBNZ
            off = ((int64_t)(int32_t)((w >> 5 & 0x7FFFF) << 13) >> 13) * 4;
            is_branch = true;
        } else if ((w & 0x7E000000) == 0x36000000) {            // TBZ/TBNZ
            off = ((int64_t)(int32_t)((w >> 5 & 0x3FFF) << 18) >> 18) * 4;
            is_branch = true;
        }
        if (is_branch) {
            int64_t tgt = (int64_t)i * 4 + off;
            if (tgt >= 0 && (uint64_t)tgt < size)
                bits[(size_t)tgt / 4 / 8] |= (uint8_t)(1u << ((size_t)tgt / 4 % 8));
        }
    }
    return bits;
}

static bool is_target(const uint8_t *bits, size_t off)
{
    return bits && (bits[off / 4 / 8] >> (off / 4 % 8) & 1);
}

static bool uncond_transfer(const cs_insn *insn)
{
    const cs_arm64 *a = &insn->detail->arm64;
    switch (insn->id) {
    case ARM64_INS_B:
        return a->cc == ARM64_CC_INVALID || a->cc == ARM64_CC_AL ||
               a->cc == ARM64_CC_NV;
    case ARM64_INS_BR:
    case ARM64_INS_RET:
    case ARM64_INS_ERET:
        return true;
    default:
        return false;
    }
}

static void scan_section(csh handle, const char *path, const uint8_t *code,
                         size_t size, uint64_t vaddr)
{
    uint8_t *targets = mark_branch_targets(code, size);
    cs_insn *insn = cs_malloc(handle);
    const uint8_t *p = code;
    size_t remain = size;
    uint64_t addr = vaddr;

    bool have_prev = false;
    char prev_tok[160];
    char prev_text[200];
    int prev_writes[16];
    int prev_nwrites = 0;

    while (remain >= 4) {
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            // Undecodable word (method header etc.): skip and reset chain.
            p += 4; remain -= 4; addr += 4;
            have_prev = false;
            continue;
        }
        if (insn->id == ARM64_INS_UDF || insn->id == ARM64_INS_BRK) {
            // OatQuickMethodHeader words / traps: treat as region boundary.
            have_prev = false;
            continue;
        }
        char tok[160];
        build_token(insn, tok, sizeof tok);

        cs_regs regs_read, regs_write;
        uint8_t nread = 0, nwrite = 0;
        cs_regs_access(handle, insn, regs_read, &nread, regs_write, &nwrite);

        size_t sec_off = (size_t)(insn->address - vaddr);
        if (have_prev && !is_target(targets, sec_off)) {
            bool dep = false, waw = false;
            for (int i = 0; i < prev_nwrites; i++) {
                int s = prev_writes[i];
                for (int j = 0; j < nread; j++)
                    if (reg_slot(regs_read[j]) == s) { dep = true; break; }
            }
            for (int i = 0; i < prev_nwrites && !waw; i++) {
                int s = prev_writes[i];
                bool w2 = false, r2 = false;
                for (int j = 0; j < nwrite; j++)
                    if (reg_slot(regs_write[j]) == s) { w2 = true; break; }
                for (int j = 0; j < nread; j++)
                    if (reg_slot(regs_read[j]) == s) { r2 = true; break; }
                if (w2 && !r2) waw = true;
            }
            char key[420];
            snprintf(key, sizeof key, "%s || %s || %s%s", prev_tok, tok,
                     dep ? "dep" : (waw ? "" : "-"), waw ? (dep ? ",waw" : "waw") : "");
            bump(key);
            total_pairs++;
            if (example_substr && example_printed < example_max &&
                strstr(key, example_substr)) {
                printf("EX %s %#" PRIx64 ": %s ;; %s %s\n", path,
                       insn->address - 4, prev_text, insn->mnemonic,
                       insn->op_str);
                example_printed++;
            }
        }

        // Current becomes prev unless it ends a straight-line region.
        if (uncond_transfer(insn)) {
            have_prev = false;
        } else {
            have_prev = true;
            memcpy(prev_tok, tok, sizeof prev_tok);
            snprintf(prev_text, sizeof prev_text, "%s %s", insn->mnemonic,
                     insn->op_str);
            prev_nwrites = 0;
            for (int j = 0; j < nwrite && prev_nwrites < 16; j++) {
                int s = reg_slot(regs_write[j]);
                if (s >= 0) prev_writes[prev_nwrites++] = s;
            }
        }
    }
    cs_free(insn, 1);
    free(targets);
}

static int scan_file(csh handle, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "%s: not a readable ELF file\n", path);
        close(fd);
        return -1;
    }
    size_t map_len = (size_t)st.st_size;
    uint8_t *base = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror(path); return -1; }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_AARCH64) {
        fprintf(stderr, "%s: not an AArch64 ELF64\n", path);
        munmap(base, map_len);
        return -1;
    }
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
    for (unsigned i = 0; i < eh->e_shnum; i++) {
        if ((sh[i].sh_flags & SHF_EXECINSTR) == 0 ||
            sh[i].sh_type != SHT_PROGBITS || sh[i].sh_size == 0)
            continue;
        if (sh[i].sh_offset + sh[i].sh_size > map_len) continue;
        scan_section(handle, path, base + sh[i].sh_offset, sh[i].sh_size,
                     sh[i].sh_addr);
    }
    munmap(base, map_len);
    return 0;
}

static int cmp_entry(const void *a, const void *b)
{
    const entry *ea = a, *eb = b;
    if (eb->count != ea->count) return eb->count > ea->count ? 1 : -1;
    return strcmp(ea->key, eb->key);
}

int main(int argc, char **argv)
{
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-e") == 0 && argi + 1 < argc) {
            example_substr = argv[++argi];
        } else if (strcmp(argv[argi], "-E") == 0 && argi + 1 < argc) {
            example_substr = argv[++argi];
            example_max = 1L << 60;
        } else if (strcmp(argv[argi], "-n") == 0 && argi + 1 < argc) {
            example_max = atol(argv[++argi]);
        } else {
            fprintf(stderr, "usage: %s [-e SUBSTR -n MAX] <elf>...\n", argv[0]);
            return 2;
        }
        argi++;
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: %s [-e SUBSTR -n MAX] <elf>...\n", argv[0]);
        return 2;
    }
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        fprintf(stderr, "capstone: cs_open failed\n");
        return 2;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    for (; argi < argc; argi++)
        scan_file(handle, argv[argi]);
    cs_close(&handle);

    size_t n = 0;
    for (size_t i = 0; i < HASH_SIZE; i++)
        if (table[i].key) n++;
    entry *flat = malloc(n * sizeof *flat);
    size_t k = 0;
    for (size_t i = 0; i < HASH_SIZE; i++)
        if (table[i].key) flat[k++] = table[i];
    qsort(flat, n, sizeof *flat, cmp_entry);
    fprintf(stderr, "TOTAL pairs=%" PRIu64 " distinct=%zu\n", total_pairs, n);
    for (size_t i = 0; i < n; i++)
        printf("%10" PRIu64 "  %s\n", flat[i].count, flat[i].key);
    return 0;
}
