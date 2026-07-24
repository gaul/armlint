// defuse: block-local def->use distance profiler for AArch64 ART code.
//
// Answers "does armlint need deeper-than-adjacent analysis?" with numbers:
// for several def patterns, how far away is the sole consumer, and how many
// multi-instruction-only redundancies (dead defs, redundant reloads,
// re-materialized constants, CMP #0 after a flag-capable ALU op) exist that
// no pair check can see.
//
// Region discipline (mirrors armlint): tracking fully resets at branch
// targets (side entries), calls (bl/blr), unconditional transfers, and
// undecodable words. Conditional branches/cbz/tbz do NOT reset; defs whose
// use lies beyond one are tagged "xbr" (would need path reasoning).
//
// Def patterns profiled (sole-use only, def and use both in-region):
//   ext   : sxtb/sxth/sxtw/uxtb/uxth rd, rn        -> consumer class
//   load  : ldrb/ldrh/ldr-w rt, [..]               -> consumer sxt*/uxt*/and
//   mov   : mov rd, rm (orr-zr / register mov)     -> any consumer
// Multi-instruction-only categories:
//   dead  : pure ALU/mov/extend def overwritten with zero uses
//   reload: ldr* same (base,disp,size) again, no store/call/dmb/base-redef
//   remat : movz/movn/mov-imm of a value already live in another register
//   cmp0  : cmp rn, #0 where rn's def was add/sub/and/orr/eor/bic (S-form
//           exists) and no flag writer sits between def and cmp
//
// Usage: defuse [-e CAT -n MAX] <elf>...   (CAT: ext load mov dead reload remat cmp0)

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

#define NSLOT 96  // 0-30 GPR, 31 sp, 64+ FP

static const char *example_cat = NULL;
static long example_max = 20, example_printed = 0;

typedef struct {
    uint64_t c[6];  // distance buckets 1,2,3,4-7,8-15,16+
} hist;

static int bucket(long d)
{
    return d <= 1 ? 0 : d == 2 ? 1 : d == 3 ? 2 : d <= 7 ? 3 : d <= 15 ? 4 : 5;
}

// key -> histogram, tiny open hash
typedef struct { char *key; hist h; uint64_t n; } entry;
#define HB 16
#define HS (1u << HB)
static entry table[HS];

static void bump(const char *key, long dist)
{
    uint32_t h = 5381;
    for (const char *s = key; *s; s++) h = h * 33 + (uint8_t)*s;
    h &= HS - 1;
    for (;;) {
        if (!table[h].key) { table[h].key = strdup(key); break; }
        if (!strcmp(table[h].key, key)) break;
        h = (h + 1) & (HS - 1);
    }
    table[h].n++;
    if (dist >= 0) table[h].h.c[bucket(dist)]++;
}

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

// ---- per-region state ----

typedef struct {
    bool live;          // def being tracked
    long idx;           // instruction index of def
    uint64_t adr;
    char text[192];
    int uses;           // uses seen since def
    long first_use_idx; // index of first (and, if uses==1, sole) use
    char first_use_cls[24];
    bool xbr;           // a conditional branch sits between def and now
    char kind;          // 'e' ext, 'l' load, 'm' mov, 'a' alu (cmp0/dead), 0
    char detail[40];    // mnemonic / extend kind
    bool pure;          // no side effects: candidate for dead-def counting
} defrec;

typedef struct {
    bool live;
    long idx;
    int base;           // slot
    int64_t disp;
    int size;           // access bytes
    int dest;           // slot loaded into
} loadrec;

typedef struct {
    bool live;
    long idx;
    int64_t val;
    int slot;
} constrec;

static defrec defs[NSLOT];
static loadrec loads[64];
static int nloads;
static constrec consts[48];
static int nconsts;
static int flags_def_slot = -1;   // slot whose defining ALU op could take S-form
static long flags_def_idx = -1;
static char flags_def_mn[32];

static uint64_t region_events[8];

static void region_reset(void)
{
    memset(defs, 0, sizeof defs);
    nloads = 0;
    nconsts = 0;
    flags_def_slot = -1;
}

static const char *use_class(const cs_insn *insn)
{
    switch (insn->id) {
    case ARM64_INS_SXTB: case ARM64_INS_SXTH: case ARM64_INS_SXTW:
    case ARM64_INS_UXTB: case ARM64_INS_UXTH:
        return "extend";
    case ARM64_INS_SBFX: case ARM64_INS_SBFIZ: case ARM64_INS_UBFX:
    case ARM64_INS_UBFIZ: case ARM64_INS_SBFM: case ARM64_INS_UBFM:
        return "bitfield";
    case ARM64_INS_ADD: case ARM64_INS_SUB:
        return "addsub";
    case ARM64_INS_CMP: case ARM64_INS_CMN:
        return "cmp";
    case ARM64_INS_AND: case ARM64_INS_ORR: case ARM64_INS_EOR:
    case ARM64_INS_BIC:
        return "logic";
    case ARM64_INS_LDR: case ARM64_INS_LDRB: case ARM64_INS_LDRH:
    case ARM64_INS_LDRSB: case ARM64_INS_LDRSH: case ARM64_INS_LDRSW:
    case ARM64_INS_LDUR: case ARM64_INS_LDP:
        return "load";
    case ARM64_INS_STR: case ARM64_INS_STRB: case ARM64_INS_STRH:
    case ARM64_INS_STUR: case ARM64_INS_STP: case ARM64_INS_STLR:
    case ARM64_INS_STLRB: case ARM64_INS_STLRH:
        return "store";
    case ARM64_INS_MOV:
        return "mov";
    case ARM64_INS_CBZ: case ARM64_INS_CBNZ: case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
        return "cbranch";
    case ARM64_INS_LSL: case ARM64_INS_LSR: case ARM64_INS_ASR:
        return "shift";
    case ARM64_INS_MUL: case ARM64_INS_MADD: case ARM64_INS_MSUB:
    case ARM64_INS_SMULL: case ARM64_INS_UMULL:
        return "mul";
    default:
        return "other";
    }
}

static bool writes_flags(csh handle, const cs_insn *insn)
{
    const cs_arm64 *a = &insn->detail->arm64;
    if (a->update_flags) return true;
    switch (insn->id) {
    case ARM64_INS_CMP: case ARM64_INS_CMN: case ARM64_INS_TST:
    case ARM64_INS_CCMP: case ARM64_INS_CCMN: case ARM64_INS_FCMP:
    case ARM64_INS_FCMPE:
        return true;
    default:
        return false;
    }
    (void)handle;
}

static void finalize_def(int s, const char *why, const char *path, const char *rtext)
{
    defrec *d = &defs[s];
    if (!d->live) return;
    char key[96];
    if (d->uses == 0 && d->pure && strcmp(why, "redef") == 0) {
        snprintf(key, sizeof key, "dead|%c|%s%s", d->kind, d->detail,
                 d->xbr ? "|xbr" : "");
        bump(key, -1);
        if (example_cat && !strcmp(example_cat, "dead") &&
            example_printed < example_max) {
            printf("EX dead %s %#" PRIx64 ": %s ;; killed+%ld by %s\n", path,
                   d->adr, d->text, 0L, rtext);
            example_printed++;
        }
    } else if (d->uses == 1) {
        snprintf(key, sizeof key, "sole|%c|%s->%s%s", d->kind, d->detail,
                 d->first_use_cls, d->xbr ? "|xbr" : "");
        bump(key, d->first_use_idx - d->idx);
    } else if (d->uses > 1) {
        snprintf(key, sizeof key, "multi|%c|%s", d->kind, d->detail);
        bump(key, -1);
    }
    d->live = false;
}

int main(int argc, char **argv)
{
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (!strcmp(argv[argi], "-e") && argi + 1 < argc) example_cat = argv[++argi];
        else if (!strcmp(argv[argi], "-n") && argi + 1 < argc) example_max = atol(argv[++argi]);
        else { fprintf(stderr, "usage: %s [-e CAT -n MAX] <elf>...\n", argv[0]); return 2; }
        argi++;
    }
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) return 2;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    for (; argi < argc; argi++) {
        const char *path = argv[argi];
        int fd = open(path, O_RDONLY);
        if (fd < 0) { perror(path); continue; }
        struct stat st;
        fstat(fd, &st);
        uint8_t *base = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (base == MAP_FAILED) { perror(path); continue; }
        const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
        if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_machine != EM_AARCH64) {
            munmap(base, (size_t)st.st_size); continue;
        }
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
        for (unsigned si = 0; si < eh->e_shnum; si++) {
            if (!(sh[si].sh_flags & SHF_EXECINSTR) || sh[si].sh_type != SHT_PROGBITS ||
                sh[si].sh_size == 0) continue;
            const uint8_t *code = base + sh[si].sh_offset;
            size_t size = sh[si].sh_size;

            // branch-target bitset (same decoding as pairscan)
            size_t words = size / 4;
            uint8_t *bits = calloc(words / 8 + 1, 1);
            for (size_t i = 0; i < words; i++) {
                uint32_t w; memcpy(&w, code + i * 4, 4);
                int64_t off = 0; bool br = false;
                if ((w >> 26) == 0x05 || (w >> 26) == 0x25) {
                    off = ((int64_t)((int32_t)((w & 0x03FFFFFF) << 6)) >> 6) * 4; br = true;
                } else if ((w & 0xFF000000) == 0x54000000 ||
                           (w & 0x7E000000) == 0x34000000) {
                    off = ((int64_t)(int32_t)(((w >> 5) & 0x7FFFF) << 13) >> 13) * 4; br = true;
                } else if ((w & 0x7E000000) == 0x36000000) {
                    off = ((int64_t)(int32_t)(((w >> 5) & 0x3FFF) << 18) >> 18) * 4; br = true;
                }
                if (br) {
                    int64_t t = (int64_t)i * 4 + off;
                    if (t >= 0 && (uint64_t)t < size) bits[(size_t)t / 4 / 8] |= 1u << ((size_t)t / 4 % 8);
                }
            }

            cs_insn *insn = cs_malloc(handle);
            const uint8_t *p = code;
            size_t remain = size;
            uint64_t addr = sh[si].sh_addr;
            long idx = 0;
            region_reset();

            while (remain >= 4) {
                if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
                    p += 4; remain -= 4; addr += 4;
                    region_reset();
                    continue;
                }
                idx++;
                size_t off = (size_t)(insn->address - sh[si].sh_addr);
                if (bits[off / 4 / 8] >> (off / 4 % 8) & 1) region_reset();
                if (insn->id == ARM64_INS_UDF || insn->id == ARM64_INS_BRK) {
                    region_reset(); continue;
                }
                const cs_arm64 *a = &insn->detail->arm64;

                cs_regs rr, rw; uint8_t nr = 0, nw = 0;
                cs_regs_access(handle, insn, rr, &nr, rw, &nw);
                // capstone models CMP/CMN/TST (SUBS/ADDS/ANDS-to-zr aliases)
                // as writing their first operand; force compare operands to
                // reads and drop their bogus GPR writes.
                if (insn->id == ARM64_INS_CMP || insn->id == ARM64_INS_CMN ||
                    insn->id == ARM64_INS_TST || insn->id == ARM64_INS_CCMP ||
                    insn->id == ARM64_INS_CCMN) {
                    nw = 0;
                    nr = 0;
                    for (int j = 0; j < a->op_count && nr < 6; j++)
                        if (a->operands[j].type == ARM64_OP_REG)
                            rr[nr++] = a->operands[j].reg;
                }

                // ---- uses ----
                for (int j = 0; j < nr; j++) {
                    int s = reg_slot(rr[j]);
                    if (s < 0 || s >= NSLOT) continue;
                    defrec *d = &defs[s];
                    if (d->live) {
                        d->uses++;
                        if (d->uses == 1) {
                            d->first_use_idx = idx;
                            snprintf(d->first_use_cls, sizeof d->first_use_cls,
                                     "%s", use_class(insn));
                            if (example_cat && d->kind ==
                                (!strcmp(example_cat, "ext") ? 'e' :
                                 !strcmp(example_cat, "load") ? 'l' :
                                 !strcmp(example_cat, "mov") ? 'm' : 0) &&
                                idx - d->idx > 1 && example_printed < example_max) {
                                printf("EX %s %s %#" PRIx64 ": d=%ld %s -> %s %s\n",
                                       example_cat, path, insn->address,
                                       idx - d->idx, d->detail, insn->mnemonic,
                                       insn->op_str);
                                example_printed++;
                            }
                        }
                    }
                }

                // ---- cmp #0 against S-capable def ----
                if (insn->id == ARM64_INS_CMP && a->op_count == 2 &&
                    a->operands[1].type == ARM64_OP_IMM && a->operands[1].imm == 0 &&
                    a->operands[0].type == ARM64_OP_REG) {
                    int s = reg_slot(a->operands[0].reg);
                    if (s >= 0 && s == flags_def_slot) {
                        char key[64];
                        snprintf(key, sizeof key, "cmp0|%s", flags_def_mn);
                        bump(key, idx - flags_def_idx);
                        if (example_cat && !strcmp(example_cat, "cmp0") &&
                            example_printed < example_max) {
                            printf("EX cmp0 %s %#" PRIx64 ": d=%ld %s\n", path,
                                   insn->address, idx - flags_def_idx, flags_def_mn);
                            example_printed++;
                        }
                    }
                }
                if (writes_flags(handle, insn)) { flags_def_slot = -1; }

                // ---- redundant reload / store invalidation ----
                bool is_store = false, is_call = false, is_barrier = false;
                switch (insn->id) {
                case ARM64_INS_STR: case ARM64_INS_STRB: case ARM64_INS_STRH:
                case ARM64_INS_STUR: case ARM64_INS_STURB: case ARM64_INS_STURH:
                case ARM64_INS_STP: case ARM64_INS_STLR: case ARM64_INS_STLRB:
                case ARM64_INS_STLRH: case ARM64_INS_STXR: case ARM64_INS_STLXR:
                    is_store = true; break;
                case ARM64_INS_BL: case ARM64_INS_BLR:
                    is_call = true; break;
                case ARM64_INS_DMB: case ARM64_INS_DSB: case ARM64_INS_ISB:
                case ARM64_INS_LDAR: case ARM64_INS_LDARB: case ARM64_INS_LDARH:
                case ARM64_INS_LDAXR: case ARM64_INS_LDXR:
                    is_barrier = true; break;
                default: break;
                }
                if (is_store || is_call || is_barrier) nloads = 0;

                int ldsize = 0;
                switch (insn->id) {
                case ARM64_INS_LDRB: ldsize = 1; break;
                case ARM64_INS_LDRH: ldsize = 2; break;
                case ARM64_INS_LDR:
                    if (a->op_count >= 1 && a->operands[0].type == ARM64_OP_REG) {
                        unsigned r = a->operands[0].reg;
                        ldsize = (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) ||
                                 r == ARM64_REG_XZR || r == ARM64_REG_LR ||
                                 r == ARM64_REG_FP ? 8 : 4;
                    }
                    break;
                default: break;
                }
                if (ldsize && a->op_count == 2 && a->operands[1].type == ARM64_OP_MEM &&
                    a->operands[1].mem.index == ARM64_REG_INVALID && !a->writeback) {
                    int bs = reg_slot(a->operands[1].mem.base);
                    int dest = a->operands[0].type == ARM64_OP_REG ?
                               reg_slot(a->operands[0].reg) : -1;
                    if (bs >= 0) {
                        for (int k = 0; k < nloads; k++) {
                            loadrec *L = &loads[k];
                            if (L->live && L->base == bs && L->disp == a->operands[1].mem.disp &&
                                L->size == ldsize) {
                                char key[64];
                                snprintf(key, sizeof key, "reload|%s|sz%d",
                                         bs == 31 ? "sp" : bs == 19 ? "tr" : "heap", ldsize);
                                bump(key, idx - L->idx);
                                if (example_cat && !strcmp(example_cat, "reload") &&
                                    example_printed < example_max) {
                                    printf("EX reload %s %#" PRIx64 ": d=%ld [%d+%" PRId64 "] sz%d\n",
                                           path, insn->address, idx - L->idx, bs,
                                           (int64_t)a->operands[1].mem.disp, ldsize);
                                    example_printed++;
                                }
                                L->idx = idx;  // re-arm from the later load
                            }
                        }
                        if (nloads < 64) {
                            loads[nloads++] = (loadrec){true, idx, bs,
                                a->operands[1].mem.disp, ldsize, dest};
                        }
                    }
                }

                // ---- writes: finalize + invalidate ----
                for (int j = 0; j < nw; j++) {
                    int s = reg_slot(rw[j]);
                    if (s < 0 || s >= NSLOT) continue;
                    char rtext[192];
                    snprintf(rtext, sizeof rtext, "%s %s", insn->mnemonic, insn->op_str);
                    finalize_def(s, "redef", path, rtext);
                    // loads/consts keyed on a clobbered base/slot die
                    for (int k = 0; k < nloads; k++)
                        if (loads[k].live && loads[k].base == s) loads[k].live = false;
                    for (int k = 0; k < nconsts; k++)
                        if (consts[k].live && consts[k].slot == s) consts[k].live = false;
                    if (flags_def_slot == s) flags_def_slot = -1;
                }

                // ---- new defs ----
                bool has_mem_write = is_store;
                int dslot = -1;
                if (a->op_count >= 1 && a->operands[0].type == ARM64_OP_REG &&
                    !has_mem_write) {
                    for (int j = 0; j < nw; j++)
                        if (reg_slot(rw[j]) == reg_slot(a->operands[0].reg))
                            { dslot = reg_slot(a->operands[0].reg); break; }
                }
                if (dslot >= 0 && dslot < NSLOT && dslot != 31) {
                    defrec *d = &defs[dslot];
                    uint64_t def_adr = insn->address;
                    char def_text[192];
                    snprintf(def_text, sizeof def_text, "%s %s", insn->mnemonic, insn->op_str);
                    switch (insn->id) {
                    case ARM64_INS_SXTB: case ARM64_INS_SXTH: case ARM64_INS_SXTW:
                    case ARM64_INS_UXTB: case ARM64_INS_UXTH:
                        { memset(d, 0, sizeof *d); d->live = true; d->idx = idx; d->kind = 'e'; d->pure = true; }
                        snprintf(d->detail, sizeof d->detail, "%s", insn->mnemonic);
                        break;
                    case ARM64_INS_LDRB: case ARM64_INS_LDRH:
                        { memset(d, 0, sizeof *d); d->live = true; d->idx = idx; d->kind = 'l'; d->pure = false; }
                        snprintf(d->detail, sizeof d->detail, "%s", insn->mnemonic);
                        break;
                    case ARM64_INS_LDR:
                        if (ldsize == 4) {
                            { memset(d, 0, sizeof *d); d->live = true; d->idx = idx; d->kind = 'l'; d->pure = false; snprintf(d->detail, sizeof d->detail, "%s", "ldrw"); }
                        }
                        break;
                    case ARM64_INS_MOV:
                        if (a->op_count == 2 && a->operands[1].type == ARM64_OP_REG) {
                            int src = reg_slot(a->operands[1].reg);
                            if (src >= 0 && src != 31) {
                                { memset(d, 0, sizeof *d); d->live = true; d->idx = idx; d->kind = 'm'; d->pure = true; snprintf(d->detail, sizeof d->detail, "%s", "movrr"); }
                            }
                        } else if (a->op_count == 2 && a->operands[1].type == ARM64_OP_IMM) {
                            // constant re-materialization tracking
                            int64_t v = a->operands[1].imm;
                            for (int k = 0; k < nconsts; k++)
                                if (consts[k].live && consts[k].val == v &&
                                    consts[k].slot != dslot) {
                                    bump("remat|movimm", idx - consts[k].idx);
                                    if (example_cat && !strcmp(example_cat, "remat") &&
                                        example_printed < example_max) {
                                        printf("EX remat %s %#" PRIx64 ": d=%ld #%" PRId64 "\n",
                                               path, insn->address, idx - consts[k].idx, v);
                                        example_printed++;
                                    }
                                    break;
                                }
                            if (nconsts < 48)
                                consts[nconsts++] = (constrec){true, idx, v, dslot};
                            { memset(d, 0, sizeof *d); d->live = true; d->idx = idx; d->kind = 'a'; d->pure = true; snprintf(d->detail, sizeof d->detail, "%s", "movimm"); }
                        }
                        break;
                    case ARM64_INS_ADD: case ARM64_INS_SUB: case ARM64_INS_AND:
                    case ARM64_INS_ORR: case ARM64_INS_EOR: case ARM64_INS_BIC:
                        if (!a->update_flags) {
                            { memset(d, 0, sizeof *d); d->live = true; d->idx = idx; d->kind = 'a'; d->pure = true; }
                            snprintf(d->detail, sizeof d->detail, "%s", insn->mnemonic);
                            flags_def_slot = dslot;
                            flags_def_idx = idx;
                            snprintf(flags_def_mn, sizeof flags_def_mn, "%s", insn->mnemonic);
                        }
                        break;
                    default:
                        d->live = false;  // untracked def kinds stop tracking the slot
                        break;
                    }
                    if (d->live && d->idx == idx) {
                        d->adr = def_adr;
                        snprintf(d->text, sizeof d->text, "%s", def_text);
                    }
                }

                // conditional branches taint open defs
                if (insn->id == ARM64_INS_CBZ || insn->id == ARM64_INS_CBNZ ||
                    insn->id == ARM64_INS_TBZ || insn->id == ARM64_INS_TBNZ ||
                    (insn->id == ARM64_INS_B && a->cc != ARM64_CC_INVALID &&
                     a->cc != ARM64_CC_AL && a->cc != ARM64_CC_NV)) {
                    for (int s = 0; s < NSLOT; s++)
                        if (defs[s].live) defs[s].xbr = true;
                }

                // region enders
                if (insn->id == ARM64_INS_RET || insn->id == ARM64_INS_BR ||
                    insn->id == ARM64_INS_ERET ||
                    (insn->id == ARM64_INS_B && (a->cc == ARM64_CC_INVALID ||
                     a->cc == ARM64_CC_AL || a->cc == ARM64_CC_NV))) {
                    region_reset();
                } else if (is_call) {
                    region_reset();
                }
                region_events[0]++;
            }
            cs_free(insn, 1);
            free(bits);
        }
        munmap(base, (size_t)st.st_size);
    }
    cs_close(&handle);

    fprintf(stderr, "insns=%" PRIu64 "\n", region_events[0]);
    // sort and print
    size_t n = 0;
    for (size_t i = 0; i < HS; i++) if (table[i].key) n++;
    entry *flat = malloc(n * sizeof *flat);
    size_t k = 0;
    for (size_t i = 0; i < HS; i++) if (table[i].key) flat[k++] = table[i];
    for (size_t i = 0; i < n; i++)
        for (size_t j = i + 1; j < n; j++)
            if (flat[j].n > flat[i].n) { entry t = flat[i]; flat[i] = flat[j]; flat[j] = t; }
    printf("%-46s %10s | %8s %8s %8s %8s %8s %8s\n", "pattern", "total",
           "d1", "d2", "d3", "d4-7", "d8-15", "d16+");
    for (size_t i = 0; i < n; i++) {
        entry *e = &flat[i];
        printf("%-46s %10" PRIu64 " | %8" PRIu64 " %8" PRIu64 " %8" PRIu64
               " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 "\n", e->key, e->n,
               e->h.c[0], e->h.c[1], e->h.c[2], e->h.c[3], e->h.c[4], e->h.c[5]);
    }
    return 0;
}
