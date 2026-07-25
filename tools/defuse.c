// defuse: block-local def->use distance profiler for AArch64 code in ELF
// (ART OAT/odex) or Mach-O (macOS, thin or universal/fat) binaries.
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
// Usage: defuse [-e CAT -n MAX] <binary>...   (CAT: ext load mov dead reload remat cmp0)

#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// === Minimal ELF64 + Mach-O definitions (mirrors main.c) ===
//
// Darwin has no <elf.h> and Apple's <mach-o/*.h> pull in host-only
// types; reproducing the on-disk layouts keeps the tool single-file
// and buildable on both Linux and macOS.

#define EI_NIDENT     16
#define EI_CLASS      4
#define ELFMAG        "\x7f""ELF"
#define SELFMAG       4
#define ELFCLASS64    2
#define EM_AARCH64    183
#define SHT_PROGBITS  1
#define SHF_EXECINSTR 0x4

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

#define MH_MAGIC_64        0xfeedfacfu       // little-endian Mach-O 64
#define FAT_MAGIC          0xcafebabeu       // fat header, stored big-endian
#define FAT_MAGIC_64       0xcafebabfu       // fat header with 64-bit offsets
#define CPU_TYPE_ARM64     0x0100000cu       // includes arm64 and arm64e
#define LC_SEGMENT_64      0x19u
#define S_ATTR_PURE_INSTRUCTIONS 0x80000000u

typedef struct {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} mach_header_64;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} load_command_hdr;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
} segment_command_64;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} section_64;

typedef struct {
    uint32_t magic;
    uint32_t nfat_arch;
} fat_header;

typedef struct {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} fat_arch_32;

typedef struct {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint64_t offset;
    uint64_t size;
    uint32_t align;
    uint32_t reserved;
} fat_arch_64;

static uint32_t be32(uint32_t v)
{
    return ((v & 0xffu) << 24) | ((v & 0xff00u) << 8)
        | ((v & 0xff0000u) >> 8) | ((v >> 24) & 0xffu);
}

static uint64_t be64(uint64_t v)
{
    return ((uint64_t)be32((uint32_t)(v & 0xffffffffu)) << 32)
        | (uint64_t)be32((uint32_t)(v >> 32));
}

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

static void scan_section(csh handle, const char *path, const uint8_t *code,
                         size_t size, uint64_t vaddr)
{
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
    uint64_t addr = vaddr;
    long idx = 0;
    region_reset();

    while (remain >= 4) {
        if (!cs_disasm_iter(handle, &p, &remain, &addr, insn)) {
            p += 4; remain -= 4; addr += 4;
            region_reset();
            continue;
        }
        idx++;
        size_t off = (size_t)(insn->address - vaddr);
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

// ---- container walking: ELF64, thin Mach-O, universal/fat Mach-O ----

static int scan_elf(csh handle, const char *path, const uint8_t *base,
                    size_t map_len)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    if (map_len < sizeof *eh || eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_machine != EM_AARCH64) {
        fprintf(stderr, "%s: not an AArch64 ELF64\n", path);
        return -1;
    }
    if (eh->e_shoff > map_len ||
        (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > map_len - eh->e_shoff) {
        fprintf(stderr, "%s: section headers out of bounds\n", path);
        return -1;
    }
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);
    for (unsigned i = 0; i < eh->e_shnum; i++) {
        if ((sh[i].sh_flags & SHF_EXECINSTR) == 0 ||
            sh[i].sh_type != SHT_PROGBITS || sh[i].sh_size == 0)
            continue;
        if (sh[i].sh_offset > map_len ||
            sh[i].sh_size > map_len - sh[i].sh_offset)
            continue;
        scan_section(handle, path, base + sh[i].sh_offset, sh[i].sh_size,
                     sh[i].sh_addr);
    }
    return 0;
}

static int scan_macho_slice(csh handle, const char *path, const uint8_t *base,
                            size_t slice_off, uint64_t slice_size)
{
    const mach_header_64 *mh = (const mach_header_64 *)(base + slice_off);
    if (slice_size < sizeof *mh || mh->magic != MH_MAGIC_64) {
        fprintf(stderr, "%s: bad Mach-O header\n", path);
        return -1;
    }
    if ((uint32_t)mh->cputype != CPU_TYPE_ARM64) {
        fprintf(stderr, "%s: not an ARM64 Mach-O (cputype=0x%08x)\n", path,
                (uint32_t)mh->cputype);
        return -1;
    }
    if (mh->ncmds > 4096 ||
        (uint64_t)mh->sizeofcmds > slice_size - sizeof *mh) {
        fprintf(stderr, "%s: implausible load commands\n", path);
        return -1;
    }
    size_t lc_off = slice_off + sizeof *mh;
    size_t lc_end = lc_off + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc_off + sizeof(load_command_hdr) > lc_end) {
            fprintf(stderr, "%s: load command %u truncated\n", path, i);
            return -1;
        }
        const load_command_hdr *lc = (const load_command_hdr *)(base + lc_off);
        if (lc->cmdsize < sizeof *lc || lc->cmdsize > lc_end - lc_off) {
            fprintf(stderr, "%s: invalid cmdsize on load command %u\n",
                    path, i);
            return -1;
        }
        if (lc->cmd == LC_SEGMENT_64 &&
            lc->cmdsize >= sizeof(segment_command_64)) {
            const segment_command_64 *seg = (const segment_command_64 *)lc;
            if (seg->nsects > 1024 ||
                sizeof *seg + (uint64_t)seg->nsects * sizeof(section_64) >
                    lc->cmdsize) {
                fprintf(stderr, "%s: section headers overflow segment\n",
                        path);
                return -1;
            }
            const section_64 *sec =
                (const section_64 *)(base + lc_off + sizeof *seg);
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (!(sec[j].flags & S_ATTR_PURE_INSTRUCTIONS) ||
                    sec[j].size == 0)
                    continue;
                if ((uint64_t)sec[j].offset > slice_size ||
                    sec[j].size > slice_size - sec[j].offset)
                    continue;
                scan_section(handle, path, base + slice_off + sec[j].offset,
                             (size_t)sec[j].size, sec[j].addr);
            }
        }
        lc_off += lc->cmdsize;
    }
    return 0;
}

static int scan_fat(csh handle, const char *path, const uint8_t *base,
                    size_t map_len, bool is_fat_64)
{
    const fat_header *fh = (const fat_header *)base;
    uint32_t nfat = be32(fh->nfat_arch);
    size_t arch_size = is_fat_64 ? sizeof(fat_arch_64) : sizeof(fat_arch_32);
    if (nfat > 256 || sizeof *fh + (uint64_t)nfat * arch_size > map_len) {
        fprintf(stderr, "%s: implausible fat header\n", path);
        return -1;
    }
    bool found = false;
    for (uint32_t i = 0; i < nfat; i++) {
        uint32_t cputype;
        uint64_t off, size;
        const uint8_t *entry = base + sizeof *fh + i * arch_size;
        if (is_fat_64) {
            const fat_arch_64 *a = (const fat_arch_64 *)entry;
            cputype = be32(a->cputype);
            off = be64(a->offset);
            size = be64(a->size);
        } else {
            const fat_arch_32 *a = (const fat_arch_32 *)entry;
            cputype = be32(a->cputype);
            off = (uint64_t)be32(a->offset);
            size = (uint64_t)be32(a->size);
        }
        if (cputype != CPU_TYPE_ARM64) continue;
        found = true;
        if (off > map_len || size > map_len - off) {
            fprintf(stderr, "%s: fat arch %u out of bounds\n", path, i);
            return -1;
        }
        if (scan_macho_slice(handle, path, base, (size_t)off, size) != 0)
            return -1;
    }
    if (!found) {
        fprintf(stderr, "%s: fat binary contains no ARM64 slice\n", path);
        return -1;
    }
    return 0;
}

static int scan_file(csh handle, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 4) {
        fprintf(stderr, "%s: not a readable binary\n", path);
        close(fd);
        return -1;
    }
    size_t map_len = (size_t)st.st_size;
    uint8_t *base = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror(path); return -1; }

    // Mach-O magic is stored host-endian (always little on ARM64); fat
    // magic is stored big-endian on disk.
    uint32_t m_le = (uint32_t)base[0] | ((uint32_t)base[1] << 8) |
                    ((uint32_t)base[2] << 16) | ((uint32_t)base[3] << 24);
    uint32_t m_be = ((uint32_t)base[0] << 24) | ((uint32_t)base[1] << 16) |
                    ((uint32_t)base[2] << 8) | (uint32_t)base[3];
    int rc;
    if (memcmp(base, ELFMAG, SELFMAG) == 0) {
        rc = scan_elf(handle, path, base, map_len);
    } else if (m_le == MH_MAGIC_64) {
        rc = scan_macho_slice(handle, path, base, 0, map_len);
    } else if (m_be == FAT_MAGIC) {
        rc = scan_fat(handle, path, base, map_len, false);
    } else if (m_be == FAT_MAGIC_64) {
        rc = scan_fat(handle, path, base, map_len, true);
    } else {
        fprintf(stderr, "%s: unsupported file format\n", path);
        rc = -1;
    }
    munmap(base, map_len);
    return rc;
}

int main(int argc, char **argv)
{
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (!strcmp(argv[argi], "-e") && argi + 1 < argc) example_cat = argv[++argi];
        else if (!strcmp(argv[argi], "-n") && argi + 1 < argc) example_max = atol(argv[++argi]);
        else { fprintf(stderr, "usage: %s [-e CAT -n MAX] <binary>...\n", argv[0]); return 2; }
        argi++;
    }
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) return 2;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    for (; argi < argc; argi++)
        scan_file(handle, argv[argi]);
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
