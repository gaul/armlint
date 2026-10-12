/*
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <capstone/capstone.h>

#include "armlint.h"

// === ELF64 minimal definitions ===
//
// Darwin has no <elf.h>; declaring the bits we need keeps the project
// self-contained and identical-on-disk across hosts.

#define EI_NIDENT     16
#define EI_CLASS      4
#define EI_DATA       5
#define ELFMAG        "\x7f""ELF"
#define SELFMAG       4
#define ELFCLASS64    2
#define ELFDATA2LSB   1
#define ET_REL        1
#define EM_AARCH64    183
#define SHT_PROGBITS  1
#define SHT_SYMTAB    2
#define SHT_RELA      4
#define SHT_NOTE      7
#define SHT_NOBITS    8
#define SHT_DYNSYM    11
#define SHT_INIT_ARRAY    14
#define SHT_FINI_ARRAY    15
#define SHT_PREINIT_ARRAY 16
#define SHT_RELR      19
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4
#define SHN_UNDEF     0
#define PT_INTERP     3
#define NT_GNU_PROPERTY_TYPE_0 5
// The AArch64 GNU property word and its bits: BTI (every indirect
// branch target carries a landing pad, so the loader maps the code
// PROT_BTI), PAC (every function signs its return address) and GCS
// (the code runs under a guarded control stack).
#define GNU_PROPERTY_AARCH64_FEATURE_1_AND 0xc0000000u
#define GNU_PROPERTY_AARCH64_FEATURE_1_BTI 0x1u
#define GNU_PROPERTY_AARCH64_FEATURE_1_PAC 0x2u
#define GNU_PROPERTY_AARCH64_FEATURE_1_GCS 0x4u
#define R_AARCH64_ABS64     257
#define R_AARCH64_GLOB_DAT  1025
#define R_AARCH64_JUMP_SLOT 1026
#define R_AARCH64_RELATIVE  1027
#define R_AARCH64_IRELATIVE 1032
#define ELF64_R_SYM(i)  ((uint32_t)((i) >> 32))
#define ELF64_R_TYPE(i) ((uint32_t)((i) & 0xffffffffu))
#define STB_LOCAL     0
#define STT_NOTYPE    0
#define STT_FUNC      2
#define STT_GNU_IFUNC 10

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

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} Elf64_Rela;

typedef struct {
    uint32_t n_namesz;
    uint32_t n_descsz;
    uint32_t n_type;
} Elf64_Nhdr;

// === Mach-O minimal definitions ===
//
// Apple's <mach-o/*.h> would do, but they pull in <mach/machine.h> and
// host-only types. Reproducing the on-disk layout here keeps Linux
// builds buildable too.

#define MH_MAGIC_64        0xfeedfacfu       // little-endian Mach-O 64
#define FAT_MAGIC          0xcafebabeu       // fat header, stored big-endian
#define FAT_MAGIC_64       0xcafebabfu       // fat header with 64-bit offsets
#define CPU_TYPE_ARM64     0x0100000cu       // includes arm64 and arm64e
// The cpusubtype's low 24 bits name the variant; the high byte holds
// capability/feature bits (CPU_SUBTYPE_PTRAUTH_ABI etc.). arm64e is 2;
// arm64e.x1 (12) is the same pointer-authentication ABI for cores
// with FEAT_PAuth_LR, whose code signs and authenticates the return
// address with pacibsppc/autibsppc/retabsppc.
#define CPU_SUBTYPE_MASK      0x00ffffffu
#define CPU_SUBTYPE_ARM64_ALL 0x00000000u
#define CPU_SUBTYPE_ARM64_V8  0x00000001u
#define CPU_SUBTYPE_ARM64E    0x00000002u
#define CPU_SUBTYPE_ARM64E_X1 0x0000000cu
#define LC_SYMTAB          0x2u
#define LC_SEGMENT_64      0x19u
#define LC_FUNCTION_STARTS 0x26u
#define S_ATTR_PURE_INSTRUCTIONS 0x80000000u
// The low byte of section flags is the section *type* (the attribute
// bits live above it); S_SYMBOL_STUBS marks the linker's dyld import
// stubs (__stubs).
#define SECTION_TYPE   0x000000ffu
#define S_SYMBOL_STUBS 0x8u
// nlist_64.n_type decomposition: any stab bit marks a debug entry,
// N_SECT means defined in the section n_sect names (1-based ordinal
// across every segment's sections), N_EXT marks nm-visible externals.
#define N_STAB_MASK 0xe0u
#define N_TYPE_MASK 0x0eu
#define N_SECT      0x0eu
#define N_EXT       0x01u

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
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
} symtab_command;

// LC_FUNCTION_STARTS (among others) points at an opaque linkedit blob.
typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
} linkedit_data_command;

typedef struct {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
} nlist_64;

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

static bool read_at(FILE *f, long off, void *buf, size_t n)
{
    if (fseek(f, off, SEEK_SET) != 0) {
        return false;
    }
    return fread(buf, 1, n, f) == n;
}

// === BTI landing-pad verification, -b ===
//
// With FEAT_BTI enforced -- the loader maps the code PROT_BTI when the
// GNU property note carries the BTI bit -- an indirect BR or BLR must
// land on a BTI whose targets admit it, or the CPU raises a Branch
// Target exception. Which addresses an indirect branch can reach is
// not a property of the instruction stream: nothing in the bytes
// distinguishes a landing site from fall-through code. But the ELF
// metadata of a linked binary evidences a checkable subset, collected
// below exactly as x86lint's -e collects it for ENDBR64. The subset
// under-approximates (a function pointer materialized by ADRP+ADD
// leaves no relocation behind), so a target the metadata does
// evidence really is reachable indirectly and a missing pad there
// really faults; the converse -- flagging a superfluous BTI -- would
// be guessing, and is not attempted.
//
// Every evidenced target is entered by a call or through a PLT: the
// loader's BLR into the entry point, init/fini and resolvers, a GOT
// slot's BLR, and a PLT entry's BR x16/x17. BTI c admits all of
// those (BR is permitted when it comes through x16 or x17, which is
// why a PLT branches that way and why the compilers' indirect tail
// calls use those registers under -mbranch-protection), as do BTI jc
// and the PACIASP/PACIBSP a pac-ret prologue opens with. A BTI j is
// a pad of the wrong flavour -- it admits BR alone -- and is reported
// as such: a sharper verdict than x86 has, where there is one ENDBR64.

// Evidence sources, strongest first: when several name the same
// address (an exported function also referenced by a GOT relocation),
// dedup keeps the smallest kind. Every kind but the last proves the
// address is *branched* to. An address relocation proves only that
// the address is *taken*: glibc bakes pointers to bracket labels that
// are only compared against interrupted PCs, with no pad by design.
// The verify loop therefore counts BTI_ADDR evidence only when the
// target is a known function entry, and its last-place rank keeps it
// from shadowing a stronger claim to the same address.
enum bti_kind {
    BTI_ENTRY,    // e_entry: ld.so transfers to it indirectly
    BTI_INIT,     // .init/.fini: DT_INIT/DT_FINI, called through a pointer
    BTI_ARRAY,    // .preinit_array/.init_array/.fini_array slot
    BTI_PLT,      // R_AARCH64_JUMP_SLOT resolving to a local definition
    BTI_GOT,      // R_AARCH64_GLOB_DAT resolving to a local definition
    BTI_IFUNC,    // R_AARCH64_IRELATIVE: the loader calls the resolver
    BTI_EXPORT,   // defined dynsym function: reachable via any caller's PLT
    BTI_ADDR,     // absolute-address relocation into an executable section
};

static const char *const bti_kind_name[] = {
    "entry point",
    ".init/.fini entry",
    "init/fini array entry",
    "PLT relocation",
    "GOT relocation",
    "ifunc resolver",
    "exported function",
    "address relocation",
};

struct bti_target {
    uint64_t va;
    uint32_t sym;       // index into .dynsym, or 0 (STN_UNDEF) for none
    uint8_t kind;       // enum bti_kind
};

struct bti_targets {
    struct bti_target *v;
    size_t n;
    size_t cap;
};

static bool bti_push(struct bti_targets *t, uint64_t va, uint32_t sym,
                     uint8_t kind)
{
    if (t->n == t->cap) {
        size_t cap = t->cap == 0 ? 64 : t->cap * 2;
        struct bti_target *v = realloc(t->v, cap * sizeof(*v));
        if (v == NULL) {
            return false;
        }
        t->v = v;
        t->cap = cap;
    }
    t->v[t->n].va = va;
    t->v[t->n].sym = sym;
    t->v[t->n].kind = kind;
    ++t->n;
    return true;
}

static int bti_target_cmp(const void *a, const void *b)
{
    const struct bti_target *ta = a, *tb = b;
    if (ta->va != tb->va) {
        return ta->va < tb->va ? -1 : 1;
    }
    if (ta->kind != tb->kind) {
        return ta->kind < tb->kind ? -1 : 1;
    }
    return 0;
}

static bool u64_push(uint64_t **v, size_t *n, size_t *cap, uint64_t x)
{
    if (*n == *cap) {
        size_t ncap = *cap == 0 ? 64 : *cap * 2;
        uint64_t *nv = realloc(*v, ncap * sizeof(*nv));
        if (nv == NULL) {
            return false;
        }
        *v = nv;
        *cap = ncap;
    }
    (*v)[(*n)++] = x;
    return true;
}

static int u64_cmp(const void *a, const void *b)
{
    uint64_t ua = *(const uint64_t *)a, ub = *(const uint64_t *)b;
    return ua < ub ? -1 : ua > ub ? 1 : 0;
}

static bool u64_contains(const uint64_t *v, size_t n, uint64_t x)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v[mid] < x) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < n && v[lo] == x;
}

// Read a whole section's contents, bounds-checked against the file.
// NULL for a section with no bytes in the file or on I/O or
// allocation failure; the callers treat all of these as absent
// evidence and move on (the summary line still states how many
// targets were actually checked).
static uint8_t *load_section(FILE *f, const Elf64_Shdr *shdr,
                             uint64_t file_size)
{
    if (shdr->sh_type == SHT_NOBITS || shdr->sh_size == 0
            || shdr->sh_offset > file_size
            || shdr->sh_size > file_size - shdr->sh_offset) {
        return NULL;
    }
    uint8_t *buf = malloc(shdr->sh_size);
    if (buf != NULL && !read_at(f, (long)shdr->sh_offset, buf, shdr->sh_size)) {
        free(buf);
        buf = NULL;
    }
    return buf;
}

// The AArch64 feature word of the GNU property note (an
// NT_GNU_PROPERTY_TYPE_0 note named "GNU"), or 0 when no note carries
// one. Property notes are 8-aligned in ELF64; other note sections
// (build-id) use 4, hence the per-section alignment. Each property is
// {u32 pr_type, u32 pr_datasz, data padded to 8}.
static uint32_t elf_aarch64_feature_1_and(FILE *f, const Elf64_Shdr *sh,
                                          uint64_t shnum, uint64_t file_size)
{
    uint32_t feat = 0;
    bool found = false;
    for (uint64_t i = 0; i < shnum && !found; ++i) {
        if (sh[i].sh_type != SHT_NOTE) {
            continue;
        }
        uint8_t *buf = load_section(f, &sh[i], file_size);
        if (buf == NULL) {
            continue;
        }
        uint64_t size = sh[i].sh_size;
        uint64_t align = sh[i].sh_addralign == 8 ? 8 : 4;
        uint64_t off = 0;
        while (off + sizeof(Elf64_Nhdr) <= size) {
            Elf64_Nhdr nh;
            memcpy(&nh, buf + off, sizeof(nh));
            uint64_t name_off = off + sizeof(nh);
            uint64_t desc_off = (name_off + nh.n_namesz + align - 1)
                & ~(align - 1);
            if (desc_off > size || nh.n_descsz > size - desc_off
                    || nh.n_namesz > size - name_off) {
                break;      // malformed: stop parsing this section
            }
            if (nh.n_type == NT_GNU_PROPERTY_TYPE_0 && nh.n_namesz == 4
                    && memcmp(buf + name_off, "GNU", 4) == 0) {
                uint64_t p = desc_off;
                uint64_t dend = desc_off + nh.n_descsz;
                while (p + 8 <= dend) {
                    uint32_t pr_type, pr_datasz;
                    memcpy(&pr_type, buf + p, 4);
                    memcpy(&pr_datasz, buf + p + 4, 4);
                    if (pr_datasz > dend - (p + 8)) {
                        break;
                    }
                    if (!found
                            && pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND
                            && pr_datasz >= 4) {
                        memcpy(&feat, buf + p + 8, 4);
                        found = true;
                    }
                    p += 8 + (((uint64_t)pr_datasz + 7) & ~(uint64_t)7);
                }
            }
            off = (desc_off + nh.n_descsz + align - 1) & ~(align - 1);
        }
        free(buf);
    }
    return feat;
}

// Resolve one RELR-relocated slot: the packed format encodes only
// WHERE a relative relocation applies; its target is the slot's raw
// link-time value, read here from whichever section holds the slot.
// Slots arrive sorted, so the single-section cache almost always
// hits. Returns false only on allocation failure; a slot outside any
// loadable section, an unreadable section, and a 0/-1 sentinel value
// are skipped.
static bool bti_relr_slot(FILE *f, const Elf64_Shdr *sh, uint64_t shnum,
                          uint64_t file_size, uint64_t where,
                          uint64_t *cache_i, uint8_t **cache,
                          struct bti_targets *targets)
{
    if (*cache_i >= shnum || where < sh[*cache_i].sh_addr
            || where - sh[*cache_i].sh_addr > sh[*cache_i].sh_size - 8) {
        free(*cache);
        *cache = NULL;
        *cache_i = shnum;
        for (uint64_t i = 0; i < shnum; ++i) {
            if ((sh[i].sh_flags & SHF_ALLOC) && sh[i].sh_type != SHT_NOBITS
                    && sh[i].sh_size >= 8 && where >= sh[i].sh_addr
                    && where - sh[i].sh_addr <= sh[i].sh_size - 8) {
                *cache = load_section(f, &sh[i], file_size);
                if (*cache == NULL) {
                    return true;
                }
                *cache_i = i;
                break;
            }
        }
        if (*cache_i >= shnum) {
            return true;
        }
    }
    uint64_t value;
    memcpy(&value, *cache + (where - sh[*cache_i].sh_addr), 8);
    if (value == 0 || value == UINT64_MAX) {
        return true;
    }
    return bti_push(targets, value, 0, BTI_ADDR);
}

// Name a target: by its recorded dynsym index, or by reverse value
// lookup for targets evidenced without a symbol. NULL when nothing
// matches.
static const char *bti_sym_name(const Elf64_Sym *dynsym, size_t ndynsym,
                                const char *dynstr, uint64_t dynstr_size,
                                uint32_t symi, uint64_t va)
{
    if (dynstr == NULL) {
        return NULL;
    }
    if (symi == 0) {
        for (size_t s = 1; s < ndynsym; ++s) {
            unsigned st = dynsym[s].st_info & 0xfu;
            if ((st == STT_FUNC || st == STT_GNU_IFUNC)
                    && dynsym[s].st_shndx != SHN_UNDEF
                    && dynsym[s].st_value == va) {
                symi = (uint32_t)s;
                break;
            }
        }
        if (symi == 0) {
            return NULL;
        }
    }
    if (symi >= ndynsym || dynsym[symi].st_name == 0
            || dynsym[symi].st_name >= dynstr_size) {
        return NULL;
    }
    return dynstr + dynsym[symi].st_name;
}

// Verify that every indirect branch target the ELF metadata evidences
// begins with a landing pad that admits a call (armlint_bti_landing),
// and reconcile the result with the binary's property note. Four
// verdicts: BTI declared and every target padded -- clean; BTI
// declared with misses -- each is a Branch Target exception once the
// pages are mapped PROT_BTI, so every miss is printed regardless of
// verbosity; BTI not declared but pads present -- the compiler emitted
// them and the link lost the note (the property is ANDed across
// inputs, so one object built without -mbranch-protection silently
// disarms the whole binary), one finding, with the per-target detail
// behind -v; no declaration and no pads -- not a BTI binary, no
// findings. Returns the finding count, or -1 on tool failure.
static int check_elf_bti(FILE *f, const char *path, uint64_t file_size,
                         bool verbose)
{
    Elf64_Ehdr ehdr;
    if (!read_at(f, 0, &ehdr, sizeof(ehdr))) {
        fprintf(stderr, "%s: failed to read ELF header\n", path);
        return -1;
    }
    // A relocatable object's indirect targets are a compile-time
    // question (its address-taken evidence dissolves into the final
    // link), and half its metadata does not exist yet.
    if (ehdr.e_type == ET_REL) {
        fprintf(stderr,
            "%s: -b requires a linked executable or shared object\n", path);
        return -1;
    }
    uint64_t shnum = ehdr.e_shnum;
    if (shnum == 0) {
        printf("BTI: no section headers; nothing to check\n");
        return 0;
    }

    int rc = -1;
    struct bti_targets targets = {NULL, 0, 0};
    Elf64_Sym *dynsym = NULL;
    size_t ndynsym = 0;
    char *dynstr = NULL;
    uint64_t dynstr_size = 0;
    char *shstr = NULL;
    uint64_t shstrsize = 0;
    uint8_t **exec_bufs = NULL;
    uint64_t *fentry = NULL;
    size_t nfentry = 0;
    size_t fentry_cap = 0;

    Elf64_Shdr *sh = malloc(shnum * sizeof(*sh));
    if (sh == NULL
            || ehdr.e_shoff > file_size
            || shnum > (file_size - ehdr.e_shoff) / sizeof(*sh)
            || !read_at(f, (long)ehdr.e_shoff, sh, shnum * sizeof(*sh))) {
        fprintf(stderr, "%s: failed to read section headers\n", path);
        goto out;
    }
    if (ehdr.e_shstrndx != 0 && ehdr.e_shstrndx < shnum) {
        shstr = (char *)load_section(f, &sh[ehdr.e_shstrndx], file_size);
        if (shstr != NULL) {
            shstrsize = sh[ehdr.e_shstrndx].sh_size;
            shstr[shstrsize - 1] = '\0';
        }
    }

    uint32_t feat = elf_aarch64_feature_1_and(f, sh, shnum, file_size);
    bool bti = (feat & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) != 0;
    bool pac = (feat & GNU_PROPERTY_AARCH64_FEATURE_1_PAC) != 0;
    bool gcs = (feat & GNU_PROPERTY_AARCH64_FEATURE_1_GCS) != 0;

    // The dynamic symbol table names relocation targets and lists the
    // exported functions, each an indirect target in its own right.
    for (uint64_t i = 0; i < shnum; ++i) {
        if (sh[i].sh_type != SHT_DYNSYM
                || sh[i].sh_entsize != sizeof(Elf64_Sym)) {
            continue;
        }
        dynsym = (Elf64_Sym *)load_section(f, &sh[i], file_size);
        if (dynsym == NULL) {
            break;
        }
        ndynsym = sh[i].sh_size / sizeof(Elf64_Sym);
        if (sh[i].sh_link < shnum) {
            dynstr = (char *)load_section(f, &sh[sh[i].sh_link], file_size);
            if (dynstr != NULL) {
                dynstr_size = sh[sh[i].sh_link].sh_size;
                dynstr[dynstr_size - 1] = '\0';     // bound every lookup
            }
        }
        break;
    }

    // Function entries known to the symbol tables (.symtab when the
    // binary kept one, .dynsym always), for grading the
    // address-relocation evidence in the verify loop: a baked code
    // pointer is proven a branch target only when it addresses a
    // function entry. A compare-only label is NOTYPE and drops out
    // here; a stripped binary loses this evidence class and nothing
    // else -- erring, as everywhere, toward the false negative.
    bool oom = false;
    for (uint64_t i = 0; i < shnum && !oom; ++i) {
        if (sh[i].sh_type != SHT_SYMTAB
                || sh[i].sh_entsize != sizeof(Elf64_Sym)) {
            continue;
        }
        Elf64_Sym *syms = (Elf64_Sym *)load_section(f, &sh[i], file_size);
        if (syms == NULL) {
            continue;
        }
        size_t nsyms = sh[i].sh_size / sizeof(Elf64_Sym);
        for (size_t s = 1; s < nsyms && !oom; ++s) {
            unsigned st = syms[s].st_info & 0xfu;
            if ((st == STT_FUNC || st == STT_GNU_IFUNC)
                    && syms[s].st_shndx != SHN_UNDEF
                    && syms[s].st_value != 0) {
                oom |= !u64_push(&fentry, &nfentry, &fentry_cap,
                    syms[s].st_value);
            }
        }
        free(syms);
    }
    for (size_t s = 1; s < ndynsym && !oom; ++s) {
        unsigned st = dynsym[s].st_info & 0xfu;
        if ((st == STT_FUNC || st == STT_GNU_IFUNC)
                && dynsym[s].st_shndx != SHN_UNDEF && dynsym[s].st_value != 0) {
            oom |= !u64_push(&fentry, &nfentry, &fentry_cap,
                dynsym[s].st_value);
        }
    }
    if (nfentry != 0) {
        qsort(fentry, nfentry, sizeof(*fentry), u64_cmp);
    }

    // The entry point is an indirect branch target only for a program
    // with an interpreter: ld.so's _dl_start_user transfers to e_entry
    // with a BR through x16, which a BTI c admits. A kernel-entered
    // binary -- static, static-PIE, ld.so itself -- starts with no
    // guarded page to land on and owes no pad there.
    bool has_interp = false;
    if (ehdr.e_phoff != 0 && ehdr.e_phentsize == sizeof(Elf64_Phdr)
            && ehdr.e_phoff <= file_size
            && ehdr.e_phnum <= (file_size - ehdr.e_phoff) / sizeof(Elf64_Phdr)) {
        for (uint16_t i = 0; i < ehdr.e_phnum; ++i) {
            Elf64_Phdr ph;
            if (!read_at(f, (long)(ehdr.e_phoff + i * sizeof(ph)), &ph,
                         sizeof(ph))) {
                break;
            }
            if (ph.p_type == PT_INTERP) {
                has_interp = true;
                break;
            }
        }
    }
    if (has_interp && ehdr.e_entry != 0) {
        oom |= !bti_push(&targets, ehdr.e_entry, 0, BTI_ENTRY);
    }

    for (uint64_t i = 0; i < shnum && !oom; ++i) {
        const Elf64_Shdr *s = &sh[i];
        switch (s->sh_type) {
        case SHT_PROGBITS:
            // .init and .fini hold DT_INIT/DT_FINI, which the loader
            // calls through a function pointer. Identified by name;
            // without a section string table they are simply not
            // evidenced.
            if (shstr != NULL && s->sh_name < shstrsize
                    && (s->sh_flags & SHF_EXECINSTR) && s->sh_addr != 0) {
                const char *name = shstr + s->sh_name;
                if (strcmp(name, ".init") == 0 || strcmp(name, ".fini") == 0) {
                    oom |= !bti_push(&targets, s->sh_addr, 0, BTI_INIT);
                }
            }
            break;
        case SHT_PREINIT_ARRAY:
        case SHT_INIT_ARRAY:
        case SHT_FINI_ARRAY: {
            // Each slot is a function pointer the startup code calls
            // indirectly. The linker stores the link-time address in
            // the slot even when a RELATIVE (or packed RELR)
            // relocation also covers it, so the raw values serve PIE
            // and non-PIE alike.
            uint8_t *buf = load_section(f, s, file_size);
            if (buf == NULL) {
                break;
            }
            for (uint64_t off = 0; off + 8 <= s->sh_size && !oom; off += 8) {
                uint64_t va;
                memcpy(&va, buf + off, 8);
                if (va != 0 && va != UINT64_MAX) {
                    oom |= !bti_push(&targets, va, 0, BTI_ARRAY);
                }
            }
            free(buf);
            break;
        }
        case SHT_RELA: {
            if (s->sh_entsize != sizeof(Elf64_Rela)) {
                break;
            }
            uint8_t *buf = load_section(f, s, file_size);
            if (buf == NULL) {
                break;
            }
            size_t n = s->sh_size / sizeof(Elf64_Rela);
            for (size_t r = 0; r < n && !oom; ++r) {
                Elf64_Rela rela;
                memcpy(&rela, buf + r * sizeof(rela), sizeof(rela));
                uint32_t type = ELF64_R_TYPE(rela.r_info);
                uint32_t symi = ELF64_R_SYM(rela.r_info);
                switch (type) {
                case R_AARCH64_JUMP_SLOT:
                case R_AARCH64_GLOB_DAT:
                case R_AARCH64_ABS64:
                    // Meaningful when the symbol is defined here: the
                    // runtime slot value is then this object's own
                    // function entry. Imports resolve elsewhere. A
                    // symbolless absolute relocation is a baked
                    // address, handled like RELATIVE.
                    if (symi != 0 && symi < ndynsym) {
                        const Elf64_Sym *y = &dynsym[symi];
                        unsigned st = y->st_info & 0xfu;
                        if ((st != STT_FUNC && st != STT_GNU_IFUNC)
                                || y->st_shndx == SHN_UNDEF || y->st_value == 0) {
                            break;
                        }
                        uint64_t va = y->st_value;
                        uint8_t kind = type == R_AARCH64_JUMP_SLOT ? BTI_PLT
                            : type == R_AARCH64_GLOB_DAT ? BTI_GOT : BTI_ADDR;
                        if (type == R_AARCH64_ABS64) {
                            va += (uint64_t)rela.r_addend;
                        }
                        oom |= !bti_push(&targets, va, symi, kind);
                    } else if (type == R_AARCH64_ABS64 && rela.r_addend != 0) {
                        oom |= !bti_push(&targets, (uint64_t)rela.r_addend, 0,
                            BTI_ADDR);
                    }
                    break;
                case R_AARCH64_IRELATIVE:
                    // The addend is the ifunc resolver, which the
                    // loader calls indirectly at startup.
                    if (rela.r_addend != 0) {
                        oom |= !bti_push(&targets, (uint64_t)rela.r_addend, 0,
                            BTI_IFUNC);
                    }
                    break;
                case R_AARCH64_RELATIVE:
                    // A baked pointer; one landing in an executable
                    // section is an address-taken function or label.
                    if (rela.r_addend != 0) {
                        oom |= !bti_push(&targets, (uint64_t)rela.r_addend, 0,
                            BTI_ADDR);
                    }
                    break;
                }
            }
            free(buf);
            break;
        }
        case SHT_RELR: {
            if (s->sh_entsize != 8) {
                break;
            }
            uint8_t *buf = load_section(f, s, file_size);
            if (buf == NULL) {
                break;
            }
            uint64_t cache_i = shnum;
            uint8_t *cache = NULL;
            uint64_t where = 0;
            size_t n = s->sh_size / 8;
            for (size_t r = 0; r < n && !oom; ++r) {
                uint64_t e;
                memcpy(&e, buf + r * 8, 8);
                if ((e & 1) == 0) {
                    oom |= !bti_relr_slot(f, sh, shnum, file_size, e,
                        &cache_i, &cache, &targets);
                    where = e + 8;
                } else {
                    for (unsigned b = 1; b < 64 && !oom; ++b) {
                        if (e & (1ULL << b)) {
                            oom |= !bti_relr_slot(f, sh, shnum, file_size,
                                where + (b - 1) * 8, &cache_i, &cache,
                                &targets);
                        }
                    }
                    where += 63 * 8;
                }
            }
            free(cache);
            free(buf);
            break;
        }
        }
    }

    // Every defined dynamic function symbol is indirectly reachable:
    // a cross-object call always arrives through the caller's PLT or
    // GOT, an indirect branch landing here.
    for (size_t s = 1; s < ndynsym && !oom; ++s) {
        unsigned st = dynsym[s].st_info & 0xfu;
        if ((st == STT_FUNC || st == STT_GNU_IFUNC)
                && dynsym[s].st_shndx != SHN_UNDEF && dynsym[s].st_value != 0) {
            oom |= !bti_push(&targets, dynsym[s].st_value, (uint32_t)s,
                BTI_EXPORT);
        }
    }

    if (oom) {
        fprintf(stderr, "%s: failed to allocate target list\n", path);
        goto out;
    }
    if (targets.n != 0) {
        qsort(targets.v, targets.n, sizeof(*targets.v), bti_target_cmp);
    }

    // The landing pads are read raw, never through the symbol-table
    // mask. Only targets inside an executable section are checked:
    // the address-relocation sweep pushes every baked pointer it
    // sees, and the ones aimed at data drop out here.
    exec_bufs = calloc(shnum, sizeof(*exec_bufs));
    if (exec_bufs == NULL) {
        fprintf(stderr, "%s: failed to allocate section list\n", path);
        goto out;
    }
    for (uint64_t i = 0; i < shnum; ++i) {
        if (sh[i].sh_type == SHT_PROGBITS && (sh[i].sh_flags & SHF_EXECINSTR)
                && (sh[i].sh_flags & SHF_ALLOC) && sh[i].sh_addr != 0) {
            exec_bufs[i] = load_section(f, &sh[i], file_size);
        }
    }

    size_t checked = 0;
    size_t misses = 0;
    size_t wrong = 0;
    uint64_t prev_va = 0;
    bool have_prev = false;
    for (size_t t = 0; t < targets.n; ++t) {
        uint64_t va = targets.v[t].va;
        if (have_prev && va == prev_va) {
            continue;       // sorted dedup; the most specific kind is first
        }
        prev_va = va;
        have_prev = true;
        if (targets.v[t].kind == BTI_ADDR && !u64_contains(fentry, nfentry, va)) {
            continue;       // address-taken only: see enum bti_kind
        }
        uint64_t sec = shnum;
        for (uint64_t i = 0; i < shnum; ++i) {
            if (exec_bufs[i] != NULL && va >= sh[i].sh_addr
                    && va - sh[i].sh_addr < sh[i].sh_size) {
                sec = i;
                break;
            }
        }
        if (sec == shnum) {
            continue;
        }
        ++checked;
        unsigned pad = armlint_bti_landing(exec_bufs[sec], sh[sec].sh_size,
                                           va - sh[sec].sh_addr);
        if (pad & ARMLINT_BTI_CALL) {
            continue;
        }
        ++misses;
        wrong += pad != 0;
        if (bti || verbose) {
            const char *nm = bti_sym_name(dynsym, ndynsym, dynstr,
                dynstr_size, targets.v[t].sym, va);
            printf("indirect branch target %s: 0x%" PRIx64 "%s%s%s (%s)\n",
                pad != 0 ? "has BTI j, which admits no call"
                         : "missing BTI c",
                va, nm != NULL ? " <" : "", nm != NULL ? nm : "",
                nm != NULL ? ">" : "", bti_kind_name[targets.v[t].kind]);
        }
    }

    if (checked == 0) {
        printf("BTI: no indirect branch targets evidenced; nothing to check\n");
        rc = 0;
    } else if (bti) {
        if (misses == 0) {
            printf("BTI: BTI property note present; all %zu indirect branch "
                "targets land on a BTI c\n", checked);
        } else {
            printf("BTI: BTI property note present; %zu of %zu indirect "
                "branch targets lack a BTI c%s (Branch Target exception "
                "when BTI is enforced)\n", misses, checked,
                wrong != 0 ? ", some carrying a BTI j" : "");
        }
        rc = (int)misses;
    } else if (misses < checked) {
        printf("BTI: no BTI in the property note, but %zu of %zu indirect "
            "branch targets begin with a BTI c (BTI annotation lost at "
            "link?)\n", checked - misses, checked);
        if (misses > 0 && !verbose) {
            printf("  (pass -v to list the %zu targets without one)\n",
                misses);
        }
        rc = (int)misses + 1;
    } else {
        printf("BTI: no BTI in the property note and no BTI landing pads; "
            "not a BTI binary\n");
        rc = 0;
    }

    // The same word carries the pac-ret bit, and
    // -mbranch-protection=standard emits both, so an asymmetric
    // declaration earns a line. Informational only, never the exit
    // status: pac-ret leaves a prologue in the instruction stream
    // (which the -a pac audit judges, function by function), but the
    // note's claim is about every input object having signed, which a
    // linked binary's instruction stream cannot be held to -- a leaf
    // function legitimately never signs. In the annotation-lost
    // verdict the pads evidence branch protection only -- a lost note
    // takes BTI and PAC down together -- so the line states the bit's
    // absence without claiming a loss. GCS has no instruction-stream
    // signature at all and is reported as declared.
    if (bti && pac) {
        printf("PAC: pac-ret declared alongside BTI\n");
    } else if (bti) {
        printf("PAC: no pac-ret in the property note despite BTI "
            "(-mbranch-protection=bti?)\n");
    } else if (pac) {
        printf("PAC: pac-ret declared without BTI (pac-ret-only asm in the "
            "link, or -mbranch-protection=pac-ret?)\n");
    } else if (checked != 0 && misses < checked) {
        printf("PAC: no pac-ret in the property note\n");
    }
    if (gcs) {
        printf("GCS: guarded control stack declared\n");
    }

out:
    if (exec_bufs != NULL) {
        for (uint64_t i = 0; i < shnum; ++i) {
            free(exec_bufs[i]);
        }
    }
    free(exec_bufs);
    free(fentry);
    free(dynstr);
    free(dynsym);
    free(shstr);
    free(targets.v);
    free(sh);
    return rc;
}

// === Symbolization ===
//
// Findings are annotated with the containing function
// ("<_foo+0x18>"), resolved from whatever the container carries:
// Mach-O nlist plus LC_FUNCTION_STARTS, or the ELF .symtab (falling
// back to .dynsym). The parsing lives here because it is
// container-format work; the library only consumes a finished, sorted
// armlint_symbol table. Everything below is best-effort -- a stripped
// binary or malformed symbol metadata degrades to unannotated
// findings, never to a failed lint.

// Working entry while assembling one code section's anchor table.
typedef struct {
    uint64_t vaddr;
    const char *name;   // NULL for a bare function start
    bool external;
    uint64_t size;      // ELF st_size; 0 when the format records none
} anchor;

static int anchor_cmp(const void *a, const void *b)
{
    const anchor *x = (const anchor *)a;
    const anchor *y = (const anchor *)b;
    if (x->vaddr != y->vaddr) {
        return x->vaddr < y->vaddr ? -1 : 1;
    }
    // Same address: the preferred anchor sorts first and survives the
    // dedupe. Named beats nameless (a function start usually
    // duplicates some symbol's address), external beats local (_main
    // beats the assembler's ltmp0), and the name itself breaks any
    // remaining tie so the ordering is deterministic.
    if ((x->name != NULL) != (y->name != NULL)) {
        return x->name != NULL ? -1 : 1;
    }
    if (x->external != y->external) {
        return x->external ? -1 : 1;
    }
    return x->name != NULL ? strcmp(x->name, y->name) : 0;
}

// Sort n working anchors, keep the preferred one per address, and lay
// the survivors out in the armlint_symbol shape the library consumes.
// out must have room for n entries; returns how many were written.
static size_t anchors_finish(anchor *tmp, size_t n, armlint_symbol *out)
{
    qsort(tmp, n, sizeof(*tmp), anchor_cmp);
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        if (m > 0 && out[m - 1].vaddr == tmp[i].vaddr) {
            // A duplicate that knows the extent lends it to the
            // survivor (an unsized alias of a sized function).
            if (tmp[i].size > out[m - 1].size) {
                out[m - 1].size = tmp[i].size;
            }
            continue;
        }
        out[m].vaddr = tmp[i].vaddr;
        out[m].name = tmp[i].name;
        out[m].size = tmp[i].size;
        m++;
    }
    return m;
}

// CLI-level reporting state, set once in main() and read by scan_code
// (the only caller of check_instructions). g_features is the baseline
// feature/audit set from the command line; scan_macho augments it
// per-slice (arm64e implies the PAC audit) and passes the result to
// scan_code explicitly, so features -- unlike g_verbose/g_summary --
// is threaded rather than read from the global.
static bool g_verbose = false;
static unsigned g_features = 0;
static armlint_summary *g_summary = NULL;
// -s: which ARM64-family slice of a fat binary to scan. NULL keeps
// the default (the lowest variant; see scan_fat), "all" scans every
// one, and anything else names one slice by its fat_arch index or its
// variant name.
static const char *g_slice = NULL;
// -A: scan every byte of each code section. By default an ELF binary
// that kept its .symtab is scanned only inside the ranges of its
// function symbols (see scan_elf); -A is the override, x86lint's -a.
// g_restrict_symbols counts the function symbols that restricted the
// scan, for the summary line and the --json document.
static bool g_scan_all = false;
static size_t g_restrict_symbols = 0;
// -f NAME: lint just the one function, every site that spells its
// name (a versioned export has several). g_func_sites and
// g_func_bytes report what was scanned; no site at all is a tool
// failure.
static const char *g_func = NULL;
static size_t g_func_sites = 0;
static uint64_t g_func_bytes = 0;
// -b: verify the ELF binary's BTI landing pads against the targets
// its own metadata evidences (see check_elf_bti).
static bool g_bti = false;
// Non-NULL in -i census mode: scan_code then tallies instead of
// linting, and main prints the census in place of the findings report.
static armlint_census *g_census = NULL;
// Non-NULL under -d: scan_code keys every range's functions before
// scanning it, and main prints the duplicate-code report after the
// findings report (or the census).
static armlint_dedup *g_dedup = NULL;
// Non-NULL under -c: scan_code tallies every range's constant chains,
// and main prints the constant report last.
static armlint_constants *g_constants = NULL;

// --json: the findings as a machine-readable stream, for a consumer
// that joins them against something else keyed by address -- most
// usefully an execution profile, so each opportunity can be weighted
// by how often the instruction it names actually runs. Findings print
// as they are found rather than accumulating in an array: a large
// binary yields tens of thousands of them, and the per-finding
// callback exists precisely so that nothing has to be buffered to
// report them. The totals therefore land after the findings, being
// unknown until the scan ends.
//
// The document covers the lint scan only. -v, -i, -d and -c are
// reports with their own shapes, and interleaving any of them with
// this one would produce neither valid JSON nor a coherent schema, so
// the driver rejects the combination rather than choosing for the
// caller. The same shape as x86lint's, with two AArch64 differences:
// a finding spans a window of whole instructions, so `text` is an
// array of its lines and `length` a multiple of four, and a finding
// carries the check's `detail` (the rewrite) besides its name.
static bool g_json = false;
static bool g_json_begun = false;       // the opening line is out
static bool g_json_any = false;         // a finding has been written
static const char *g_json_path = NULL;
static const char *g_json_section = ""; // the section being scanned
static const char *g_json_slice = NULL; // the fat slice, when there is one

// Write s as a JSON string. Escapes what the grammar requires -- the
// quote, the backslash, and every control character -- and passes
// bytes >= 0x80 through unchanged: section and symbol names are copied
// out of the file verbatim, so a binary whose string tables are not
// UTF-8 yields strings that are not either, the same bytes nm and
// objdump reproduce.
static void json_string(const char *s)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; ++p) {
        switch (*p) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\b': fputs("\\b", stdout);  break;
        case '\f': fputs("\\f", stdout);  break;
        case '\n': fputs("\\n", stdout);  break;
        case '\r': fputs("\\r", stdout);  break;
        case '\t': fputs("\\t", stdout);  break;
        default:
            if (*p < 0x20) {
                printf("\\u%04x", (unsigned)*p);
            } else {
                putchar((char)*p);
            }
        }
    }
    putchar('"');
}

// Open the document. Deferred to the first range scanned (or to the
// close, for a file with no code), so that every way the file itself
// can be rejected -- an unknown format, a malformed header -- leaves
// stdout empty rather than holding half a document. A failure inside
// the scan can still truncate it, which the exit status reports and
// the diagnostic on stderr explains.
static void json_begin(void)
{
    if (g_json_begun) {
        return;
    }
    g_json_begun = true;
    printf("{\"file\": ");
    json_string(g_json_path);
    printf(",\n  \"findings\": [");
}

// What scan_code hands the callback: the range's symbol table, for
// the function attribution the verbose report prints as "<f+0x18>".
struct json_ctx {
    const armlint_symbol *symbols;
    size_t nsymbols;
};

// One finding, one line: compact enough to grep and to stream through
// jq, and small enough that a scan yielding tens of thousands of them
// stays readable. vaddr is a number rather than a hex string so that
// it composes with arithmetic -- range tests against a code object,
// sums of profile weights -- which is the whole point of reporting
// the absolute address. A function start that LC_FUNCTION_STARTS
// records without a name is reported by its address.
static void json_finding(void *ctx, const armlint_finding *f,
                         uint64_t vaddr, const uint8_t *bytes)
{
    const struct json_ctx *j = ctx;

    printf("%s\n    {\"vaddr\": %" PRIu64 ", \"check\": ",
        g_json_any ? "," : "", vaddr);
    json_string(f->name);
    g_json_any = true;
    printf(", \"detail\": ");
    json_string(f->detail);
    printf(", \"section\": ");
    json_string(g_json_section);
    if (g_json_slice != NULL) {
        printf(", \"slice\": ");
        json_string(g_json_slice);
    }

    const armlint_symbol *sym =
        armlint_symbol_lookup(j->symbols, j->nsymbols, vaddr);
    if (sym != NULL) {
        if (sym->name != NULL) {
            printf(", \"function\": ");
            json_string(sym->name);
        } else {
            printf(", \"function_start\": %" PRIu64, sym->vaddr);
        }
        printf(", \"function_offset\": %" PRIu64, vaddr - sym->vaddr);
    }

    unsigned length = f->insn_count * 4u;
    printf(", \"length\": %u, \"bytes\": \"", length);
    for (unsigned i = 0; i < length; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\", \"text\": [");
    bool first = true;
    for (unsigned i = 0; i < ARMLINT_FINDING_LINES; ++i) {
        if (f->lines[i][0] != '\0') {
            fputs(first ? "" : ", ", stdout);
            json_string(f->lines[i]);
            first = false;
        }
    }
    printf("]}");
}

// A byte range of a code section the scan keeps: section-relative,
// end-exclusive.
typedef struct {
    uint64_t start;
    uint64_t end;
} code_range;

static int code_range_cmp(const void *a, const void *b)
{
    const code_range *x = a, *y = b;
    return x->start < y->start ? -1 : x->start > y->start ? 1 : 0;
}

// Overwrite every word of buf outside the kept ranges with 0xffffffff,
// an unallocated encoding Capstone refuses to decode (0 would not do:
// it decodes as UDF #0). The scan's resync loop then steps over those
// words one at a time and tallies them as skipped, so the excluded
// volume surfaces in the summary's skipped count instead of being
// linted as code. Ranges are rounded outward to whole words -- a
// symbol's size need not be a multiple of four -- so coverage errs
// toward keeping bytes. keep must be sorted by start.
static void mask_outside_ranges(uint8_t *buf, uint64_t size,
                                const code_range *keep, size_t nkeep)
{
    uint64_t pos = 0;
    for (size_t i = 0; i <= nkeep; i++) {
        uint64_t start = i < nkeep ? keep[i].start & ~(uint64_t)3 : size;
        uint64_t end = i < nkeep ? (keep[i].end + 3) & ~(uint64_t)3 : size;
        if (start > size) {
            start = size;
        }
        if (end > size) {
            end = size;
        }
        if (start > pos) {
            memset(buf + pos, 0xff, (size_t)(start - pos));
        }
        if (end > pos) {
            pos = end;
        }
    }
}

// -f: the kept ranges of one section, from its anchor table -- every
// anchor named g_func, reaching to its recorded size or, unsized, to
// the next anchor or the section end (the rule the annotation, the
// census and -d already define a function by, and the only one
// Mach-O's sizeless nlist admits). The table is sorted and deduped,
// so one address yields one site. Returns the count, with *keep
// allocated for it (NULL when there is none); -1 on allocation
// failure.
static int keep_named_function(const armlint_symbol *table, size_t ntable,
                               uint64_t base, uint64_t size,
                               code_range **keep)
{
    *keep = NULL;
    size_t n = 0;
    for (size_t k = 0; k < ntable; k++) {
        if (table[k].name != NULL && strcmp(table[k].name, g_func) == 0) {
            n++;
        }
    }
    if (n == 0) {
        return 0;
    }
    *keep = malloc(n * sizeof(**keep));
    if (*keep == NULL) {
        return -1;
    }
    size_t m = 0;
    for (size_t k = 0; k < ntable; k++) {
        if (table[k].name == NULL || strcmp(table[k].name, g_func) != 0
                || table[k].vaddr < base || table[k].vaddr - base >= size) {
            continue;
        }
        uint64_t start = table[k].vaddr - base;
        uint64_t end;
        if (table[k].size != 0) {
            end = table[k].size > size - start ? size : start + table[k].size;
        } else if (k + 1 < ntable && table[k + 1].vaddr - base < size) {
            end = table[k + 1].vaddr - base;
        } else {
            end = size;
        }
        (*keep)[m].start = start;
        (*keep)[m].end = end;
        m++;
        g_func_sites++;
        g_func_bytes += end - start;
    }
    return (int)m;
}

// Read `size` bytes at `base_offset` and run all checks with the
// given feature/audit set. vmaddr is the section's runtime base,
// reported back to the user in findings; symbols/nsymbols (possibly
// NULL/0) annotate verbose findings with the containing function.
// When restricted is set, only the nkeep ranges in keep are linted
// (see mask_outside_ranges). The census is restricted only under -f
// -- it is a description of the file, not a per-function report,
// unless one function is exactly what was asked for -- and then it
// scans each kept range as its own slice rather than through the
// mask, so the masked words do not count as undecodable.
static int scan_code(FILE *f, const char *path, long base_offset,
                     uint64_t size, uint64_t vmaddr, csh handle,
                     unsigned features,
                     const armlint_symbol *symbols, size_t nsymbols,
                     bool restricted, const code_range *keep, size_t nkeep)
{
    // A64 instructions are 4 bytes. Truncate trailing slop (e.g.
    // section padding) rather than fail the whole binary.
    uint64_t aligned = size & ~(uint64_t)3;
    if (aligned == 0) {
        return 0;
    }
    uint8_t *buf = malloc(aligned);
    if (buf == NULL) {
        fprintf(stderr, "%s: failed to allocate %" PRIu64 " bytes\n",
            path, aligned);
        return -1;
    }
    if (!read_at(f, base_offset, buf, aligned)) {
        fprintf(stderr, "%s: failed to read code at offset %ld\n",
            path, base_offset);
        free(buf);
        return -1;
    }
    if (restricted && g_census == NULL) {
        mask_outside_ranges(buf, aligned, keep, nkeep);
    }
    // -d keys the range's functions first, so that the lint run's
    // findings resolve against them.
    if (g_dedup != NULL
            && !armlint_dedup_scan(g_dedup, buf, aligned, vmaddr, features,
                                   symbols, nsymbols)) {
        fprintf(stderr, "%s: failed to allocate the duplicate-code tables\n",
            path);
        free(buf);
        return -1;
    }
    if (g_constants != NULL
            && !armlint_constants_scan(g_constants, buf, aligned, vmaddr,
                                       features, symbols, nsymbols)) {
        fprintf(stderr, "%s: failed to allocate the constant tables\n",
            path);
        free(buf);
        return -1;
    }
    int n;
    if (g_census != NULL) {
        // Census mode: tally only. The report prints once, after every
        // section of every slice has been scanned. Boundaries feed the
        // per-function pac-ret coverage.
        if (restricted) {
            for (size_t k = 0; k < nkeep; k++) {
                uint64_t start = keep[k].start & ~(uint64_t)3;
                uint64_t end = (keep[k].end + 3) & ~(uint64_t)3;
                if (end > aligned) {
                    end = aligned;
                }
                if (start < end) {
                    armlint_census_scan(g_census, handle, buf + start,
                                        end - start, vmaddr + start,
                                        g_features, symbols, nsymbols);
                }
            }
        } else {
            armlint_census_scan(g_census, handle, buf, aligned, vmaddr,
                                g_features, symbols, nsymbols);
        }
        n = 0;
    } else {
        struct json_ctx jctx = { symbols, nsymbols };
        if (g_json) {
            json_begin();
        }
        n = check_instructions(handle, buf, aligned, vmaddr,
                               g_verbose, g_summary, features,
                               symbols, nsymbols,
                               g_json ? json_finding : NULL,
                               g_json ? &jctx : NULL);
    }
    free(buf);
    return n;
}

static int scan_elf(FILE *f, const char *path, uint64_t file_size, csh handle)
{
    Elf64_Ehdr ehdr;
    if (!read_at(f, 0, &ehdr, sizeof(ehdr))) {
        fprintf(stderr, "%s: failed to read ELF header\n", path);
        return -1;
    }

    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "%s: only 64-bit ELF files are supported\n", path);
        return -1;
    }
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "%s: only little-endian ELF files are supported\n", path);
        return -1;
    }
    if (ehdr.e_machine != EM_AARCH64) {
        fprintf(stderr, "%s: not an AArch64 ELF (e_machine=%u)\n",
            path, ehdr.e_machine);
        return -1;
    }

    // Read the section header table whole: the scan wants the
    // executable sections; symbolization wants .symtab (or .dynsym)
    // and the string table it links to.
    if (ehdr.e_shnum == 0) {
        return 0;
    }
    Elf64_Shdr *shdrs = malloc((size_t)ehdr.e_shnum * sizeof(*shdrs));
    if (shdrs == NULL) {
        fprintf(stderr, "%s: failed to allocate section headers\n", path);
        return -1;
    }
    for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
        if (!read_at(f, ehdr.e_shoff + (long)i * (long)sizeof(Elf64_Shdr),
                     &shdrs[i], sizeof(Elf64_Shdr))) {
            fprintf(stderr, "%s: failed to read section header %u\n", path, i);
            free(shdrs);
            return -1;
        }
    }

    // Load the symbol table whole, preferring the full .symtab over
    // .dynsym (a stripped binary's exports still name the functions
    // that matter most). Five consumers want the boundaries: the
    // default scan restriction below, -v finding annotations, the
    // census's per-function pac-ret coverage, -d's functions and -c's.
    Elf64_Sym *syms = NULL;
    size_t nsyms = 0;
    char *strtab = NULL;
    uint64_t strsize = 0;
    bool have_symtab = false;   // the table is .symtab, not .dynsym
    {
        uint16_t symidx = 0;    // section 0 is the null section: "none"
        for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
            if (shdrs[i].sh_type == SHT_SYMTAB) {
                symidx = i;
                break;
            }
            if (shdrs[i].sh_type == SHT_DYNSYM && symidx == 0) {
                symidx = i;
            }
        }
        if (symidx != 0
                && shdrs[symidx].sh_link < ehdr.e_shnum
                && shdrs[symidx].sh_offset <= file_size
                && shdrs[symidx].sh_size <= file_size - shdrs[symidx].sh_offset) {
            const Elf64_Shdr *str = &shdrs[shdrs[symidx].sh_link];
            if (str->sh_size > 0
                    && str->sh_offset <= file_size
                    && str->sh_size <= file_size - str->sh_offset) {
                nsyms = shdrs[symidx].sh_size / sizeof(Elf64_Sym);
                syms = malloc(nsyms * sizeof(Elf64_Sym));
                strtab = malloc(str->sh_size + 1);
                if (syms != NULL && strtab != NULL
                        && read_at(f, (long)shdrs[symidx].sh_offset, syms,
                                   nsyms * sizeof(Elf64_Sym))
                        && read_at(f, (long)str->sh_offset, strtab,
                                   str->sh_size)) {
                    strsize = str->sh_size;
                    strtab[strsize] = '\0';
                    have_symtab = shdrs[symidx].sh_type == SHT_SYMTAB;
                } else {
                    free(syms);
                    free(strtab);
                    syms = NULL;
                    strtab = NULL;
                    nsyms = 0;
                }
            }
        }
    }

    // The default restriction: lint only inside the function symbols'
    // ranges. Executable sections routinely interleave non-code that
    // decodes cleanly -- literal pools, jump tables, alignment
    // islands -- which a linear sweep lints as code (four copies of
    // SHA-1's round constant in libcrypto's literal pools once made
    // six of ten "dead write" findings). When the binary says where
    // its functions are, scanning only there removes those findings
    // at the source. Only .symtab qualifies: .dynsym survives
    // stripping but lists exports alone, and restricting to those
    // would silently skip almost every internal function -- a clean
    // report that scanned nothing -- so a stripped binary scans whole
    // sections exactly as before. STT_FUNC and STT_GNU_IFUNC symbols
    // place the functions; a table that kept its symbols but dropped
    // their types (some strippers do) must not exclude every byte, so
    // the restriction needs at least one. -A forces the full sweep,
    // and the census never restricts. Mach-O records no symbol sizes,
    // so this is an ELF-only gate.
    size_t nfunc_syms = 0;
    if (have_symtab && !g_scan_all && g_census == NULL && g_func == NULL) {
        for (size_t s = 0; s < nsyms; ++s) {
            unsigned type = syms[s].st_info & 0xfu;
            if ((type == STT_FUNC || type == STT_GNU_IFUNC)
                    && syms[s].st_shndx != 0
                    && syms[s].st_shndx < ehdr.e_shnum) {
                nfunc_syms++;
            }
        }
    }

    // Section names live in the e_shstrndx string table; the scan
    // needs them to recognize linker-synthesized PLT glue below.
    // Best-effort: index 0 is SHN_UNDEF ("no table"), and a missing
    // or malformed table just means no names to match, so every
    // executable section is scanned as before.
    char *shstr = NULL;
    uint64_t shstrsize = 0;
    if (ehdr.e_shstrndx != 0 && ehdr.e_shstrndx < ehdr.e_shnum) {
        const Elf64_Shdr *str = &shdrs[ehdr.e_shstrndx];
        if (str->sh_size > 0
                && str->sh_offset <= file_size
                && str->sh_size <= file_size - str->sh_offset) {
            shstr = malloc(str->sh_size + 1);
            if (shstr != NULL
                    && read_at(f, (long)str->sh_offset, shstr,
                               str->sh_size)) {
                shstrsize = str->sh_size;
                shstr[shstrsize] = '\0';
            } else {
                free(shstr);
                shstr = NULL;
            }
        }
    }

    int errors = 0;
    for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
        const Elf64_Shdr *shdr = &shdrs[i];
        if (shdr->sh_type != SHT_PROGBITS
            || !(shdr->sh_flags & SHF_EXECINSTR)
            || shdr->sh_size == 0) {
            continue;
        }
        // The ELF analogue of Mach-O stub glue: .plt, .iplt, and the
        // CET/BTI-era .plt.* variants are fixed-format linker
        // trampolines, not compiler output, so a finding there
        // restates the psABI. The name is the only marker -- their
        // sh_type is plain SHT_PROGBITS.
        const char *sname = "";
        if (shstr != NULL && shdr->sh_name < shstrsize) {
            sname = shstr + shdr->sh_name;
            if (strcmp(sname, ".plt") == 0
                    || strcmp(sname, ".iplt") == 0
                    || strncmp(sname, ".plt.", 5) == 0) {
                continue;
            }
        }
        g_json_section = sname;
        if (shdr->sh_offset > file_size
            || shdr->sh_size > file_size - shdr->sh_offset) {
            fprintf(stderr, "%s: section %u out of bounds\n", path, i);
            errors = -1;
            break;
        }

        // This section's anchors: defined symbols the table assigns to
        // section i. st_value is absolute in linked binaries and
        // section-relative in ET_REL objects (where sh_addr, normally
        // 0, still offsets it) -- in both cases the same space as
        // sh_addr + buffer offset, under which findings resolve.
        // Three filters: mapping symbols ($x/$d mark code/data runs,
        // not functions); STT_FUNC of any binding (a C or Go function,
        // local or exported); STT_NOTYPE only when non-local --
        // assembly functions carry no .type and surface as global
        // NOTYPE, but *local* NOTYPE labels are inner jump targets
        // that Mach-O assemblers never emit into the symtab, and
        // admitting them would fork the fixture snapshots by host
        // object format. STT_OBJECT is dropped so a data island inside
        // .text cannot claim the code after it.
        armlint_symbol *table = NULL;
        anchor *tmp = NULL;
        size_t ntable = 0;
        if (nsyms > 0) {
            tmp = malloc(nsyms * sizeof(*tmp));
            table = malloc(nsyms * sizeof(*table));
            if (tmp != NULL && table != NULL) {
                size_t n = 0;
                for (size_t s = 0; s < nsyms; ++s) {
                    const Elf64_Sym *sym = &syms[s];
                    unsigned type = sym->st_info & 0xfu;
                    unsigned bind = sym->st_info >> 4;
                    if (sym->st_shndx != i || sym->st_name >= strsize) {
                        continue;
                    }
                    const char *name = strtab + sym->st_name;
                    if (name[0] == '\0' || name[0] == '$') {
                        continue;
                    }
                    if (type != STT_FUNC
                        && !(type == STT_NOTYPE && bind != STB_LOCAL)) {
                        continue;
                    }
                    tmp[n].vaddr = sym->st_value
                        + (ehdr.e_type == ET_REL ? shdr->sh_addr : 0);
                    tmp[n].name = name;
                    tmp[n].external = bind != STB_LOCAL;
                    // st_size bounds the annotation's reach; 0 (an
                    // assembler label without .size) means unknown.
                    tmp[n].size = sym->st_size;
                    n++;
                }
                ntable = anchors_finish(tmp, n, table);
            }
        }

        // This section's kept ranges under the restriction: its
        // function symbols, section-relative (st_value is absolute in
        // a linked binary, section-relative in an ET_REL object). An
        // unsized symbol -- an assembly label without .size -- extends
        // to the next function's start or the section end. A section
        // with no function symbol at all is masked whole: the table
        // positively places the functions, and this is not where it
        // put any. Allocation failure keeps the unmasked full sweep.
        code_range *keep = NULL;
        size_t nkeep = 0;
        bool restricted = false;
        if (g_func != NULL) {
            // -f: the named function's sites, or nothing from this
            // section. Skipped whole rather than scanned masked, so a
            // name matching nowhere leaves stdout empty under --json.
            int m = keep_named_function(table, ntable, shdr->sh_addr,
                                        shdr->sh_size, &keep);
            if (m < 0) {
                fprintf(stderr, "%s: failed to allocate the -f ranges\n",
                    path);
                free(tmp);
                free(table);
                errors = -1;
                break;
            }
            if (m == 0) {
                free(tmp);
                free(table);
                continue;
            }
            nkeep = (size_t)m;
            restricted = true;
        } else if (nfunc_syms > 0) {
            keep = malloc(nfunc_syms * sizeof(*keep));
            if (keep != NULL) {
                restricted = true;
                for (size_t s = 0; s < nsyms; ++s) {
                    const Elf64_Sym *sym = &syms[s];
                    unsigned type = sym->st_info & 0xfu;
                    if ((type != STT_FUNC && type != STT_GNU_IFUNC)
                            || sym->st_shndx != i) {
                        continue;
                    }
                    uint64_t off;
                    if (ehdr.e_type == ET_REL) {
                        off = sym->st_value;
                    } else if (sym->st_value >= shdr->sh_addr) {
                        off = sym->st_value - shdr->sh_addr;
                    } else {
                        continue;
                    }
                    if (off >= shdr->sh_size) {
                        continue;
                    }
                    keep[nkeep].start = off;
                    keep[nkeep].end = sym->st_size > shdr->sh_size - off
                        ? shdr->sh_size : off + sym->st_size;
                    nkeep++;
                }
                qsort(keep, nkeep, sizeof(*keep), code_range_cmp);
                for (size_t k = 0; k < nkeep; ++k) {
                    if (keep[k].end == keep[k].start) {
                        keep[k].end = k + 1 < nkeep ? keep[k + 1].start
                                                    : shdr->sh_size;
                    }
                }
                g_restrict_symbols += nkeep;
            }
        }

        // ELF has no arm64e slice concept: pac-ret/BTI on Linux is
        // recorded in .note.gnu.property, not the cpusubtype, so the
        // Mach-O auto-arm does not apply here -- pass the baseline.
        int n = scan_code(f, path, (long)shdr->sh_offset, shdr->sh_size,
                          shdr->sh_addr, handle, g_features, table, ntable,
                          restricted, keep, nkeep);
        free(keep);
        free(tmp);
        free(table);
        if (n < 0) {
            errors = -1;
            break;
        }
        errors += n;
    }
    free(shdrs);
    free(syms);
    free(strtab);
    free(shstr);
    return errors;
}

// Scan a single Mach-O 64-bit slice. base_offset is its byte offset
// within the file (0 for thin Mach-O, fat_arch.offset for fat).
// slice_size bounds it.
static int scan_macho(FILE *f, const char *path, long base_offset,
                      uint64_t slice_size, csh handle)
{
    mach_header_64 mh;
    if (slice_size < sizeof(mh)
            || !read_at(f, base_offset, &mh, sizeof(mh))) {
        fprintf(stderr, "%s: failed to read Mach-O header\n", path);
        return -1;
    }
    if (mh.magic != MH_MAGIC_64) {
        fprintf(stderr, "%s: unsupported Mach-O magic 0x%08x\n",
            path, mh.magic);
        return -1;
    }
    if ((uint32_t)mh.cputype != CPU_TYPE_ARM64) {
        fprintf(stderr, "%s: not an ARM64 Mach-O (cputype=0x%08x)\n",
            path, (uint32_t)mh.cputype);
        return -1;
    }
    if (mh.ncmds > 4096) {
        fprintf(stderr, "%s: implausible ncmds=%u\n", path, mh.ncmds);
        return -1;
    }
    if ((uint64_t)mh.sizeofcmds > slice_size - sizeof(mh)) {
        fprintf(stderr, "%s: sizeofcmds exceeds slice\n", path);
        return -1;
    }

    // An arm64e slice has opted into the PAC ABI: every function
    // signs its return address and routes indirect calls through the
    // authenticated branches. Two things follow, and arm64e arms
    // both. First, the PAC audit (-a pac): its central assumption
    // (the binary opted into pac-ret) is exactly true here, whereas a
    // plain arm64 slice never opted in and arming there would flag
    // every function's unsigned spill (the reason the audit is
    // opt-in). Second, the PAuth fold (-m pauth): arm64e mandates
    // Armv8.3 FEAT_PAuth, so the combined RETAA/RETAB it suggests are
    // guaranteed to decode and run -- which is what an -m feature
    // flag asserts -- and the split autibsp+ret epilogues it folds
    // are exactly what arm64e code emits. Neither of the other -m
    // features is implied: arm64e is a statement about pointer auth,
    // not about CSSC/LRCPC2/LSE. Explicit flags still force any of
    // these on any slice.
    //
    // arm64e.x1 has opted into the same ABI but is deliberately not
    // armed. Its functions sign and authenticate with FEAT_PAuth_LR
    // (pacibsppc, autibsppc, retabsppc), which Capstone 5 does not
    // decode and neither check models, so the audit would report
    // every function's LR spill as unsigned: 1,325 of 1,325 in the
    // x1 slice of macOS 27's /bin/bash.
    unsigned features = g_features;
    if (((uint32_t)mh.cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
        features |= ARMLINT_AUDIT_PAC | ARMLINT_FEATURE_PAUTH;
    }

    // Walk the load commands, collecting rather than scanning: the
    // code sections to lint, the __TEXT vmaddr (the base
    // LC_FUNCTION_STARTS deltas accumulate from), and the two
    // linkedit commands symbolization reads. Those sort after the
    // segments, so scanning inline would annotate nothing.
    long lc_offset = base_offset + (long)sizeof(mh);
    long lc_end = lc_offset + (long)mh.sizeofcmds;

    struct code_section {
        uint64_t offset;    // slice-relative file offset
        uint64_t size;
        uint64_t addr;
        uint32_t ordinal;   // 1-based across all segments, as n_sect counts
        char name[34];      // "__TEXT,__text", for the --json document
    } *sections = NULL;
    size_t nsections = 0, sections_cap = 0;
    symtab_command st;
    linkedit_data_command fs;
    bool have_st = false, have_fs = false, have_text = false;
    uint64_t text_vmaddr = 0;
    uint32_t sect_ordinal = 0;

    for (uint32_t i = 0; i < mh.ncmds; ++i) {
        if (lc_offset + (long)sizeof(load_command_hdr) > lc_end) {
            fprintf(stderr, "%s: load command %u truncated\n", path, i);
            goto fail;
        }
        load_command_hdr lc;
        if (!read_at(f, lc_offset, &lc, sizeof(lc))) {
            fprintf(stderr, "%s: failed to read load command %u\n", path, i);
            goto fail;
        }
        if (lc.cmdsize < sizeof(lc)
                || (long)lc.cmdsize > lc_end - lc_offset) {
            fprintf(stderr, "%s: invalid cmdsize on load command %u\n", path, i);
            goto fail;
        }

        if (lc.cmd == LC_SEGMENT_64) {
            if (lc.cmdsize < sizeof(segment_command_64)) {
                fprintf(stderr, "%s: short LC_SEGMENT_64\n", path);
                goto fail;
            }
            segment_command_64 seg;
            if (!read_at(f, lc_offset, &seg, sizeof(seg))) {
                fprintf(stderr, "%s: failed to read segment %u\n", path, i);
                goto fail;
            }
            if (seg.nsects > 1024) {
                fprintf(stderr, "%s: implausible nsects=%u\n", path, seg.nsects);
                goto fail;
            }
            uint64_t need = (uint64_t)sizeof(seg)
                + (uint64_t)seg.nsects * sizeof(section_64);
            if (need > lc.cmdsize) {
                fprintf(stderr, "%s: section headers overflow segment\n", path);
                goto fail;
            }
            if (strncmp(seg.segname, "__TEXT", sizeof(seg.segname)) == 0) {
                text_vmaddr = seg.vmaddr;
                have_text = true;
            }
            long sects_off = lc_offset + (long)sizeof(seg);
            for (uint32_t j = 0; j < seg.nsects; ++j) {
                section_64 sec;
                long off = sects_off + (long)j * (long)sizeof(sec);
                if (!read_at(f, off, &sec, sizeof(sec))) {
                    fprintf(stderr, "%s: failed to read section %u of segment %u\n",
                        path, j, i);
                    goto fail;
                }
                sect_ordinal++;     // n_sect counts every section
                if (!(sec.flags & S_ATTR_PURE_INSTRUCTIONS) || sec.size == 0) {
                    continue;
                }
                // Linker-synthesized import glue is not compiler
                // output, so a finding there restates the dyld ABI
                // rather than a codegen miss. Three sections
                // qualify: __stubs (type S_SYMBOL_STUBS), the
                // classic lazy-binding __stub_helper -- each fixed
                // 12-byte entry LDRs its lazy-bind-info offset into
                // w16 from an inline literal, exactly the shape
                // check_ldr_literal_const flags, so one minos<12
                // binary can contribute hundreds of spurious
                // findings -- and ld's __objc_stubs msgSend
                // trampolines. Skipped before the bounds check, like
                // any other unscanned section, and thereby excluded
                // from the census too.
                if ((sec.flags & SECTION_TYPE) == S_SYMBOL_STUBS
                        || strncmp(sec.sectname, "__stub_helper",
                                   sizeof(sec.sectname)) == 0
                        || strncmp(sec.sectname, "__objc_stubs",
                                   sizeof(sec.sectname)) == 0) {
                    continue;
                }
                if ((uint64_t)sec.offset > slice_size
                        || sec.size > slice_size - (uint64_t)sec.offset) {
                    fprintf(stderr, "%s: section %.16s,%.16s out of bounds\n",
                        path, sec.segname, sec.sectname);
                    goto fail;
                }
                if (nsections == sections_cap) {
                    size_t cap = sections_cap == 0 ? 8 : sections_cap * 2;
                    struct code_section *grown =
                        realloc(sections, cap * sizeof(*sections));
                    if (grown == NULL) {
                        fprintf(stderr, "%s: failed to allocate section list\n",
                            path);
                        goto fail;
                    }
                    sections = grown;
                    sections_cap = cap;
                }
                sections[nsections].offset = sec.offset;
                sections[nsections].size = sec.size;
                sections[nsections].addr = sec.addr;
                sections[nsections].ordinal = sect_ordinal;
                snprintf(sections[nsections].name,
                    sizeof(sections[nsections].name), "%.16s,%.16s",
                    sec.segname, sec.sectname);
                nsections++;
            }
        } else if (lc.cmd == LC_SYMTAB
                   && lc.cmdsize >= sizeof(symtab_command)) {
            have_st = read_at(f, lc_offset, &st, sizeof(st));
        } else if (lc.cmd == LC_FUNCTION_STARTS
                   && lc.cmdsize >= sizeof(linkedit_data_command)) {
            have_fs = read_at(f, lc_offset, &fs, sizeof(fs));
        }
        lc_offset += (long)lc.cmdsize;
    }

    // Symbolization inputs, loaded whole per slice and shared by every
    // code section: the nlist array with its string table, and the
    // decoded function-start addresses. Best-effort throughout --
    // absence (a stripped binary; Go's linker emits neither) or
    // malformed metadata degrades to unannotated findings. All
    // linkedit offsets are slice-relative. Every mode wants the
    // boundaries: the summary's by-function table, -v finding
    // annotations, -f, the census's per-function pac-ret coverage,
    // -d's functions and -c's.
    bool want_symbols = true;
    nlist_64 *nl = NULL;
    size_t nsyms = 0;
    char *strtab = NULL;
    uint64_t strsize = 0;
    uint64_t *fstarts = NULL;
    size_t nfstarts = 0;
    if (want_symbols && have_st && st.nsyms > 0
            && st.nsyms < (1u << 24)
            && (uint64_t)st.symoff <= slice_size
            && (uint64_t)st.nsyms * sizeof(nlist_64)
                <= slice_size - st.symoff
            && st.strsize > 0
            && (uint64_t)st.stroff <= slice_size
            && (uint64_t)st.strsize <= slice_size - st.stroff) {
        nl = malloc((size_t)st.nsyms * sizeof(nlist_64));
        strtab = malloc((size_t)st.strsize + 1);
        if (nl != NULL && strtab != NULL
                && read_at(f, base_offset + (long)st.symoff, nl,
                           (size_t)st.nsyms * sizeof(nlist_64))
                && read_at(f, base_offset + (long)st.stroff, strtab,
                           st.strsize)) {
            nsyms = st.nsyms;
            strsize = st.strsize;
            strtab[strsize] = '\0';
        } else {
            free(nl);
            free(strtab);
            nl = NULL;
            strtab = NULL;
        }
    }
    if (want_symbols && have_fs && have_text
            && fs.datasize > 0
            && (uint64_t)fs.dataoff <= slice_size
            && (uint64_t)fs.datasize <= slice_size - fs.dataoff) {
        // The blob is a ULEB128 stream: deltas between successive
        // function entries, the first relative to __TEXT's vmaddr; a
        // zero where a new delta would begin terminates it (the tail
        // is zero padding). Each entry consumes at least one byte, so
        // datasize bounds the count.
        uint8_t *blob = malloc(fs.datasize);
        fstarts = malloc((size_t)fs.datasize * sizeof(uint64_t));
        if (blob != NULL && fstarts != NULL
                && read_at(f, base_offset + (long)fs.dataoff, blob,
                           fs.datasize)) {
            const uint8_t *p = blob;
            const uint8_t *end = blob + fs.datasize;
            uint64_t addr = text_vmaddr;
            while (p < end && *p != 0) {
                uint64_t delta = 0;
                unsigned shift = 0;
                bool malformed = false;
                for (;;) {
                    if (p == end || shift >= 64) {
                        malformed = true;   // dangling continuation bit
                        break;
                    }
                    uint8_t byte = *p++;
                    delta |= (uint64_t)(byte & 0x7fu) << shift;
                    shift += 7;
                    if ((byte & 0x80u) == 0) {
                        break;
                    }
                }
                if (malformed) {
                    break;      // keep the valid prefix
                }
                addr += delta;
                fstarts[nfstarts++] = addr;
            }
        } else {
            free(fstarts);
            fstarts = NULL;
        }
        free(blob);
    }

    int errors = 0;
    for (size_t sidx = 0; sidx < nsections; ++sidx) {
        const struct code_section *cs = &sections[sidx];
        // Assemble this section's anchor table: nlist definitions
        // claiming its ordinal, plus function starts landing inside
        // it. A function start usually duplicates some symbol's
        // address; anchors_finish keeps the named external one. Stab
        // entries are debug records, not definitions, and unlike ELF
        // there is no type field to filter on -- any named definition
        // in a code section anchors (which is also what keeps the
        // Darwin-only fixtures' non-.globl labels annotating).
        armlint_symbol *table = NULL;
        anchor *tmp = NULL;
        size_t ntable = 0;
        size_t max = nsyms + nfstarts;
        if (max > 0) {
            tmp = malloc(max * sizeof(*tmp));
            table = malloc(max * sizeof(*table));
            if (tmp != NULL && table != NULL) {
                size_t n = 0;
                for (size_t s = 0; s < nsyms; ++s) {
                    const nlist_64 *sym = &nl[s];
                    if ((sym->n_type & N_STAB_MASK) != 0
                            || (sym->n_type & N_TYPE_MASK) != N_SECT
                            || sym->n_sect != cs->ordinal
                            || sym->n_strx >= strsize) {
                        continue;
                    }
                    const char *name = strtab + sym->n_strx;
                    if (name[0] == '\0') {
                        continue;
                    }
                    tmp[n].vaddr = sym->n_value;
                    tmp[n].name = name;
                    tmp[n].external = (sym->n_type & N_EXT) != 0;
                    tmp[n].size = 0;   // nlist records no extent
                    n++;
                }
                for (size_t s = 0; s < nfstarts; ++s) {
                    if (fstarts[s] >= cs->addr
                            && fstarts[s] - cs->addr < cs->size) {
                        tmp[n].vaddr = fstarts[s];
                        tmp[n].name = NULL;
                        tmp[n].external = false;
                        tmp[n].size = 0;
                        n++;
                    }
                }
                ntable = anchors_finish(tmp, n, table);
            }
        }
        g_json_section = cs->name;
        // Restricted only under -f: nlist records no symbol sizes, so
        // there is nothing to place a function's end by except the
        // next anchor, which is what -f settles for.
        code_range *keep = NULL;
        size_t nkeep = 0;
        bool restricted = false;
        if (g_func != NULL) {
            int m = keep_named_function(table, ntable, cs->addr, cs->size,
                                        &keep);
            if (m < 0) {
                fprintf(stderr, "%s: failed to allocate the -f ranges\n",
                    path);
                free(tmp);
                free(table);
                errors = -1;
                break;
            }
            if (m == 0) {
                free(tmp);
                free(table);
                continue;
            }
            nkeep = (size_t)m;
            restricted = true;
        }
        int n = scan_code(f, path, base_offset + (long)cs->offset,
                          cs->size, cs->addr, handle, features,
                          table, ntable, restricted, keep, nkeep);
        free(keep);
        free(tmp);
        free(table);
        if (n < 0) {
            errors = -1;
            break;
        }
        errors += n;
    }

    free(sections);
    free(nl);
    free(strtab);
    free(fstarts);
    return errors;

fail:
    free(sections);
    return -1;
}

// The variant name lipo prints for an ARM64 cpusubtype, or NULL for
// a variant this table does not know.
static const char *arm64_variant_name(uint32_t cpusubtype)
{
    switch (cpusubtype & CPU_SUBTYPE_MASK) {
    case CPU_SUBTYPE_ARM64_ALL:
        return "arm64";
    case CPU_SUBTYPE_ARM64_V8:
        return "arm64v8";
    case CPU_SUBTYPE_ARM64E:
        return "arm64e";
    case CPU_SUBTYPE_ARM64E_X1:
        return "arm64e.x1";
    default:
        return NULL;
    }
}

// One ARM64-family entry of a fat header: its index among all the
// fat_arch entries (as `otool -f` numbers them), its cpusubtype, and
// where it lies in the file.
typedef struct {
    uint32_t index;
    uint32_t cpusubtype;
    uint64_t offset;
    uint64_t size;
} arm64_slice;

// Print a slice as "2 (arm64e.x1)", falling back to the raw variant
// number for a cpusubtype arm64_variant_name does not know.
static void print_slice(FILE *out, const arm64_slice *s)
{
    const char *name = arm64_variant_name(s->cpusubtype);
    if (name != NULL) {
        fprintf(out, "%" PRIu32 " (%s)", s->index, name);
    } else {
        fprintf(out, "%" PRIu32 " (arm64 variant %" PRIu32 ")", s->index,
            s->cpusubtype & CPU_SUBTYPE_MASK);
    }
}

// Walk a fat binary and scan its ARM64-family slices. arm64, arm64e
// and arm64e.x1 all share CPU_TYPE_ARM64, and one file may hold
// several: macOS 27's /bin/bash, /usr/bin/ssh and /usr/lib/dyld each
// carry an arm64e and an arm64e.x1 slice, two compilations of one
// program, so scanning both reports each program about twice. By
// default one slice is scanned, the lowest variant -- the most widely
// runnable (arm64 before arm64e before arm64e.x1), and for those two
// system slices also the one Capstone 5 can read, since the x1 code's
// FEAT_PAuth_LR prologues and epilogues are undecodable to it (3,140
// words in /bin/bash). A note on stderr names what was skipped.
// -s all scans every ARM64 slice; -s INDEX or -s NAME picks one.
static int scan_fat(FILE *f, const char *path, bool is_fat_64,
                    uint64_t file_size, csh handle)
{
    fat_header fh;
    if (!read_at(f, 0, &fh, sizeof(fh))) {
        fprintf(stderr, "%s: failed to read fat header\n", path);
        return -1;
    }
    uint32_t nfat = be32(fh.nfat_arch);
    if (nfat > 256) {
        fprintf(stderr, "%s: implausible nfat_arch=%u\n", path, nfat);
        return -1;
    }

    size_t arch_size = is_fat_64 ? sizeof(fat_arch_64) : sizeof(fat_arch_32);
    long arches_off = (long)sizeof(fh);

    // nfat is at most 256, so every ARM64 entry fits.
    arm64_slice slices[256];
    size_t nslices = 0;
    for (uint32_t i = 0; i < nfat; ++i) {
        uint32_t cputype, cpusubtype;
        uint64_t off, size;
        long entry = arches_off + (long)i * (long)arch_size;
        if (is_fat_64) {
            fat_arch_64 a;
            if (!read_at(f, entry, &a, sizeof(a))) {
                fprintf(stderr, "%s: failed to read fat arch %u\n", path, i);
                return -1;
            }
            cputype = be32(a.cputype);
            cpusubtype = be32(a.cpusubtype);
            off = be64(a.offset);
            size = be64(a.size);
        } else {
            fat_arch_32 a;
            if (!read_at(f, entry, &a, sizeof(a))) {
                fprintf(stderr, "%s: failed to read fat arch %u\n", path, i);
                return -1;
            }
            cputype = be32(a.cputype);
            cpusubtype = be32(a.cpusubtype);
            off = (uint64_t)be32(a.offset);
            size = (uint64_t)be32(a.size);
        }
        if (cputype != CPU_TYPE_ARM64) {
            continue;
        }
        if (off > file_size || size > file_size - off) {
            fprintf(stderr, "%s: fat arch %u out of bounds\n", path, i);
            return -1;
        }
        slices[nslices].index = i;
        slices[nslices].cpusubtype = cpusubtype;
        slices[nslices].offset = off;
        slices[nslices].size = size;
        nslices++;
    }
    if (nslices == 0) {
        fprintf(stderr, "%s: fat binary contains no ARM64 slice\n", path);
        return -1;
    }

    bool all = g_slice != NULL && strcmp(g_slice, "all") == 0;
    size_t pick = 0;
    if (all) {
        // Every slice; pick is unused.
    } else if (g_slice != NULL) {
        char *end;
        unsigned long want = strtoul(g_slice, &end, 10);
        bool by_index = g_slice[0] >= '0' && g_slice[0] <= '9'
            && *end == '\0';
        pick = nslices;
        for (size_t k = 0; k < nslices; k++) {
            const char *name = arm64_variant_name(slices[k].cpusubtype);
            if (by_index ? slices[k].index == want
                    : name != NULL && strcmp(name, g_slice) == 0) {
                pick = k;
                break;
            }
        }
        if (pick == nslices) {
            fprintf(stderr, "%s: no ARM64 slice '%s'; the slices are",
                path, g_slice);
            for (size_t k = 0; k < nslices; k++) {
                fputs(k == 0 ? " " : ", ", stderr);
                print_slice(stderr, &slices[k]);
            }
            fputc('\n', stderr);
            return -1;
        }
    } else {
        for (size_t k = 1; k < nslices; k++) {
            if ((slices[k].cpusubtype & CPU_SUBTYPE_MASK)
                    < (slices[pick].cpusubtype & CPU_SUBTYPE_MASK)) {
                pick = k;
            }
        }
    }
    if (!all && nslices > 1) {
        fprintf(stderr, "%s: scanning ARM64 slice ", path);
        print_slice(stderr, &slices[pick]);
        fputs(", skipping", stderr);
        bool first = true;
        for (size_t k = 0; k < nslices; k++) {
            if (k == pick) {
                continue;
            }
            fputs(first ? " " : ", ", stderr);
            print_slice(stderr, &slices[k]);
            first = false;
        }
        fputs("; -s all scans every slice\n", stderr);
    }

    int errors = 0;
    for (size_t k = 0; k < nslices; k++) {
        if (!all && k != pick) {
            continue;
        }
        g_json_slice = arm64_variant_name(slices[k].cpusubtype);
        int n = scan_macho(f, path, (long)slices[k].offset, slices[k].size,
                           handle);
        g_json_slice = NULL;
        if (n < 0) {
            return -1;
        }
        errors += n;
    }
    return errors;
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    bool census = false;
    bool dedup = false;
    bool constants = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            g_verbose = true;
        } else if (strcmp(argv[i], "-A") == 0) {
            // Scan every byte of every code section, including the
            // bytes the symbol table places outside any function.
            g_scan_all = true;
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            // Lint just the one function: every site spelling NAME.
            g_func = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0) {
            // Also verify the ELF binary's BTI landing pads.
            g_bti = true;
        } else if (strcmp(argv[i], "-i") == 0) {
            census = true;
        } else if (strcmp(argv[i], "-d") == 0) {
            // Report duplicate code: which functions are copies of
            // one another, and which findings repeat across copies.
            dedup = true;
        } else if (strcmp(argv[i], "-c") == 0) {
            // Report the constants built by MOVZ/MOVN + MOVK chains,
            // and those a function builds more than once.
            constants = true;
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            // Enable ISA-extension-gated checks; suggestions may then
            // use instructions the target must support. pauth also
            // arms automatically on arm64e slices (see scan_macho),
            // whose ABI mandates FEAT_PAuth; the rest stay opt-in.
            i++;
            if (strcmp(argv[i], "cssc") == 0) {
                g_features |= ARMLINT_FEATURE_CSSC;
            } else if (strcmp(argv[i], "lrcpc2") == 0) {
                g_features |= ARMLINT_FEATURE_LRCPC2;
            } else if (strcmp(argv[i], "pauth") == 0) {
                g_features |= ARMLINT_FEATURE_PAUTH;
            } else if (strcmp(argv[i], "lse") == 0) {
                g_features |= ARMLINT_FEATURE_LSE;
            } else if (strcmp(argv[i], "cmpbr") == 0) {
                g_features |= ARMLINT_FEATURE_CMPBR;
            } else if (strcmp(argv[i], "sha3") == 0) {
                g_features |= ARMLINT_FEATURE_SHA3;
            } else if (strcmp(argv[i], "fp16") == 0) {
                g_features |= ARMLINT_FEATURE_FP16;
            } else if (strcmp(argv[i], "v8") == 0) {
                // Not an ISA extension but an input: a V8 JIT dump
                // (v8dump2elf output from a pointer-compressed build).
                // Asserts both of V8's stream invariants at once --
                // x28 is the 4GB-aligned cage base, and every LDR XZR,
                // (literal) word opens a constant pool the scans step
                // over -- since neither is useful alone on such a dump
                // (see ARMLINT_FEATURE_V8).
                g_features |= ARMLINT_FEATURE_V8;
            } else {
                fprintf(stderr, "%s: unknown -m feature '%s' "
                    "(known: cssc, lrcpc2, pauth, lse, cmpbr, "
                    "sha3, fp16, v8)\n",
                    argv[0], argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            // Enable opt-in audit checks: informational findings
            // about missing hardening rather than missed folds. The
            // PAC audit also arms automatically on arm64e slices
            // (see scan_macho); passing it here forces it on any
            // slice, e.g. a plain arm64 binary built with pac-ret.
            i++;
            if (strcmp(argv[i], "pac") == 0) {
                g_features |= ARMLINT_AUDIT_PAC;
            } else if (strcmp(argv[i], "imm") == 0) {
                g_features |= ARMLINT_AUDIT_IMM;
            } else if (strcmp(argv[i], "const") == 0) {
                g_features |= ARMLINT_AUDIT_CONST;
            } else {
                fprintf(stderr, "%s: unknown -a audit '%s' "
                    "(known: pac, imm, const)\n", argv[0], argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--json") == 0) {
            // The findings as one JSON document on stdout, in place
            // of the human report (see json_finding).
            g_json = true;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            // Which ARM64 slice of a universal binary to scan: "all",
            // a fat_arch index, or a variant name such as arm64e.x1.
            // Checked against the file's slices in scan_fat, and
            // ignored for a thin Mach-O or ELF file, which has one.
            g_slice = argv[++i];
        } else if (path == NULL && argv[i][0] != '-') {
            path = argv[i];
        } else {
            fprintf(stderr, "usage: %s [-v] [-A] [-f FUNC] [-b] [-i] [-d] [-c] [--json] [-m cssc|lrcpc2|pauth|lse|cmpbr|sha3|fp16|v8]\n            [-a pac|imm|const] [-s all|INDEX|NAME] <FILE>\n",
                argv[0]);
            return 2;
        }
    }
    if (path == NULL) {
        fprintf(stderr, "usage: %s [-v] [-A] [-f FUNC] [-b] [-i] [-d] [-c] [--json] [-m cssc|lrcpc2|pauth|lse|cmpbr|sha3|fp16|v8]\n            [-a pac|imm|const] [-s all|INDEX|NAME] <FILE>\n",
            argv[0]);
        return 2;
    }

    // -A widens the scan to every byte and -f narrows it to one
    // function; combining them has no coherent meaning.
    if (g_func != NULL && g_scan_all) {
        fprintf(stderr, "%s: -A and -f are mutually exclusive\n", argv[0]);
        return 2;
    }
    // --json owns stdout: -v would interleave per-finding text with
    // the document, and -i, -d, -c and -b are other reports.
    if (g_json && (g_verbose || census || dedup || constants || g_bti)) {
        fprintf(stderr, "%s: --json cannot be combined with -v, -i, -d, -c "
            "or -b\n", argv[0]);
        return 2;
    }
    g_json_path = path;

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        return 2;
    }

    // The exit status follows the grep convention -- 0 for a clean
    // scan, 1 when any opportunity is found, 2 on a tool failure (a
    // bad invocation, an unreadable or malformed file, an allocation
    // failure) -- so a CI job can tell a dirty scan from a broken run.
    // Every goto-out path below is an error, so failure is the default.
    int rc = 2;
    csh handle = 0;
    bool capstone_open = false;

    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "%s: failed to seek to end of file\n", path);
        goto out;
    }
    long file_size_signed = ftell(f);
    if (file_size_signed < 0) {
        fprintf(stderr, "%s: failed to get file size\n", path);
        goto out;
    }
    uint64_t file_size = (uint64_t)file_size_signed;
    if (file_size < 4) {
        fprintf(stderr, "%s: file too short\n", path);
        goto out;
    }

    uint8_t magic[4];
    if (!read_at(f, 0, magic, sizeof(magic))) {
        fprintf(stderr, "%s: failed to read magic bytes\n", path);
        goto out;
    }

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        fprintf(stderr, "%s: failed to initialize Capstone\n", path);
        goto out;
    }
    capstone_open = true;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // NULL is tolerated by the summary API (tallying is simply skipped).
    g_summary = armlint_summary_create();

    // The census, by contrast, IS the whole report of a -i run, so a
    // NULL from allocation failure would degrade to printing nothing;
    // fail hard instead.
    if (census) {
        g_census = armlint_census_create();
        if (g_census == NULL) {
            fprintf(stderr, "%s: failed to allocate the ISA census\n", path);
            goto out;
        }
    }

    // Likewise the duplicate-code report. In lint mode the summary
    // hands it every finding, to be told apart from its repeats.
    if (dedup) {
        g_dedup = armlint_dedup_create();
        if (g_dedup == NULL) {
            fprintf(stderr, "%s: failed to allocate the duplicate-code "
                "tables\n", path);
            goto out;
        }
        if (!census) {
            armlint_summary_set_dedup(g_summary, g_dedup);
        }
    }

    // And the constant report.
    if (constants) {
        g_constants = armlint_constants_create();
        if (g_constants == NULL) {
            fprintf(stderr, "%s: failed to allocate the constant tables\n",
                path);
            goto out;
        }
    }

    int errors = -1;
    bool is_elf = memcmp(magic, ELFMAG, SELFMAG) == 0;
    if (is_elf) {
        errors = scan_elf(f, path, file_size, handle);
    } else {
        // Mach-O magic is stored host-endian (always little on ARM64);
        // fat magic is stored big-endian on disk so the kernel can
        // distinguish them from a byte-swapped Mach-O.
        uint32_t m_le = (uint32_t)magic[0] | ((uint32_t)magic[1] << 8)
            | ((uint32_t)magic[2] << 16) | ((uint32_t)magic[3] << 24);
        uint32_t m_be = ((uint32_t)magic[0] << 24) | ((uint32_t)magic[1] << 16)
            | ((uint32_t)magic[2] << 8) | (uint32_t)magic[3];
        if (m_le == MH_MAGIC_64) {
            errors = scan_macho(f, path, 0, file_size, handle);
        } else if (m_be == FAT_MAGIC) {
            errors = scan_fat(f, path, false, file_size, handle);
        } else if (m_be == FAT_MAGIC_64) {
            errors = scan_fat(f, path, true, file_size, handle);
        } else {
            fprintf(stderr,
                "%s: unsupported file format (magic %02x %02x %02x %02x)\n",
                path, magic[0], magic[1], magic[2], magic[3]);
        }
    }

    if (errors < 0) {
        goto out;
    }
    if (g_func != NULL && g_func_sites == 0) {
        fprintf(stderr, "%s: no function symbol named '%s'\n", path, g_func);
        goto out;
    }
    // The BTI pass is separate from the peephole scan -- its findings
    // are faults located by virtual address, not encoding
    // opportunities located by section offset -- so it reports its
    // own block, after the scan's, and only shares the exit status.
    // Mach-O has no BTI: arm64e's branch protection is pointer
    // authentication, which the -a pac audit judges.
    int bti_errors = 0;
    if (g_bti && !is_elf) {
        fprintf(stderr, "%s: -b applies to ELF binaries\n", path);
        goto out;
    }
    if (census) {
        armlint_census_print(g_census, g_verbose);
        if (g_func != NULL) {
            printf("  scan restricted to function '%s': %zu site%s, "
                "%" PRIu64 " bytes\n", g_func, g_func_sites,
                g_func_sites == 1 ? "" : "s", g_func_bytes);
        }
        if (g_dedup != NULL || g_constants != NULL) {
            printf("\n");
        }
        armlint_dedup_print(g_dedup, g_verbose);
        armlint_constants_print(g_constants, g_verbose);
        if (g_bti) {
            bti_errors = check_elf_bti(f, path, file_size, g_verbose);
            if (bti_errors < 0) {
                goto out;
            }
        }
        rc = bti_errors != 0;
    } else if (g_json) {
        // The totals close the document because the scan only knows
        // them now. A file with no code still gets a complete document
        // with an empty array.
        json_begin();
        printf("\n  ],\n");
        // What narrowed the scan, so that a restricted scan is not
        // read as a clean sweep of the whole file.
        if (g_func != NULL) {
            printf("  \"restriction\": {\"function\": ");
            json_string(g_func);
            printf(", \"sites\": %zu, \"bytes\": %" PRIu64 "},\n",
                g_func_sites, g_func_bytes);
        } else if (g_restrict_symbols != 0) {
            printf("  \"restriction\": {\"symbols\": %zu},\n",
                g_restrict_symbols);
        }
        printf("  \"instructions\": %zu,\n"
               "  \"skipped\": %zu,\n"
               "  \"opportunities\": %d\n}\n",
            armlint_summary_instructions(g_summary),
            armlint_summary_skipped(g_summary), errors);
        rc = errors != 0;
    } else {
        armlint_summary_print(g_summary);
        armlint_dedup_print(g_dedup, g_verbose);
        armlint_constants_print(g_constants, g_verbose);
        if (g_bti) {
            bti_errors = check_elf_bti(f, path, file_size, g_verbose);
            if (bti_errors < 0) {
                goto out;
            }
            printf("\n");
        }
        if (g_func != NULL) {
            printf("scan restricted to function '%s': %zu site%s, "
                "%" PRIu64 " bytes\n", g_func, g_func_sites,
                g_func_sites == 1 ? "" : "s", g_func_bytes);
        } else if (g_restrict_symbols != 0) {
            printf("scan restricted to %zu function symbol%s "
                "(-A scans every byte)\n", g_restrict_symbols,
                g_restrict_symbols == 1 ? "" : "s");
        }
        printf("%d optimization opportunities in %zu instructions\n",
            errors, armlint_summary_instructions(g_summary));
        rc = errors != 0 || bti_errors != 0;
    }

out:
    armlint_census_destroy(g_census);
    armlint_summary_destroy(g_summary);
    armlint_dedup_destroy(g_dedup);
    armlint_constants_destroy(g_constants);
    if (capstone_open) {
        cs_close(&handle);
    }
    fclose(f);
    return rc;
}
