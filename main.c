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
#define SHT_DYNSYM    11
#define SHF_EXECINSTR 0x4
#define STB_LOCAL     0
#define STT_NOTYPE    0
#define STT_FUNC      2

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
// capability/feature bits (CPU_SUBTYPE_PTRAUTH_ABI etc.). arm64e is 2.
#define CPU_SUBTYPE_MASK   0x00ffffffu
#define CPU_SUBTYPE_ARM64E 0x00000002u
#define LC_SYMTAB          0x2u
#define LC_SEGMENT_64      0x19u
#define LC_FUNCTION_STARTS 0x26u
#define S_ATTR_PURE_INSTRUCTIONS 0x80000000u
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
            continue;
        }
        out[m].vaddr = tmp[i].vaddr;
        out[m].name = tmp[i].name;
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
// Non-NULL in -i census mode: scan_code then tallies instead of
// linting, and main prints the census in place of the findings report.
static armlint_census *g_census = NULL;

// Read `size` bytes at `base_offset` and run all checks with the
// given feature/audit set. vmaddr is the section's runtime base,
// reported back to the user in findings; symbols/nsymbols (possibly
// NULL/0) annotate verbose findings with the containing function.
static int scan_code(FILE *f, const char *path, long base_offset,
                     uint64_t size, uint64_t vmaddr, csh handle,
                     unsigned features,
                     const armlint_symbol *symbols, size_t nsymbols)
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
    int n;
    if (g_census != NULL) {
        // Census mode: tally only. The report prints once, after every
        // section of every slice has been scanned.
        armlint_census_scan(g_census, handle, buf, aligned, vmaddr);
        n = 0;
    } else {
        n = check_instructions(handle, buf, aligned, vmaddr,
                               g_verbose, g_summary, features,
                               symbols, nsymbols);
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
    // that matter most). Annotations render only on -v finding
    // headers, so the other modes skip the IO entirely.
    Elf64_Sym *syms = NULL;
    size_t nsyms = 0;
    char *strtab = NULL;
    uint64_t strsize = 0;
    if (g_verbose && g_census == NULL) {
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

    int errors = 0;
    for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
        const Elf64_Shdr *shdr = &shdrs[i];
        if (shdr->sh_type != SHT_PROGBITS
            || !(shdr->sh_flags & SHF_EXECINSTR)
            || shdr->sh_size == 0) {
            continue;
        }
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
                    n++;
                }
                ntable = anchors_finish(tmp, n, table);
            }
        }

        // ELF has no arm64e slice concept: pac-ret/BTI on Linux is
        // recorded in .note.gnu.property, not the cpusubtype, so the
        // Mach-O auto-arm does not apply here -- pass the baseline.
        int n = scan_code(f, path, (long)shdr->sh_offset, shdr->sh_size,
                          shdr->sh_addr, handle, g_features, table, ntable);
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
    // linkedit offsets are slice-relative. Annotations render only on
    // -v finding headers, so the other modes skip the IO.
    nlist_64 *nl = NULL;
    size_t nsyms = 0;
    char *strtab = NULL;
    uint64_t strsize = 0;
    uint64_t *fstarts = NULL;
    size_t nfstarts = 0;
    if (g_verbose && g_census == NULL && have_st && st.nsyms > 0
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
    if (g_verbose && g_census == NULL && have_fs && have_text
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
                    n++;
                }
                for (size_t s = 0; s < nfstarts; ++s) {
                    if (fstarts[s] >= cs->addr
                            && fstarts[s] - cs->addr < cs->size) {
                        tmp[n].vaddr = fstarts[s];
                        tmp[n].name = NULL;
                        tmp[n].external = false;
                        n++;
                    }
                }
                ntable = anchors_finish(tmp, n, table);
            }
        }
        int n = scan_code(f, path, base_offset + (long)cs->offset,
                          cs->size, cs->addr, handle, features,
                          table, ntable);
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

// Walk a fat binary and scan every ARM64-family slice. arm64 and
// arm64e share CPU_TYPE_ARM64; both are scanned.
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

    int errors = 0;
    bool found_arm64 = false;
    for (uint32_t i = 0; i < nfat; ++i) {
        uint32_t cputype;
        uint64_t off, size;
        long entry = arches_off + (long)i * (long)arch_size;
        if (is_fat_64) {
            fat_arch_64 a;
            if (!read_at(f, entry, &a, sizeof(a))) {
                fprintf(stderr, "%s: failed to read fat arch %u\n", path, i);
                return -1;
            }
            cputype = be32(a.cputype);
            off = be64(a.offset);
            size = be64(a.size);
        } else {
            fat_arch_32 a;
            if (!read_at(f, entry, &a, sizeof(a))) {
                fprintf(stderr, "%s: failed to read fat arch %u\n", path, i);
                return -1;
            }
            cputype = be32(a.cputype);
            off = (uint64_t)be32(a.offset);
            size = (uint64_t)be32(a.size);
        }
        if (cputype != CPU_TYPE_ARM64) {
            continue;
        }
        found_arm64 = true;

        if (off > file_size || size > file_size - off) {
            fprintf(stderr, "%s: fat arch %u out of bounds\n", path, i);
            return -1;
        }
        int n = scan_macho(f, path, (long)off, size, handle);
        if (n < 0) {
            return -1;
        }
        errors += n;
    }
    if (!found_arm64) {
        fprintf(stderr, "%s: fat binary contains no ARM64 slice\n", path);
        return -1;
    }
    return errors;
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    bool census = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            g_verbose = true;
        } else if (strcmp(argv[i], "-i") == 0) {
            census = true;
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
            } else {
                fprintf(stderr, "%s: unknown -m feature '%s' "
                    "(known: cssc, lrcpc2, pauth, lse)\n", argv[0], argv[i]);
                return 1;
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
            } else {
                fprintf(stderr, "%s: unknown -a audit '%s' "
                    "(known: pac)\n", argv[0], argv[i]);
                return 1;
            }
        } else if (path == NULL && argv[i][0] != '-') {
            path = argv[i];
        } else {
            fprintf(stderr, "usage: %s [-v] [-i] [-m cssc|lrcpc2|pauth|lse] [-a pac] <FILE>\n",
                argv[0]);
            return 1;
        }
    }
    if (path == NULL) {
        fprintf(stderr, "usage: %s [-v] [-i] [-m cssc|lrcpc2|pauth|lse] [-a pac] <FILE>\n",
            argv[0]);
        return 1;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        return 1;
    }

    int rc = 1;
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

    int errors = -1;
    if (memcmp(magic, ELFMAG, SELFMAG) == 0) {
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
    if (census) {
        armlint_census_print(g_census, g_verbose);
        rc = 0;
    } else {
        armlint_summary_print(g_summary);
        printf("%d optimization opportunities in %zu instructions\n",
            errors, armlint_summary_instructions(g_summary));
        rc = errors != 0;
    }

out:
    armlint_census_destroy(g_census);
    armlint_summary_destroy(g_summary);
    if (capstone_open) {
        cs_close(&handle);
    }
    fclose(f);
    return rc;
}
