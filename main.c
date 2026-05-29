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

// === Mach-O minimal definitions ===
//
// Apple's <mach-o/*.h> would do, but they pull in <mach/machine.h> and
// host-only types. Reproducing the on-disk layout here keeps Linux
// builds buildable too.

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

static bool read_at(FILE *f, long off, void *buf, size_t n)
{
    if (fseek(f, off, SEEK_SET) != 0) {
        return false;
    }
    return fread(buf, 1, n, f) == n;
}

// CLI-level reporting state, set once in main() and read by scan_code
// (the only caller of check_instructions). Kept here rather than
// threaded through scan_elf/scan_macho/scan_fat, which don't need it.
static bool g_verbose = false;
static armlint_summary *g_summary = NULL;

// Read `size` bytes at `base_offset` and run all checks. vmaddr is the
// section's runtime base, reported back to the user in findings.
static int scan_code(FILE *f, const char *path, long base_offset,
                     uint64_t size, uint64_t vmaddr, csh handle)
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
    int n = check_instructions(handle, buf, aligned, vmaddr,
                               g_verbose, g_summary);
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

    int errors = 0;
    for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
        Elf64_Shdr shdr;
        if (!read_at(f, ehdr.e_shoff + (long)i * (long)sizeof(shdr),
                     &shdr, sizeof(shdr))) {
            fprintf(stderr, "%s: failed to read section header %u\n", path, i);
            return -1;
        }
        if (shdr.sh_type != SHT_PROGBITS
            || !(shdr.sh_flags & SHF_EXECINSTR)
            || shdr.sh_size == 0) {
            continue;
        }
        if (shdr.sh_offset > file_size
            || shdr.sh_size > file_size - shdr.sh_offset) {
            fprintf(stderr, "%s: section %u out of bounds\n", path, i);
            return -1;
        }
        int n = scan_code(f, path, (long)shdr.sh_offset, shdr.sh_size,
                          shdr.sh_addr, handle);
        if (n < 0) {
            return -1;
        }
        errors += n;
    }
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

    int errors = 0;
    long lc_offset = base_offset + (long)sizeof(mh);
    long lc_end = lc_offset + (long)mh.sizeofcmds;

    for (uint32_t i = 0; i < mh.ncmds; ++i) {
        if (lc_offset + (long)sizeof(load_command_hdr) > lc_end) {
            fprintf(stderr, "%s: load command %u truncated\n", path, i);
            return -1;
        }
        load_command_hdr lc;
        if (!read_at(f, lc_offset, &lc, sizeof(lc))) {
            fprintf(stderr, "%s: failed to read load command %u\n", path, i);
            return -1;
        }
        if (lc.cmdsize < sizeof(lc)
                || (long)lc.cmdsize > lc_end - lc_offset) {
            fprintf(stderr, "%s: invalid cmdsize on load command %u\n", path, i);
            return -1;
        }

        if (lc.cmd == LC_SEGMENT_64) {
            if (lc.cmdsize < sizeof(segment_command_64)) {
                fprintf(stderr, "%s: short LC_SEGMENT_64\n", path);
                return -1;
            }
            segment_command_64 seg;
            if (!read_at(f, lc_offset, &seg, sizeof(seg))) {
                fprintf(stderr, "%s: failed to read segment %u\n", path, i);
                return -1;
            }
            if (seg.nsects > 1024) {
                fprintf(stderr, "%s: implausible nsects=%u\n", path, seg.nsects);
                return -1;
            }
            uint64_t need = (uint64_t)sizeof(seg)
                + (uint64_t)seg.nsects * sizeof(section_64);
            if (need > lc.cmdsize) {
                fprintf(stderr, "%s: section headers overflow segment\n", path);
                return -1;
            }
            long sects_off = lc_offset + (long)sizeof(seg);
            for (uint32_t j = 0; j < seg.nsects; ++j) {
                section_64 sec;
                long off = sects_off + (long)j * (long)sizeof(sec);
                if (!read_at(f, off, &sec, sizeof(sec))) {
                    fprintf(stderr, "%s: failed to read section %u of segment %u\n",
                        path, j, i);
                    return -1;
                }
                if (!(sec.flags & S_ATTR_PURE_INSTRUCTIONS) || sec.size == 0) {
                    continue;
                }
                if ((uint64_t)sec.offset > slice_size
                        || sec.size > slice_size - (uint64_t)sec.offset) {
                    fprintf(stderr, "%s: section %.16s,%.16s out of bounds\n",
                        path, sec.segname, sec.sectname);
                    return -1;
                }
                int n = scan_code(f, path, base_offset + (long)sec.offset,
                                  sec.size, sec.addr, handle);
                if (n < 0) {
                    return -1;
                }
                errors += n;
            }
        }
        lc_offset += (long)lc.cmdsize;
    }
    return errors;
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
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            g_verbose = true;
        } else if (path == NULL && argv[i][0] != '-') {
            path = argv[i];
        } else {
            fprintf(stderr, "usage: %s [-v] <FILE>\n", argv[0]);
            return 1;
        }
    }
    if (path == NULL) {
        fprintf(stderr, "usage: %s [-v] <FILE>\n", argv[0]);
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
    armlint_summary_print(g_summary);
    printf("%d optimization opportunities in %zu instructions\n",
        errors, armlint_summary_instructions(g_summary));
    rc = errors != 0;

out:
    armlint_summary_destroy(g_summary);
    if (capstone_open) {
        cs_close(&handle);
    }
    fclose(f);
    return rc;
}
