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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <capstone/capstone.h>

#include "armlint.h"

// Minimal ELF64 declarations -- Darwin has no <elf.h>, and the bits
// we need are stable across implementations.
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

static bool read_at(FILE *f, long off, void *buf, size_t n)
{
    if (fseek(f, off, SEEK_SET) != 0) {
        return false;
    }
    return fread(buf, 1, n, f) == n;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <ELF_FILE>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror(argv[1]);
        return 1;
    }

    int rc = 1;
    uint8_t *buf = NULL;
    csh handle = 0;
    bool capstone_open = false;

    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "%s: failed to seek to end of file\n", argv[1]);
        goto out;
    }
    long file_size_signed = ftell(f);
    if (file_size_signed < 0) {
        fprintf(stderr, "%s: failed to get file size\n", argv[1]);
        goto out;
    }
    uint64_t file_size = (uint64_t) file_size_signed;

    Elf64_Ehdr ehdr;
    if (!read_at(f, 0, &ehdr, sizeof(ehdr))) {
        fprintf(stderr, "%s: failed to read ELF header\n", argv[1]);
        goto out;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s: not an ELF file\n", argv[1]);
        goto out;
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "%s: only 64-bit ELF files are supported\n", argv[1]);
        goto out;
    }
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "%s: only little-endian ELF files are supported\n", argv[1]);
        goto out;
    }
    if (ehdr.e_machine != EM_AARCH64) {
        fprintf(stderr, "%s: not an AArch64 ELF (e_machine=%u)\n",
            argv[1], ehdr.e_machine);
        goto out;
    }

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        fprintf(stderr, "%s: failed to initialize Capstone\n", argv[1]);
        goto out;
    }
    capstone_open = true;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    int errors = 0;
    for (uint16_t i = 0; i < ehdr.e_shnum; ++i) {
        Elf64_Shdr shdr;
        if (!read_at(f, ehdr.e_shoff + (long) i * sizeof(shdr), &shdr, sizeof(shdr))) {
            fprintf(stderr, "%s: failed to read section header %u\n", argv[1], i);
            goto out;
        }

        if (shdr.sh_type != SHT_PROGBITS || !(shdr.sh_flags & SHF_EXECINSTR) || shdr.sh_size == 0) {
            continue;
        }

        if (shdr.sh_offset > file_size ||
            shdr.sh_size > file_size - shdr.sh_offset) {
            fprintf(stderr,
                "%s: section %u out of bounds (offset %lu size %lu, file %lu)\n",
                argv[1], i, (unsigned long) shdr.sh_offset,
                (unsigned long) shdr.sh_size, (unsigned long) file_size);
            goto out;
        }

        // A64 instructions are 4 bytes; a section whose size isn't a
        // multiple of 4 either has padding bytes we should not decode
        // or is something unusual. Round down to the largest multiple
        // and keep going.
        uint64_t section_size = shdr.sh_size & ~(uint64_t)3;
        if (section_size == 0) {
            continue;
        }

        buf = malloc(section_size);
        if (buf == NULL) {
            fprintf(stderr, "%s: failed to allocate %lu bytes\n",
                argv[1], (unsigned long) section_size);
            goto out;
        }
        if (!read_at(f, shdr.sh_offset, buf, section_size)) {
            fprintf(stderr, "%s: failed to read section %u\n", argv[1], i);
            goto out;
        }

        int n = check_instructions(handle, buf, section_size, shdr.sh_addr);
        if (n < 0) {
            goto out;
        }
        errors += n;

        free(buf);
        buf = NULL;
    }

    printf("%d errors\n", errors);
    rc = errors != 0;

out:
    free(buf);
    if (capstone_open) {
        cs_close(&handle);
    }
    fclose(f);
    return rc;
}
