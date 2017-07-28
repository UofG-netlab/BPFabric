/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include "ubpf_int.h"
#include <elf.h>

#include <unistd.h>
#include "bpfmap.h"

#define MAX_SECTIONS 32

struct bounds {
    const void *base;
    uint64_t size;
};

struct section {
    const Elf64_Shdr *shdr;
    const void *data;
    uint64_t size;
};

// Should we replace this with the definition in linux/bpf.h?
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

#ifndef EM_BPF
#define EM_BPF 0xF7
#endif

#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif

static const void *
bounds_check(struct bounds *bounds, uint64_t offset, uint64_t size)
{
    if (offset + size > bounds->size || offset + size < offset) {
        return NULL;
    }
    return bounds->base + offset;
}

int
ubpf_load_elf(struct ubpf_vm *vm, const void *elf, size_t elf_size, char **errmsg)
{
    struct bounds b = { .base=elf, .size=elf_size };
    void *text_copy = NULL;
    int i;

    const Elf64_Ehdr *ehdr = bounds_check(&b, 0, sizeof(*ehdr));
    if (!ehdr) {
        *errmsg = ubpf_error("not enough data for ELF header");
        goto error;
    }

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
        *errmsg = ubpf_error("wrong magic");
        goto error;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        *errmsg = ubpf_error("wrong class");
        goto error;
    }

//    TODO CHECK: This check assumes the host platform and the eBPF endianess architecture match
//    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
//        *errmsg = ubpf_error("wrong byte order: got %d expected %d", ehdr->e_ident[EI_DATA], ELFDATA2LSB);
//        goto error;
//    }

    if (ehdr->e_ident[EI_VERSION] != 1) {
        *errmsg = ubpf_error("wrong version");
        goto error;
    }

    if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE) {
        *errmsg = ubpf_error("wrong OS ABI");
        goto error;
    }

    if (ehdr->e_type != ET_REL) {
        *errmsg = ubpf_error("wrong type, expected relocatable");
        goto error;
    }


    if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF) {
        *errmsg = ubpf_error("wrong machine, expected none or EM_BPF (%d)", EM_BPF);
        goto error;
    }

    if (ehdr->e_shnum > MAX_SECTIONS) {
        *errmsg = ubpf_error("too many sections");
        goto error;
    }

    // ref to string table, TODO: probably a better way to reference to the strings_table
    const char* strings_table = NULL;

    /* Parse section headers into an array */
    struct section sections[MAX_SECTIONS];
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = bounds_check(&b, ehdr->e_shoff + i*ehdr->e_shentsize, sizeof(*shdr));
        if (!shdr) {
            *errmsg = ubpf_error("bad section header offset or size");
            goto error;
        }

        const void *data = bounds_check(&b, shdr->sh_offset, shdr->sh_size);
        if (!data) {
            *errmsg = ubpf_error("bad section offset or size");
            goto error;
        }

        sections[i].shdr = shdr;
        sections[i].data = data;
        sections[i].size = shdr->sh_size;

        // Store the reference to the strings table
        if (shdr->sh_type == SHT_STRTAB) {
            strings_table = data;
        }
    }

    // Find the reference to the symtab and maps sections, NOTE: quite hacky way of doing things ...
    int symtab_idx = 0;
    int maps_idx = 0;

    for (i = 0; i < ehdr->e_shnum; i++) {
        struct section *sec = &sections[i];

        if (sec->shdr->sh_type == SHT_SYMTAB) {
            symtab_idx = i;
        }

        else if (strcmp("maps", strings_table + sec->shdr->sh_name) == 0) {
            maps_idx = i;
        }
    }

    if (symtab_idx != 0 && maps_idx != 0) {
        // Iterate over symbol definition to find the maps
        struct section *symtab = &sections[symtab_idx];
        const Elf64_Sym *syms = symtab->data;
        uint32_t num_syms = symtab->size/sizeof(Elf64_Sym);
        for (i = 0; i < num_syms; i++) {
            // Get the related section using st_shndx entry
            const Elf64_Sym *sym = &syms[i];
            struct section *rel = &sections[sym->st_shndx];

            // If the related section is the maps definition, then we have a table definition symbol
            if (sym->st_shndx == maps_idx) {
                int bpf_map_def_idx = sym->st_value / sizeof(struct bpf_map_def);
                const struct bpf_map_def *maps_defs = rel->data;
                const struct bpf_map_def map_def = maps_defs[bpf_map_def_idx];

                // TODO do we have to copy the name as it will be copied again ...
                char map_name[TABLE_NAME_MAX_LENGTH] = {0};
                strncpy(map_name, strings_table + sym->st_name, TABLE_NAME_MAX_LENGTH-1);

                //
                int ret;
                struct table_entry *tab_entry;
                ret = bpf_lookup_elem(vm->tables, map_name, &tab_entry);

                // If the map doesn't exist create it
                if (ret == -1) {
                    tab_entry = calloc(1, sizeof(struct table_entry));
                    tab_entry->fd = bpf_create_map(map_def.type, map_def.key_size, map_def.value_size, map_def.max_entries);
                    printf("created map %s with fd %d\n", map_name, tab_entry->fd);

                    if (tab_entry->fd == -1)  {
                        *errmsg = ubpf_error("unable to allocate BPF table");
                        goto error;
                    }

                    tab_entry->type = map_def.type;
                    tab_entry->key_size = map_def.key_size;
                    tab_entry->value_size = map_def.value_size;
                    tab_entry->max_entries = map_def.max_entries;

                    ret = bpf_update_elem(vm->tables, map_name, tab_entry, 0);
                    free(tab_entry);
                }
            }
        }
    }

    /* Find first text section */
    int text_shndx = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {
            text_shndx = i;
            break;
        }
    }

    if (!text_shndx) {
        *errmsg = ubpf_error("text section not found");
        goto error;
    }

    struct section *text = &sections[text_shndx];

    /* May need to modify text for relocations, so make a copy */
    text_copy = malloc(text->size);
    if (!text_copy) {
        *errmsg = ubpf_error("failed to allocate memory");
        goto error;
    }
    memcpy(text_copy, text->data, text->size);

    /* Process each relocation section */
    for (i = 0; i < ehdr->e_shnum; i++) {
        struct section *rel = &sections[i];

        if (rel->shdr->sh_type != SHT_REL) {
            continue;
        } else if (rel->shdr->sh_info != text_shndx) {
            continue;
        }

        const Elf64_Rel *rs = rel->data;

        if (rel->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ubpf_error("bad symbol table section index");
            goto error;
        }

        struct section *symtab = &sections[rel->shdr->sh_link];
        const Elf64_Sym *syms = symtab->data;
        uint32_t num_syms = symtab->size/sizeof(syms[0]);

        if (symtab->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ubpf_error("bad string table section index");
            goto error;
        }

        struct section *strtab = &sections[symtab->shdr->sh_link];
        const char *strings = strtab->data;

        int j;
        for (j = 0; j < rel->size/sizeof(Elf64_Rel); j++) {
            const Elf64_Rel *r = &rs[j];


            uint32_t sym_idx = ELF64_R_SYM(r->r_info);
            if (sym_idx >= num_syms) {
                *errmsg = ubpf_error("bad symbol index");
                goto error;
            }

            const Elf64_Sym *sym = &syms[sym_idx];

            if (sym->st_name >= strtab->size) {
                *errmsg = ubpf_error("bad symbol name");
                goto error;
            }

            const char *sym_name = strings + sym->st_name;
            // printf("symbol name %s sym_idx %d  ndx: %d\n", sym_name, sym_idx, sym->st_shndx);

            if (r->r_offset + 8 > text->size) {
                *errmsg = ubpf_error("bad relocation offset");
                goto error;
            }

            // Custom map relocation
            if (ELF64_R_TYPE(r->r_info) == 1 && sym->st_shndx == maps_idx) { // map relocation
                struct ebpf_inst *insns = text_copy;
                unsigned int insn_idx;

                insn_idx = r->r_offset / sizeof(struct ebpf_inst);

                if (insns[insn_idx].opcode != (EBPF_CLS_LD | EBPF_SRC_IMM | EBPF_SIZE_DW)) {
                    *errmsg = ubpf_error("bad relocation for instruction 0x%x at index %d\n", insns[insn_idx].opcode, insn_idx);
                    goto error;
                }

                char map_name[32] = {0};
                struct table_entry *tab_entry;
                strncpy(map_name, sym_name, 31);

                if (bpf_lookup_elem(vm->tables, map_name, &tab_entry) != 0) {
                    *errmsg = ubpf_error("cannot find map");
                    goto error;
                }

                insns[insn_idx].src = BPF_PSEUDO_MAP_FD; // do we need this?
                insns[insn_idx].imm = tab_entry->fd;
            }

            // Perform string relocation
            else if (ELF64_R_TYPE(r->r_info) == 1) {
                struct section *rodata = &sections[sym->st_shndx];
                // printf("value %lu s %s\n", sym->st_value, rodata_value);

                struct ebpf_inst *insns = text_copy;
                unsigned int insn_idx;

                insn_idx = r->r_offset / sizeof(struct ebpf_inst);

                if (insns[insn_idx].opcode != (EBPF_CLS_LD | EBPF_SRC_IMM | EBPF_SIZE_DW)) {
                    *errmsg = ubpf_error("bad relocation for instruction 0x%x at index %d\n", insns[insn_idx].opcode, insn_idx);
                    goto error;
                }

                uint64_t address = (uintptr_t)rodata->data + sym->st_value;
                insns[insn_idx].imm = address;
                insns[insn_idx+1].imm = address >> 32;
            }

            else if (ELF64_R_TYPE(r->r_info) == 2) {
                unsigned int imm = ubpf_lookup_registered_function(vm, sym_name);
                if (imm == -1) {
                    *errmsg = ubpf_error("function '%s' not found", sym_name);
                    goto error;
                }

                *(uint32_t *)(text_copy + r->r_offset + 4) = imm;
            }


            else {
                *errmsg = ubpf_error("bad relocation type %u", ELF64_R_TYPE(r->r_info));
                goto error;
            }
        }
    }

    int rv = ubpf_load(vm, text_copy, sections[text_shndx].size, errmsg);
    free(text_copy);
    return rv;

error:
    free(text_copy);
    return -1;
}
