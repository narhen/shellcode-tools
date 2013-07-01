#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>

#include "elf_stuff.h"

inline int elf_class(struct elf_handle *h)
{
    char *ptr = (char *)h;

    return ptr[EI_CLASS];
}

struct elf_handle *elf_init(char *file)
{
    char buffer[EI_NIDENT];
    struct elf_handle *ret;

    if (!(ret = calloc(1, sizeof(struct elf_handle))))
        return NULL;

    if (!(ret->fp = fopen(file, "r")))
        return NULL;

    fread(buffer, sizeof buffer, 1, ret->fp);
    fseek(ret->fp, 0, SEEK_SET);

    if (buffer[EI_CLASS] == ELFCLASS32) {
        Elf32_Shdr *stmp;

        /* read main elf header */
        ret->main_header = calloc(1, sizeof(Elf32_Ehdr));
        fread(ret->main_header, sizeof(Elf32_Ehdr), 1, ret->fp);

        /* read section headers */
        int tmp = E32_EHDR(ret->main_header)->e_shentsize * E32_EHDR(ret->main_header)->e_shnum;
        ret->section_headers = calloc(1, tmp);
        fseek(ret->fp, E32_EHDR(ret->main_header)->e_shoff, SEEK_SET);
        fread(ret->section_headers, tmp, 1, ret->fp);

        /* read shstrtab */
        stmp = &E32_SHDR(ret->section_headers)[E32_EHDR(ret->main_header)->e_shstrndx];
        ret->shstrtab = calloc(1, stmp->sh_size);
        fseek(ret->fp, stmp->sh_offset, SEEK_SET);
        fread(ret->shstrtab, stmp->sh_size, 1, ret->fp);

        /* read strtab */
        stmp = elf_get_section_entry(ret, ".strtab");
        ret->strtab = calloc(1, stmp->sh_size);
        fseek(ret->fp, stmp->sh_offset, SEEK_SET);
        fread(ret->strtab, stmp->sh_size, 1, ret->fp);

        /* read symbol table */
        stmp = elf_get_section_entry(ret, ".symtab");
        ret->symtable = calloc(1, stmp->sh_size);
        fseek(ret->fp, stmp->sh_offset, SEEK_SET);
        fread(ret->symtable, stmp->sh_size, 1, ret->fp);
    } else if (buffer[EI_CLASS] == ELFCLASS64) {
        Elf64_Shdr *stmp;

        /* read main header */
        ret->main_header = calloc(1, sizeof(Elf64_Ehdr));
        fread(ret->main_header, sizeof(Elf64_Ehdr), 1, ret->fp);

        int tmp = E64_EHDR(ret->main_header)->e_shentsize * E64_EHDR(ret->main_header)->e_shnum;
        /* read section haders */
        ret->section_headers = calloc(1, tmp);
        fseek(ret->fp, E64_EHDR(ret->main_header)->e_shoff, SEEK_SET);
        fread(ret->section_headers, tmp, 1, ret->fp);

        /* read shstrtab */
        stmp = &E64_SHDR(ret->section_headers)[E64_EHDR(ret->main_header)->e_shstrndx];
        ret->shstrtab = calloc(1, stmp->sh_size);
        fseek(ret->fp, stmp->sh_offset, SEEK_SET);
        fread(ret->shstrtab, stmp->sh_size, 1, ret->fp);

        /* read strtab */
        stmp = elf_get_section_entry(ret, ".strtab");
        ret->strtab = calloc(1, stmp->sh_size);
        fseek(ret->fp, stmp->sh_offset, SEEK_SET);
        fread(ret->strtab, stmp->sh_size, 1, ret->fp);

        /* read symbol table */
        stmp = elf_get_section_entry(ret, ".symtab");
        ret->symtable = calloc(1, stmp->sh_size);
        fseek(ret->fp, stmp->sh_offset, SEEK_SET);
        fread(ret->symtable, stmp->sh_size, 1, ret->fp);
    }

    return ret;
}

void *elf_get_section_entry(struct elf_handle *h, char *id)
{
    int i;
    if (elf_class(h->main_header) == ELFCLASS32) {
        Elf32_Ehdr *hdr = h->main_header;;
        Elf32_Shdr *shdr = h->section_headers;

        for (i = 0; i < hdr->e_shnum; ++i, ++shdr)
            if (!strcmp(h->shstrtab + shdr->sh_name, id))
                return shdr;
    } else {
        Elf64_Ehdr *hdr = h->main_header;;
        Elf64_Shdr *shdr = h->section_headers;

        for (i = 0; i < hdr->e_shnum; ++i, ++shdr)
            if (!strcmp(h->shstrtab + shdr->sh_name, id))
                return shdr;
    }
    return NULL;
}

void *elf_get_symbol_entry(struct elf_handle *h, char *id)
{
    int i;
    if (elf_class(h->main_header) == ELFCLASS32) {
        Elf32_Sym *sym = h->symtable;
        Elf32_Shdr *shdr = elf_get_section_entry(h, ".symtab");

        for (i = 0; i < shdr->sh_size / shdr->sh_entsize; ++i, ++sym)
            if (!strcmp(h->strtab + sym->st_name, id))
                return sym;
    } else {
        Elf64_Sym *sym = h->symtable;
        Elf64_Shdr *shdr = elf_get_section_entry(h, ".symtab");

        for (i = 0; i < shdr->sh_size / shdr->sh_entsize; ++i, ++sym)
            if (!strcmp(h->strtab + sym->st_name, id))
                return sym;

    }
    return NULL;
}

inline void *elf_get_main_header(struct elf_handle *h)
{
    return h->main_header;
}

inline void *elf_get_section_headers(struct elf_handle *h)
{
    return h->section_headers;
}

inline void *elf_get_symbol_table(struct elf_handle *h)
{
    return h->symtable;
}

inline char *elf_get_shstrtab_name(struct elf_handle *h, int index)
{
    return h->shstrtab + index;
}

inline char *elf_get_strtab_name(struct elf_handle *h, int index)
{
    return h->strtab + index;
}

void elf_free(struct elf_handle *h)
{
    fclose(h->fp);
    free(h->main_header);
    free(h->section_headers);
    free(h->symtable);
    free(h->shstrtab);
    free(h->strtab);
}
