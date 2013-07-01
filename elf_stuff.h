#ifndef __ELF_STUFF_H /* start of include guard */
#define __ELF_STUFF_H

#define E32_EHDR(ptr) ((Elf32_Ehdr *)(ptr))
#define E64_EHDR(ptr) ((Elf64_Ehdr *)(ptr))

#define E32_SHDR(ptr) ((Elf32_Shdr *)(ptr))
#define E64_SHDR(ptr) ((Elf64_Shdr *)(ptr))

#define E32_SYM(ptr) ((Elf32_Sym *)(ptr))
#define E64_SYM(ptr) ((Elf64_Sym *)(ptr))

struct elf_handle {
    FILE *fp;
    void *main_header;
    void *section_headers;
    void *symtable;
    char *shstrtab, *strtab;
};

extern inline int elf_class(struct elf_handle *h);
extern struct elf_handle *elf_init(char *file);
extern void *elf_get_section_entry(struct elf_handle *h, char *id);
extern void *elf_get_symbol_entry(struct elf_handle *h, char *id);
extern void elf_free(struct elf_handle *h);

#endif /* end of include guard: __ELF_STUFF_H */
