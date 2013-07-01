/* gcc elf_stuff.c get_opcodes.c -o get_opcodes */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "elf_stuff.h"

struct {
    int flat_binary;
    char *function, *format;
} options = {0, "_start", "C"};

void usage(char *argv0)
{
    fprintf(stderr, "USAGE: %s <options> <file>\n", argv0);
    fprintf(stderr, "   Available options are:\n");
    fprintf(stderr, "   -f              -file is a flat binary file\n");
    fprintf(stderr, "   -F function     -print opcodes for a spesific function (default _start)\n");
    fprintf(stderr, "   -s format       -output format (C (default), python, hexdump or raw)\n");
}

/* returns the elf filename */
char *parse_args(int argc, char **argv)
{
    int opt;

    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }

    while ((opt = getopt(argc, argv, "fF:s:")) != -1) {
        switch (opt) {
            case 'f':
                options.flat_binary = 1;
                break;
            case 'F':
                options.function = optarg;
                break;
            case 's':
                options.format = optarg;
                break;
            default:
                usage(argv[0]);
                exit(1);
        }
    }

    return argv[optind];
}

void print_opcodes_raw(char *bytes, int size)
{
    int i;
    unsigned char *ptr = (unsigned char *)bytes;

    for (i = 0; i < size; ++i)
        putc(ptr[i], stdout);
}

void print_opcodes_hex(char *bytes, int size)
{
    int i;
    unsigned char *ptr = (unsigned char *)bytes;

    for (i = 0; i < size; ++i) {
        printf("%02x ", ptr[i]);
        if (!((i + 1) % 16) && i + 1 < size)
            printf("\n");
    }
    if (!(i % 16))
        printf("\n");
}

void print_opcodes_py(char *bytes, int size)
{
    int i;
    unsigned char *ptr = (unsigned char *)bytes;

    printf("shellcode =  \"");

    for (i = 0; i < size; ++i) {
        printf("\\x%02x", ptr[i]);
        if (!((i + 1) % 16) && i + 1 < size)
            printf("\"\nshellcode += \"");
    }
    printf("\"\n");
}

void print_opcodes_C(char *bytes, int size)
{
    int i;
    unsigned char *ptr = (unsigned char *)bytes;

    printf("char shellcode[] =\n\"");
    for (i = 0; i < size; ++i) {
        printf("\\x%02x", ptr[i]);
        if (!((i + 1) % 16) && i + 1 < size)
            printf("\"\n\"");
    }
    printf("\";\n");
}

char *read_flat_binary(char *file, int *size)
{
    char *ret;
    FILE *fp;
    struct stat info;


    if ((fp = fopen(file, "r")) == NULL)
        return NULL;

    fstat(fileno(fp), &info);
    ret = malloc(info.st_size);

    fread(ret, info.st_size, 1, fp);
    fclose(fp);

    *size = info.st_size;
    return ret;
}

void *get_bytes(struct elf_handle *h, char *symbol, int *size)
{
    int count;
    void *ret;
    void *main_hdr = h->main_header;
    void *sym = elf_get_symbol_entry(h, symbol);
    void *sect = elf_get_section_entry(h, ".text");

    if (sym == NULL)
        return NULL;

    if (elf_class(main_hdr) == ELFCLASS32) {
        fseek(h->fp, E32_SHDR(sect)->sh_offset, SEEK_SET);
        if (E32_SYM(sym)->st_size != 0) {
            fseek(h->fp, E32_SYM(sym)->st_value -
                    E32_EHDR(h->main_header)->e_entry, SEEK_CUR);
            count = E32_SYM(sym)->st_size;
        } else {
            fprintf(stderr, "Apparently %s is 0 bytes. Using .text instead\n", symbol);
            count = E32_SHDR(sect)->sh_size;
        }
    } else {
        fseek(h->fp, E64_SHDR(sect)->sh_offset, SEEK_SET);
        if (E64_SYM(sym)->st_size != 0) {
            fseek(h->fp, E64_SYM(sym)->st_value -
                    E64_EHDR(h->main_header)->e_entry, SEEK_CUR);
            count = E64_SYM(sym)->st_size;
        } else {
            fprintf(stderr, "Apparently %s is 0 bytes. Using .text instead\n", symbol);
            count = E64_SHDR(sect)->sh_size;
        }
    }

    *size = count;
    ret = malloc(count);
    fread(ret, count, 1, h->fp);

    return ret;
}

int main(int argc, char *argv[])
{
    struct elf_handle *handle;
    char *file, *bytes;
    int size;

    file = parse_args(argc, argv);

    if (!options.flat_binary) {
        if ((handle = elf_init(file)) == NULL) {
            fprintf(stderr, "Failed to initialize elf file %s: %s\n", file, strerror(errno));
            return 1;
        }
        bytes = get_bytes(handle, options.function, &size);

        elf_free(handle);
    } else
        bytes = read_flat_binary(file, &size);

    fprintf(stderr, "Printing shellcode (%d bytes)\n", size);
    if (!strcasecmp(options.format, "python"))
        print_opcodes_py(bytes, size);
    else if (!strcasecmp(options.format, "hexdump"))
        print_opcodes_hex(bytes, size);
    else if (!strcasecmp(options.format, "raw"))
        print_opcodes_raw(bytes, size);
    else
        print_opcodes_C(bytes, size);
    fflush(stdout);

    free(bytes);

    return 0;
}
