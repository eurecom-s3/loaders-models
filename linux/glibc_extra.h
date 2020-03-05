typedef uint32_t Elf32_Word;
typedef struct elf32_note {
    Elf32_Word namesz;
    Elf32_Word descsz;
    Elf32_Word type;
    char name[4];
    Elf32_Word desc[40];
} Elf32_Note;
