typedef struct elf32_note {
    Elf32_Word namesz;
    Elf32_Word descsz;
    Elf32_Word type;
    char name[4];
    Elf32_Word desc[];
} Elf32_Note;  // TODO: hard-coded namesz for GNU\0