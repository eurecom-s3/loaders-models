typedef struct pe_image_file_hdr {
    uint32_t Magic;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} pe_image_file_hdr;




typedef struct pe_image_data_dir {
    uint32_t VirtualAddress;
    uint32_t Size;
} pe_image_data_dir;




typedef struct pe_image_optional_hdr32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;

} pe_image_optional_hdr32;




typedef struct pe_image_optional_hdr64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;

}pe_image_optional_hdr64;




typedef struct pe_image_section_hdr {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} pe_image_section_hdr;

typedef struct
{
  uint16_t magic;
  uint16_t cblp;
  uint16_t cp;
  uint16_t crlc;
  uint16_t cparhdr;
  uint16_t minalloc;
  uint16_t maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t lfarlc;
  uint16_t ovno;
  uint16_t res[4];
  uint16_t oemid;
  uint16_t oeminfo;
  uint16_t res2[10];
  int e_lfanew;
} DOSHeader;

struct pe_certificate_hdr {
    uint32_t length;
    uint16_t revision;
    uint16_t type;
};
struct cli_exe_section {
    uint32_t rva;
    uint32_t vsz;
    uint32_t raw;
    uint32_t rsz;
    uint32_t chr;
    uint32_t urva;
    uint32_t uvsz;
    uint32_t uraw;
    uint32_t ursz;
};
