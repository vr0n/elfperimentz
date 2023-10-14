#define EI_NIDENT    16 // Byte length of the ELF magic
#define EHDR_32_SIZE 52
#define EHDR_64_SIZE 64
#define EHDR_SIZE    64 // Assume 64-bit for now

typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned short Elf64_Half;      // 2 bytes
typedef signed short Elf64_SHalf;       // 2 bytes
typedef unsigned long long Elf64_Off;   // 8 bytes
typedef unsigned int Elf64_Word;        // 4 bytes
typedef signed int Elf64_SWord;         // 4 bytes
typedef unsigned long long Elf64_Xword; // 8 bytes
typedef signed long long Elf64_SXword;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes
typedef unsigned long long Elf64_Addr;  // 8 bytes

typedef struct {
  unsigned char e_ident[EI_NIDENT]; // 16 bytes: To capture the ELF magic
  Elf64_Half e_type;      // 2 bytes: Object file type
  Elf64_Half e_machine;   // 2 bytes: Machine type
  Elf64_Word e_version;   // 4 bytes: Object file version
  Elf64_Addr e_entry;     // 8 bytes: Entry point address
  Elf64_Off e_phoff;      // 8 bytes: Program header offset
  Elf64_Off e_shoff;      // 8 bytes: Section header offset
  Elf64_Word e_flags;     // 4 bytes: Processor specific flags
  Elf64_Half e_ehsize;    // 2 bytes: Elf header size
  Elf64_Half e_phentsize; // 2 bytes: Size of program header entry
  Elf64_Half e_phnum;     // 2 bytes: Number of program header entries
  Elf64_Half e_shentsize; // 2 bytes: Size of section header entry
  Elf64_Half e_shnum;     // 2 bytes: Number of section header entries
  Elf64_Half e_shstrndx;  // 2 bytes: Section name string table index
} Elf64_Ehdr; // 64 bytes

typedef struct {
  Elf64_Word p_type;    // 4 bytes: Segment type
  Elf64_Word p_flags;   // 4 bytes: Segment flags
  Elf64_Off p_offset;   // 8 bytes: Offset of this segment from start of file
  Elf64_Addr p_vaddr;   // 8 bytes: Address in memory
  Elf64_Addr p_paddr;   // 8 bytes: For physical addressing systems
  Elf64_Xword p_filesz; // 8 bytes: File image size of this segment
  Elf64_Xword p_memsz;  // 8 bytes: Memory image size of this segment
  Elf64_Xword p_align;  // 8 bytes: Alginment constraint of this segment
} Elf64_Phdr; // 56 bytes

typedef struct {
} Elf64_Shdr;

typedef struct {
} Elf64_Sec;

typedef struct {
} Elf64_Seg;

typedef struct Elf_File {
  FILE  *binary; // Pointer to FILE that is our open ELF binary
  Elf64_Ehdr elf_header; // 64 bytes: Header
  Elf64_Phdr prog_headers[13]; // 56 bytes each: Array of program headers
} Elf_File;

typedef struct elf_bin {
  Elf64_Ehdr* hdr;
  unsigned int phdr_num;
  Elf64_Phdr* phdr;
  unsigned int shdr_num;
  Elf64_Shdr* shdr;
  unsigned int sec_num;
  Elf64_Sec* sec;
  unsigned int seg_num;
  Elf64_Seg* seg;
  unsigned long size;
  unsigned long perms;
  char* perms_chr;
} elf_bin_t;

char* map_phdr_types(unsigned int);
char* map_perms(unsigned int);
void print_elf_header(Elf64_Ehdr*);
unsigned long long parse_elf_header(FILE*, Elf64_Ehdr*);
void print_program_header(Elf64_Phdr*);
void parse_program_header(FILE*, Elf64_Phdr*);
void parse_section_headers(unsigned char*, elf_bin_t*);
void parse_program_headers(unsigned char*, elf_bin_t*);
void parse_header(unsigned char*, elf_bin_t*);
void parse_sections(unsigned char*, elf_bin_t*);
void parse_elf(unsigned char*, elf_bin_t*);
void describe_elf(elf_bin_t*);
