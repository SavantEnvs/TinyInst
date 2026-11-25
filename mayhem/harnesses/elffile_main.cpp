// TinyInst ELF reader, file-input (AFL) target and CLI test tool.
//
// Does what Debugger::GetSymbolAddress (Linux/debugger.cpp) does for -target_method and hooks:
// ElfFile::OpenFile on the module's file, then the SHT_SYMTAB / SHT_DYNSYM symbol lookup, plus IsPIE.
// ElfFile reports every malformed read with FATAL() == exit(1), so this is a whole-process
// file-input target (Mayhemfile `afl: true`, input passed as @@), not an in-process libFuzzer one.
//
//   elffile <file> [symbol ...]     (default symbol: main)
#include <stdio.h>
#include <inttypes.h>

#include "common.h"
#include "Linux/elffile.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <elf file> [symbol ...]\n", argv[0]);
    return 2;
  }
  ElfFile elf;
  elf.OpenFile(argv[1]);
  printf("pie=%d\n", elf.IsPIE());
  if (argc == 2) {
    printf("main=0x%" PRIx64 "\n", elf.GetSymbolAddress("main"));
  }
  for (int i = 2; i < argc; i++) {
    printf("%s=0x%" PRIx64 "\n", argv[i], elf.GetSymbolAddress(argv[i]));
  }
  return 0;
}
