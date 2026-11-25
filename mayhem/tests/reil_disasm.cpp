// Known-answer tool for mayhem/test.sh: decodes each hex instruction word given on the command line
// with TinyInst's vendored AArch64 decoder (third_party/reil) and prints it, one per line.
//   reil_disasm <hexword> ...
#include <stdint.h>
#include <stdlib.h>
#include <iostream>

#include "reil/aarch64/decoder.h"

int main(int argc, char **argv) {
  uint64_t address = 0x1000;
  for (int i = 1; i < argc; i++, address += 4) {
    uint32_t word = (uint32_t)strtoul(argv[i], nullptr, 16);
    std::cout << reil::aarch64::decoder::DecodeInstruction(address, word) << "\n";
  }
  return 0;
}
