// TinyInst's vendored AArch64 decoder (third_party/reil: decoder.cpp + printer.cpp), which the arm64
// build runs on every instruction of the instrumented module (arch/arm64) — i.e. on bytes of the target
// binary. The input is consumed as little-endian 4-byte instruction words; each one is decoded at a
// running address and printed through the decoder's operator<<, as TinyInst's disassembly dumps do.
#include <stdint.h>
#include <string.h>
#include <sstream>

#include "reil/aarch64/decoder.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::ostringstream out;
  uint64_t address = 0x100000;
  for (size_t i = 0; i + 4 <= size; i += 4, address += 4) {
    uint32_t word;
    memcpy(&word, data + i, 4);
    reil::aarch64::decoder::Instruction insn =
        reil::aarch64::decoder::DecodeInstruction(address, word);
    out << insn << "\n";
  }
  return 0;
}
