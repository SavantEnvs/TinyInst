// TinyInst /proc/<pid>/maps line tokenizer (Linux/procmaps.cpp MapsParser::SplitLine), which the
// Linux debugger runs on every maps line of the traced process. Mapped file names (the last field)
// are chosen by the target. Each input line is tokenized the way MapsParser::Parse does.
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

#include "Linux/procmaps.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // getline() hands SplitLine a NUL-terminated line that ends with its '\n'.
  std::string all((const char *)data, size);
  MapsParser parser;
  size_t pos = 0;
  while (pos < all.size()) {
    size_t nl = all.find('\n', pos);
    size_t end = (nl == std::string::npos) ? all.size() : nl + 1;
    std::vector<char> line(all.begin() + pos, all.begin() + end);
    line.push_back(0);
    std::vector<std::string> parts;
    parser.SplitLine(line.data(), parts);
    pos = end;
  }
  return 0;
}
