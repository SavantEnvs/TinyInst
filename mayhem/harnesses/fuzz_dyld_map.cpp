// TinyInst dyld shared cache .map parser (macOS/dyld_cache_map_parser.cpp parse_dyld_map_file),
// which groups the cache's libraries by their __TEXT ranges. The parser is portable C++ (CMake
// only builds it on Apple) and takes a file path, so each input is written to a scratch file.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

#include "macOS/dyld_cache_map_parser.h"

static std::string scratch_path;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  const char *tmp = getenv("TMPDIR");
  std::string tmpl = std::string(tmp && *tmp ? tmp : "/tmp") + "/tinyinst-dyldmap-XXXXXX";
  int fd = mkstemp(&tmpl[0]);
  if (fd < 0) { perror("mkstemp"); abort(); }
  close(fd);
  scratch_path = tmpl;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *fp = fopen(scratch_path.c_str(), "wb");
  if (!fp) abort();
  if (size && fwrite(data, 1, size, fp) != size) abort();
  fclose(fp);
  auto groups = parse_dyld_map_file(scratch_path);
  volatile size_t n = 0;
  for (auto &g : groups) n += g.first.size() + g.second.size();
  (void)n;
  return 0;
}
