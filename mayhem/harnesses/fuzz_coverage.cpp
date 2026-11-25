// TinyInst binary coverage file reader (coverage.cpp ReadCoverageBinary, the format litecov /
// tinyinst-coverage write with -coverage_file and read back to merge runs).
// The input is read as two consecutive coverage records from one stream; both are then put
// through the set operations and written back out, as the coverage tools do.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "coverage.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *fp = fmemopen((void *)data, size, "rb");
  if (!fp) return 0;
  Coverage a, b;
  ReadCoverageBinary(a, fp);
  ReadCoverageBinary(b, fp);
  fclose(fp);

  Coverage inter, diff, sym;
  CoverageIntersection(a, b, inter);
  CoverageDifference(a, b, diff);
  CoverageSymmetricDifference(a, b, sym);
  volatile bool contains = CoverageContains(a, b);
  (void)contains;
  MergeCoverage(a, b);

  char *buf = nullptr;
  size_t len = 0;
  FILE *out = open_memstream(&buf, &len);
  if (out) {
    WriteCoverageBinary(a, out);
    WriteCoverageBinary(sym, out);
    fclose(out);
  }
  free(buf);
  return 0;
}
