// Known-answer tests for the TinyInst code the fuzz targets reach: coverage file round trip and
// set operations (coverage.cpp), option parsing and argv escaping (common.cpp), and the
// /proc/<pid>/maps parser (Linux/procmaps.cpp) and the dyld cache .map parser (argv[1]). Prints one "PASS <name>" / "FAIL <name>" line
// per check; mayhem/test.sh counts them. (The ELF reader is checked by test.sh through the
// elffile tool.)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <list>
#include <string>
#include <vector>

#include "common.h"
#include "coverage.h"
#include "Linux/procmaps.h"
#include "macOS/dyld_cache_map_parser.h"

static int failures = 0;
static void check(const char *name, bool ok) {
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok) failures++;
}

static Coverage make(std::vector<std::pair<std::string, std::vector<uint64_t>>> mods) {
  Coverage c;
  for (auto &m : mods) {
    std::set<uint64_t> s(m.second.begin(), m.second.end());
    c.push_back(ModuleCoverage(m.first, s));
  }
  return c;
}

static std::set<uint64_t> offs(Coverage &c, const char *name) {
  std::string n(name);
  ModuleCoverage *m = GetModuleCoverage(c, n);
  return m ? m->offsets : std::set<uint64_t>();
}

int main(int argc_main, char **argv_main) {
  // --- coverage ---
  Coverage a = make({{"libc", {1, 2, 3}}, {"target", {0x1000}}});
  Coverage b = make({{"target", {0x1000, 0x2000}}, {"libm", {7}}});

  char *buf = nullptr; size_t len = 0;
  FILE *out = open_memstream(&buf, &len);
  WriteCoverageBinary(a, out);
  fclose(out);
  check("coverage_binary_size", len == 8 + (8 + 4 + 8 + 24) + (8 + 6 + 8 + 8));
  FILE *in = fmemopen(buf, len, "rb");
  Coverage r;
  ReadCoverageBinary(r, in);
  fclose(in);
  free(buf);
  check("coverage_roundtrip_modules", r.size() == 2);
  check("coverage_roundtrip_offsets", offs(r, "libc") == std::set<uint64_t>({1, 2, 3}) &&
                                      offs(r, "target") == std::set<uint64_t>({0x1000}));

  Coverage inter; CoverageIntersection(a, b, inter);
  check("coverage_intersection", inter.size() == 1 && offs(inter, "target") == std::set<uint64_t>({0x1000}));
  Coverage diff; CoverageDifference(a, b, diff);
  check("coverage_difference", offs(diff, "target") == std::set<uint64_t>({0x2000}) &&
                               offs(diff, "libm") == std::set<uint64_t>({7}) && offs(diff, "libc").empty());
  Coverage sym; CoverageSymmetricDifference(a, b, sym);
  check("coverage_symdiff", offs(sym, "libc").size() == 3 && offs(sym, "target") == std::set<uint64_t>({0x2000}) &&
                            offs(sym, "libm").size() == 1);
  check("coverage_contains_false", !CoverageContains(a, b));
  Coverage m = a; MergeCoverage(m, b);
  check("coverage_merge", offs(m, "target") == std::set<uint64_t>({0x1000, 0x2000}) && m.size() == 3);
  check("coverage_contains_true", CoverageContains(m, b));

  // --- options ---
  const char *cargv[] = {"litecov", "-instrument_module", "libfoo.so", "-instrument_module=libbar.so",
                         "-persist", "-iterations", "0x10", "-loop=off", "-coverage_file=c.bin",
                         "--", "/bin/prog", "-target_module", "x", "a b", "q\"u", nullptr};
  char **argv = (char **)cargv;
  int argc = 15;
  char *v = GetOption("-coverage_file", argc, argv);
  check("option_equals", v && strcmp(v, "c.bin") == 0);
  v = GetOption("-instrument_module", argc, argv);
  check("option_separate", v && strcmp(v, "libfoo.so") == 0);
  check("option_stops_at_dashdash", GetOption("-target_module", argc, argv) == nullptr);
  std::list<char *> all;
  GetOptionAll("-instrument_module", argc, argv, &all);
  check("option_all", all.size() == 2 && strcmp(all.front(), "libfoo.so") == 0 &&
                      strcmp(all.back(), "libbar.so") == 0);
  check("option_int_hex", GetIntOption("-iterations", argc, argv, 5) == 16);
  check("option_int_default", GetIntOption("-nargs", argc, argv, 5) == 5);
  check("option_bool_flag", GetBinaryOption("-persist", argc, argv, false) == true);
  check("option_bool_off", GetBinaryOption("-loop", argc, argv, true) == false);
  check("option_bool_default", GetBinaryOption("-cmp_coverage", argc, argv, true) == true);
  char *cmd = ArgvToCmd(5, argv + 10);
  check("argv_to_cmd", cmd && strcmp(cmd, "/bin/prog -target_module x a\\ b q\\\"u") == 0);
  if (cmd) printf("     cmd: %s\n", cmd);
  free(cmd);

  // --- /proc/<pid>/maps ---
  MapsParser p;
  std::vector<std::string> parts;
  char line[] = "55e4c1a00000-55e4c1a02000 r-xp 00000000 08:01 1234   /usr/bin/my prog\n";
  p.SplitLine(line, parts);
  check("maps_splitline", parts.size() == 6 && parts[0] == "55e4c1a00000-55e4c1a02000" &&
                          parts[1] == "r-xp" && parts[5] == "/usr/bin/my prog");
  std::vector<MapsEntry> entries;
  p.Parse(getpid(), entries);
  bool found_exec = false;
  char self[4096];
  ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
  if (n > 0) self[n] = 0;
  for (auto &e : entries) {
    if (n > 0 && e.name == self && e.IsExecutable() && e.addr_to > e.addr_from) found_exec = true;
  }
  check("maps_parse_self", found_exec);

  // --- dyld shared cache .map ---
  if (argc_main > 1) {
    auto g = parse_dyld_map_file(argv_main[1]);
    using V = std::vector<std::string>;
    check("dyld_map_groups", g.size() == 4 && g["libobjc.A.dylib"] == V({"libobjc.A.dylib"}) &&
                             g["libalpha.dylib"] == V({"libalpha.dylib", "libbeta.dylib"}) &&
                             g["libbeta.dylib"] == V({"libalpha.dylib", "libbeta.dylib"}) &&
                             g["libgamma.dylib"] == V({"libgamma.dylib"}));
  } else {
    check("dyld_map_groups", false);
  }

  return failures ? 1 : 0;
}
