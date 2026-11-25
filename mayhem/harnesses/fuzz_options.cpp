// TinyInst command-line handling (common.cpp): option lookup used by every TinyInst tool and
// ArgvToCmd, which escapes and joins the target's argv into the command line it launches.
// The input is split on NUL bytes into argv.
#include <stdint.h>
#include <stdlib.h>
#include <list>
#include <string>
#include <vector>

#include "common.h"

static const char *kOptions[] = {
  "-instrument_module", "-target_module", "-target_method", "-coverage_file",
  "-persist", "-loop", "-iterations", "-nargs", "-cmp_coverage", "-generate_unwind",
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::vector<std::string> args(1);
  for (size_t i = 0; i < size; i++) {
    if (data[i] == 0) {
      if (args.size() >= 256) break;
      args.emplace_back();
    } else {
      args.back().push_back((char)data[i]);
    }
  }
  std::vector<char *> argv;
  for (auto &a : args) argv.push_back(&a[0]);
  int argc = (int)argv.size();  // >= 1, as for every tool (ArgvToCmd FATALs on argc == 0)
  argv.push_back(nullptr);

  volatile uintptr_t sink = 0;
  for (const char *name : kOptions) {
    char *v = GetOption(name, argc, argv.data());
    sink += (uintptr_t)v;
    sink += GetBinaryOption(name, argc, argv.data(), false);
    sink += GetIntOption(name, argc, argv.data(), 0);
    std::list<char *> all;
    GetOptionAll(name, argc, argv.data(), &all);
    sink += all.size();
  }
  // The tools pass the target's argv (everything after "--") to ArgvToCmd.
  int start = 0;
  for (int i = 0; i < argc; i++) {
    if (args[i] == "--") { start = i + 1; break; }
  }
  if (start >= argc) start = 0;
  char *cmd = ArgvToCmd(argc - start, argv.data() + start);
  free(cmd);
  return 0;
}
