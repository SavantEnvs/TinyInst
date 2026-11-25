#!/usr/bin/env bash
#
# mayhem/build.sh — build TinyInst's fuzz targets and the known-answer test tools.
#
# The targets reach TinyInst's byte parsers: the ELF reader (Linux/elffile.cpp), the binary
# coverage file reader (coverage.cpp), option/argv handling (common.cpp), the /proc maps
# tokenizer (Linux/procmaps.cpp) and the dyld shared cache .map parser
# (macOS/dyld_cache_map_parser.cpp, portable C++ that CMake only builds on Apple) and the vendored
# AArch64 instruction decoder/printer (third_party/reil) the arm64 build runs on target code. Those sources do not depend on XED or on the rest of
# libtinyinst (the debugger/instrumentation, which needs a live traced process), so they are
# compiled directly here with the sanitizer flags instead of through CMake, which would also
# build XED from the third_party submodules.
#
# Outputs: /mayhem/fuzz_{coverage,options,procmaps,dyld_map,reil_aarch64}[-standalone] (libFuzzer), /mayhem/elffile_afl
# (AFL file-input target) and, built with normal flags for mayhem/test.sh,
# /mayhem/build/mayhem-test/{elffile,selftest,reil_disasm}. Intermediate objects go under build/ (gitignored).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

LIB_SRCS=(common.cpp coverage.cpp Linux/elffile.cpp Linux/procmaps.cpp macOS/dyld_cache_map_parser.cpp)
# The vendored AArch64 decoder TinyInst's arm64 build links (CMake target `reil`).
REIL_SRCS=(third_party/reil/reil/aarch64/decoder.cpp third_party/reil/reil/aarch64/printer.cpp)
CXXSTD=(-std=c++17 -I"$SRC" -I"$SRC/third_party/reil")
B="$SRC/build/mayhem"
mkdir -p "$B/fuzz" "$B/afl" "$B/test" "$SRC/build/mayhem-test"

# compile_lib <compiler> <outdir> <flags...>: objects for LIB_SRCS (or $SRCS_VAR's list, e.g. REIL_SRCS)
compile_lib() {
  local cxx="$1" outdir="$2"; shift 2
  local objs=()
  local -n srcs="${SRCS_VAR:-LIB_SRCS}"
  for s in "${srcs[@]}"; do
    local o="$outdir/$(echo "$s" | tr '/' '_').o"
    "$cxx" "${CXXSTD[@]}" "$@" -c "$SRC/$s" -o "$o"
    objs+=("$o")
  done
  printf '%s\n' "${objs[@]}"
}

# 1) libFuzzer targets: the TinyInst sources themselves are compiled with the sanitizers.
#    DEBUG_FLAGS comes after SANITIZER_FLAGS so -gdwarf-3 wins over the base's -g.
FUZZ_FLAGS=($SANITIZER_FLAGS $DEBUG_FLAGS -O1)
mapfile -t FUZZ_OBJS < <(compile_lib "$CXX" "$B/fuzz" "${FUZZ_FLAGS[@]}" -fsanitize=fuzzer-no-link)
$CXX "${FUZZ_FLAGS[@]}" -c "$SRC/mayhem/lsan_off.cc" -o "$B/fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"
for t in fuzz_coverage fuzz_options fuzz_procmaps fuzz_dyld_map; do
  $CXX "${CXXSTD[@]}" "${FUZZ_FLAGS[@]}" -fsanitize=fuzzer-no-link -c "$SRC/mayhem/harnesses/$t.cpp" -o "$B/fuzz/$t.o"
  $CXX "${FUZZ_FLAGS[@]}" $LIB_FUZZING_ENGINE "$B/fuzz/$t.o" "${FUZZ_OBJS[@]}" "$B/fuzz/lsan_off.o" \
    -o "$SRC/$t"
  $CXX "${FUZZ_FLAGS[@]}" "$B/fuzz/standalone_main.o" "$B/fuzz/$t.o" "${FUZZ_OBJS[@]}" "$B/fuzz/lsan_off.o" \
    -o "$SRC/$t-standalone"
done
# AArch64 decoder target (third_party/reil, instrumented like the rest).
mapfile -t REIL_FUZZ_OBJS < <(SRCS_VAR=REIL_SRCS compile_lib "$CXX" "$B/fuzz" "${FUZZ_FLAGS[@]}" -fsanitize=fuzzer-no-link)
t=fuzz_reil_aarch64
$CXX "${CXXSTD[@]}" "${FUZZ_FLAGS[@]}" -fsanitize=fuzzer-no-link -c "$SRC/mayhem/harnesses/$t.cpp" -o "$B/fuzz/$t.o"
$CXX "${FUZZ_FLAGS[@]}" $LIB_FUZZING_ENGINE "$B/fuzz/$t.o" "${REIL_FUZZ_OBJS[@]}" "$B/fuzz/lsan_off.o" -o "$SRC/$t"
$CXX "${FUZZ_FLAGS[@]}" "$B/fuzz/standalone_main.o" "$B/fuzz/$t.o" "${REIL_FUZZ_OBJS[@]}" "$B/fuzz/lsan_off.o" \
  -o "$SRC/$t-standalone"

# 2) AFL file-input target for the ELF reader (it exit()s on malformed input, so it runs as a
#    whole process per input). Its own reproducer outside afl-fuzz, so no -standalone.
AFL_CXX=afl-clang-fast++
mapfile -t AFL_OBJS < <(AFL_QUIET=1 compile_lib "$AFL_CXX" "$B/afl" $SANITIZER_FLAGS $DEBUG_FLAGS -O1)
AFL_QUIET=1 $AFL_CXX "${CXXSTD[@]}" $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -c "$SRC/mayhem/lsan_off.cc" -o "$B/afl/lsan_off.o"
AFL_QUIET=1 $AFL_CXX "${CXXSTD[@]}" $SANITIZER_FLAGS $DEBUG_FLAGS -O1 \
  "$SRC/mayhem/harnesses/elffile_main.cpp" "${AFL_OBJS[@]}" "$B/afl/lsan_off.o" -o "$SRC/elffile_afl"

# 3) Test tools with normal flags (no sanitizers) for mayhem/test.sh.
TEST_FLAGS=(-O2 $COVERAGE_FLAGS)
mapfile -t TEST_OBJS < <(compile_lib "$CXX" "$B/test" "${TEST_FLAGS[@]}")
$CXX "${CXXSTD[@]}" "${TEST_FLAGS[@]}" "$SRC/mayhem/harnesses/elffile_main.cpp" "${TEST_OBJS[@]}" \
  -o "$SRC/build/mayhem-test/elffile"
$CXX "${CXXSTD[@]}" "${TEST_FLAGS[@]}" "$SRC/mayhem/tests/selftest.cpp" "${TEST_OBJS[@]}" \
  -o "$SRC/build/mayhem-test/selftest"
mapfile -t REIL_TEST_OBJS < <(SRCS_VAR=REIL_SRCS compile_lib "$CXX" "$B/test" "${TEST_FLAGS[@]}")
$CXX "${CXXSTD[@]}" "${TEST_FLAGS[@]}" "$SRC/mayhem/tests/reil_disasm.cpp" "${REIL_TEST_OBJS[@]}" \
  -o "$SRC/build/mayhem-test/reil_disasm"

echo "build.sh: done"
