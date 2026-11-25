#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# TinyInst ships no test suite upstream; these are known-answer checks over the code the fuzz targets
# reach, run on the tools build.sh built with normal flags (build/mayhem-test/).
T="$SRC/build/mayhem-test"
for b in selftest elffile reil_disasm; do
  [ -x "$T/$b" ] || { echo "missing $T/$b — run mayhem/build.sh" >&2; emit_ctrf tinyinst-selftest 0 1; exit 1; }
done

passed=0; failed=0
ok()   { echo "PASS $1"; passed=$((passed+1)); }
bad()  { echo "FAIL $1${2:+: $2}"; failed=$((failed+1)); }

# 1) selftest: coverage, options, argv escaping, /proc maps, dyld cache .map. It prints one PASS/FAIL line per check.
SELFTEST_CHECKS=22
out="$("$T/selftest" "$SRC/mayhem/fuzz-dyld-map/testsuite/cache.map" 2>&1)"; echo "$out"
p=$(grep -c '^PASS ' <<<"$out" || true); f=$(grep -c '^FAIL ' <<<"$out" || true)
passed=$((passed+p)); failed=$((failed+f))
[ $((p+f)) -eq $SELFTEST_CHECKS ] || bad selftest_count "expected $SELFTEST_CHECKS checks, got $((p+f))"

# 2) ELF reader: golden answers on the committed seeds ...
S="$SRC/mayhem/elffile-afl/testsuite"
expect_elf() {  # <name> <file> <expected output> [symbols...]
  local name="$1" file="$2" want="$3"; shift 3
  local got; got="$("$T/elffile" "$file" "$@" 2>&1)"
  if [ "$got" = "$want" ]; then ok "$name"; else bad "$name" "got '$got'"; fi
}
expect_elf elf64_exec_symtab "$S/exec64.elf" $'pie=0\nmain=0x401136\nfoo=0x401000\nnope=0x0' main foo nope
expect_elf elf64_pie_dynsym  "$S/pie64_dynsym.elf" $'pie=1\nmain=0x1139\nbar=0x2000' main bar
expect_elf elf32_exec_symtab "$S/exec32.elf" $'pie=0\nmain=0x8049176\nbaz=0x8049000' main baz
expect_elf elf32_pie         "$S/pie32.elf" $'pie=1\nmain=0x11ad'
# ... and cross-checked against binutils on real binaries built by build.sh.
for bin in "$T/selftest" "$T/elffile"; do
  want_main="0x$(nm "$bin" | awk '$3=="main"{sub(/^0+/,"",$1); print $1; exit}')"
  want_pie=$(readelf -h "$bin" | grep -q 'DYN' && echo 1 || echo 0)
  expect_elf "elf_real_$(basename "$bin")" "$bin" "pie=$want_pie"$'\n'"main=$want_main"
done
# Malformed input is rejected with exit(1) and the FATAL message.
got="$(printf 'NOTELF' > /tmp/tinyinst-notelf.$$; "$T/elffile" /tmp/tinyinst-notelf.$$; echo "rc=$?")"; rm -f /tmp/tinyinst-notelf.$$
if grep -q 'Elf header expected' <<<"$got" && grep -q 'rc=1' <<<"$got"; then ok elf_reject_bad_magic; else bad elf_reject_bad_magic "$got"; fi

# 3) AArch64 decoder (third_party/reil): golden disassembly of known instruction words.
expect_reil() {  # <name> <expected> <hexword>
  local got; got="$("$T/reil_disasm" "$3" 2>&1)"
  if [ "$got" = "$2" ]; then ok "reil_$1"; else bad "reil_$1" "got '$got'"; fi
}
expect_reil ret      'ret'                            d65f03c0
expect_reil stp_pre  'stp x29, x30, [sp, #-0x10]!'    a9bf7bfd
expect_reil mov_sp   'mov x29, sp'                    910003fd
expect_reil bl       'bl #0x1040'                     94000010
expect_reil ldr      'ldr w1, [x1, #0x8]'             b9400821
expect_reil cbz      'cbz x0, #0x1008'                b4000040
expect_reil movz     'mov w0, #0x2a'                  52800540
expect_reil add      'add x0, x1, x2'                 8b020020
expect_reil sdiv     'sdiv x0, x0, x1'                9ac10c00
expect_reil b_cond   'b.eq #0x1008'                   54000040
expect_reil ldxr     'ldxr x0, [x1]'                  c85f7c20
expect_reil svc      'svc #0'                         d4000001
expect_reil invalid  'invalid'                        00000000

emit_ctrf "tinyinst-selftest" "$passed" "$failed" 0
