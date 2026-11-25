#!/usr/bin/env python3
"""Generate the committed seed files for the TinyInst targets (run by hand; outputs are committed).

  python3 mayhem/tools/gen_seeds.py <mayhem dir>
"""
import os, struct, sys

def elf(cls, etype, syms, dyn=False):
    """Minimal ELF: header, .symtab/.dynsym + .strtab + .shstrtab, section header table at the end."""
    is64 = cls == 2
    strtab = b"\0"
    entries = []
    for name, value in syms:
        off = len(strtab)
        strtab += name.encode() + b"\0"
        entries.append((off, value))
    if is64:
        symfmt = "<IBBHQQ"; symsize = 24
        symtab = b"\0" * symsize + b"".join(struct.pack(symfmt, o, 0x12, 0, 1, v, 0) for o, v in entries)
    else:
        symfmt = "<IIIBBH"; symsize = 16
        symtab = b"\0" * symsize + b"".join(struct.pack(symfmt, o, v, 0, 0x12, 0, 1) for o, v in entries)
    shstr = b"\0.symtab\0.strtab\0.shstrtab\0"
    ehsize = 64 if is64 else 52
    shentsize = 64 if is64 else 40
    body = b""
    off_sym = ehsize; body += symtab
    off_str = ehsize + len(body); body += strtab
    off_shs = ehsize + len(body); body += shstr
    while (ehsize + len(body)) % 8: body += b"\0"
    shoff = ehsize + len(body)
    symtype = 11 if dyn else 2
    def sh(name, typ, off, size, link, entsize, info=0):
        if is64:
            return struct.pack("<IIQQQQIIQQ", name, typ, 0, 0, off, size, link, info, 1, entsize)
        return struct.pack("<IIIIIIIIII", name, typ, 0, 0, off, size, link, info, 1, entsize)
    shdrs = sh(0, 0, 0, 0, 0, 0)
    shdrs += sh(1, symtype, off_sym, len(symtab), 2, symsize, 1)
    shdrs += sh(9, 3, off_str, len(strtab), 0, 0)
    shdrs += sh(17, 3, off_shs, len(shstr), 0, 0)
    ident = b"\x7fELF" + bytes([cls, 1, 1, 0]) + b"\0" * 8
    machine = 62 if is64 else 3
    if is64:
        hdr = ident + struct.pack("<HHIQQQIHHHHHH", etype, machine, 1, 0, 0, shoff, 0, ehsize, 0, 0, shentsize, 4, 3)
    else:
        hdr = ident + struct.pack("<HHIIIIIHHHHHH", etype, machine, 1, 0, 0, shoff, 0, ehsize, 0, 0, shentsize, 4, 3)
    assert len(hdr) == ehsize
    return hdr + body + shdrs

def coverage(mods):
    out = struct.pack("<Q", len(mods))
    for name, offs in mods:
        out += struct.pack("<Q", len(name)) + name.encode()
        out += struct.pack("<Q", len(offs)) + b"".join(struct.pack("<Q", o) for o in sorted(set(offs)))
    return out

def main(root):
    def put(target, name, data):
        d = os.path.join(root, target, "testsuite"); os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "wb") as f: f.write(data)
    put("elffile-afl", "exec64.elf", elf(2, 2, [("foo", 0x401000), ("main", 0x401136)]))
    put("elffile-afl", "pie64_dynsym.elf", elf(2, 3, [("main", 0x1139), ("bar", 0x2000)], dyn=True))
    put("elffile-afl", "exec32.elf", elf(1, 2, [("main", 0x8049176), ("baz", 0x8049000)]))
    put("elffile-afl", "pie32.elf", elf(1, 3, [("x", 1), ("main", 0x11ad)]))
    c1 = coverage([("libc.so.6", [0x10, 0x20, 0x30]), ("target", [0x1000])])
    c2 = coverage([("target", [0x1000, 0x2000]), ("libm.so.6", [0x40])])
    put("fuzz-coverage", "two_covs.bin", c1 + c2)
    put("fuzz-coverage", "one_cov.bin", c1)
    put("fuzz-coverage", "empty.bin", coverage([]) + coverage([("a", [])]))
    put("fuzz-options", "litecov.args",
        b"litecov\0-instrument_module\0libfoo.so\0-instrument_module=libbar.so\0-persist\0"
        b"-iterations\0" b"0x10\0-coverage_file=out.bin\0-target_module\0t\0--\0/bin/prog\0a b\0x\"y")
    put("fuzz-options", "bools.args", b"tool\0-persist=off\0-loop\0false\0-iterations=42\0--\0cmd")
    put("fuzz-procmaps", "maps.txt",
        b"55e4c1a00000-55e4c1a02000 r--p 00000000 08:01 1234   /usr/bin/cat\n"
        b"7ffd1c3e0000-7ffd1c401000 rw-p 00000000 00:00 0      [stack]\n"
        b"7f00 r-xp 0 00:00 0 /tmp/name with spaces\r\n"
        b"\tffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0\n")
    put("fuzz-dyld-map", "cache.map", DYLD_MAP)

DYLD_MAP = b"""path: /System/Library/dyld/dyld_shared_cache_arm64e
mapping  EX 0x180000000 -> 0x1A0000000

/usr/lib/libobjc.A.dylib
      __TEXT 0x180004000 -> 0x180038000
      __DATA_CONST 0x1D0000000 -> 0x1D0004000

/usr/lib/libalpha.dylib
      __TEXT 0x180038000 -> 0x180039100

/usr/lib/libbeta.dylib
      __TEXT 0x180039100 -> 0x18003C000

/usr/lib/system/libgamma.dylib
      __TEXT 0x18003C000 -> 0x180040000
"""

if __name__ == "__main__":
    main(sys.argv[1])
