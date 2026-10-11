# -*- coding: utf-8 -*-
"""Расследование дампов, этап 3: полный обход ETIM + пересечения с дампами."""
import os
import re
from collections import Counter

from tools import disasm

HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.path.join(HERE, "процессоры")
C_ETIM = os.path.join(HERE, "docs", "nm27c512n_decompiled.c")


def load_hex(path):
    mem = {}
    with open(path, "r", encoding="ascii", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith(":"):
                continue
            try:
                raw = bytes.fromhex(line[1:])
            except ValueError:
                continue
            if len(raw) < 4:
                continue
            count, addr, rtype = raw[0], (raw[1] << 8) | raw[2], raw[3]
            if rtype == 1:
                break
            if rtype != 0:
                continue
            for j, b in enumerate(raw[4:4 + count]):
                mem[addr + j] = b
    return mem


def to_buf(mem, fill=0xFF):
    buf = bytearray([fill]) * 0x10000
    for a, b in mem.items():
        buf[a] = b
    return buf


def names(path, pat=r"\b(FUN|LAB)_CODE_([0-9a-fA-F]{4})\b"):
    txt = open(path, encoding="utf-8", errors="replace").read()
    return {int(m[1], 16) for m in re.findall(pat, txt)}


def traverse(buf, seeds, follow_upper=True, cap=200_000):
    """Обход кода: линейно + по всем переходам (абсолютным и относительным).

    Возвращает (посещённые адреса, абсолютные цели LJMP/LCALL).
    """
    ABS = re.compile(r"(LJMP|LCALL)\s+([0-9A-Fa-f]{4})h")
    REL = re.compile(r"(AJMP|ACALL)\s+([0-9A-Fa-f]{4})h")
    SHORT = re.compile(r"\s([0-9A-Fa-f]{4})h$")
    todo = list(seeds)
    seen = set()
    calls = []
    while todo and len(seen) < cap:
        pc = todo.pop()
        while 0 <= pc < 0x10000 and pc not in seen and len(seen) < cap:
            seen.add(pc)
            try:
                text, size = disasm.disassemble_one(buf, pc)
            except Exception:
                break
            if not size:
                break
            m = ABS.match(text)
            if m:
                dst = int(m.group(2), 16)
                calls.append((pc, dst, m.group(1)))
                if follow_upper and dst >= 0x8000:
                    todo.append(dst)
                break                                   # LJMP: линейно не идём
            m = REL.match(text)
            if m:
                dst = int(m.group(2), 16)
                if follow_upper and dst >= 0x8000:
                    todo.append(dst)
                pc += size
                continue
            if text.startswith(("RET", "RETI")):
                break
            if text.startswith(("SJMP", "AJMP", "ACALL")):
                m = SHORT.search(text)
                if m:
                    todo.append(int(m.group(1), 16))
                break
            if any(text.startswith(k) for k in
                   ("JC ", "JNC", "JZ ", "JNZ", "JB ", "JNB", "JBC", "CJNE", "DJNZ")):
                m = SHORT.search(text)
                if m:
                    todo.append(int(m.group(1), 16))    # условная: обе ветки
            pc += size
    return seen, calls


def main():
    etim = load_hex(os.path.join(HERE, "firmware", "nm27c512n.hex"))
    buf = to_buf(etim)
    seeds = sorted(set(names(C_ETIM)) | {0x8000, 0x0050})
    print("семян ETIM (FUN_CODE из декомпиляции + 0x8000):", len(seeds))

    seen, calls = traverse(buf, seeds)
    print("посещено адресов:", len(seen), " LJMP/LCALL:", len(calls))
    lower = [(s, d, k) for s, d, k in calls if d < 0x8000]
    uniq = sorted({d for _, d, _ in lower})
    print("целей в нижнюю половину: вызовов=%d уникальных=%d" % (len(lower), len(uniq)))
    print("гистограмма по 4КБ-полосам:",
          dict(sorted(Counter(d >> 12 for d in uniq).items())))
    in4k = [d for d in uniq if d < 0x1000]
    print("уникальных целей в 0x0000..0x0FFF: %d -> %s"
          % (len(in4k), " ".join("%04X" % d for d in in4k)))
    srcs = {}
    for s, d, k in lower:
        if d < 0x1000:
            srcs.setdefault(d, []).append((s, k))
    for d in in4k:
        print("   %04X <- %s" % (d, ", ".join("%04X %s" % (s, k) for s, k in srcs[d])))

    # --- пересечение с дампами --------------------------------------------
    print("\n=== пересечение целей ETIM с точками входа Ghidra дампов ===")
    dumps = {}
    for fn in sorted(os.listdir(DIR)):
        if not fn.endswith(".hex"):
            continue
        dumps[fn] = load_hex(os.path.join(DIR, fn))
    for fn, mem in dumps.items():
        cfile = os.path.join(DIR, fn[:-4] + ".c")
        ents = set(names(cfile))
        ents |= {0x0000, 0x0003, 0x000B, 0x0013, 0x001B, 0x0023, 0x002B}
        inside = [d for d in in4k if d in mem]
        hit = [d for d in inside if d in ents]
        print("  %-16s целей ETIM внутри образа: %d, из них -- входные точки Ghidra: %d %s"
              % (fn, len(inside), len(hit), ["%04X" % d for d in hit]))

    # --- что по адресам целей в at89c51 / at89c52_2 ------------------------
    for fn in ("at89c51.hex", "at89c52_2.hex"):
        mem = dumps[fn]
        b = to_buf(mem, fill=0x00)
        cfile = os.path.join(DIR, fn[:-4] + ".c")
        ents = set(names(cfile))
        print("\n--- %s: разбор целей ETIM ---" % fn)
        for d in in4k:
            if d >= len(mem):
                print("    %04X: за пределами образа" % d)
                continue
            try:
                text, size = disasm.disassemble_one(b, d)
            except Exception as exc:
                text = "ERR %s" % exc
            tag = "FUN/LAB Ghidra" if d in ents else "не входная точка"
            print("    %04X: %-18s  %s" % (d, text, tag))

    # --- обратная сверка (потоковая, из .c каждого дампа) ------------------
    print("\n=== обращения самих дампов в 0x8000..0xFFFF ===")
    for fn, mem in dumps.items():
        cfile = os.path.join(DIR, fn[:-4] + ".c")
        if not os.path.isfile(cfile):
            continue
        b = to_buf(mem, fill=0x00)
        seeds = sorted(set(names(cfile)) | {0x0000})
        _, calls = traverse(b, seeds, follow_upper=False, cap=60_000)
        up = [(s, d, k) for s, d, k in calls if d >= 0x8000]
        print("  %-16s семян=%-4d LJMP/LCALL=%-5d в 0x8000..0xFFFF: %d %s"
              % (fn, len(seeds), len(calls), len(up), up[:4]))


if __name__ == "__main__":
    main()
