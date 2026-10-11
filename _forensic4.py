# -*- coding: utf-8 -*-
"""Расследование дампов, этап 4: схожесть байтов, контекст, стиль, кассовые
признаки (только чтение)."""
import os
import re
from collections import Counter

from tools import disasm

HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.path.join(HERE, "процессоры")

ETIM_TARGETS = [0x00C1, 0x02D9, 0x04D1, 0x0A06, 0x0C95]   # из этапов 2-3


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


def grams(mem, n=8):
    """Набор n-грамм по возрастющим адресам (плотный участок)."""
    if not mem:
        return set()
    lo, hi = min(mem), max(mem)
    data = bytes(mem.get(a, 0xFF) for a in range(lo, hi + 1))
    return {data[i:i + n] for i in range(len(data) - n + 1)}


def main():
    etim = load_hex(os.path.join(HERE, "firmware", "nm27c512n.hex"))
    dumps = {}
    for fn in sorted(os.listdir(DIR)):
        if fn.endswith(".hex"):
            dumps[fn] = load_hex(os.path.join(DIR, fn))

    print("=== 8-граммное пересечение с верхней половиной ETIM ===")
    eg = grams(etim, 8)
    print("  ETIM 8-грамм:", len(eg))
    for fn, mem in dumps.items():
        g = grams(mem, 8)
        common = g & eg
        print("  %-16s 8-грамм=%-6d общих с ETIM=%-5d (%.2f%%)"
              % (fn, len(g), len(common), 100.0 * len(common) / max(1, len(g))))

    print("\n=== пары дампов между собой ===")
    names = [n for n in dumps if n in ("at89c51.hex", "at89c52_2.hex",
                                       "at87f51.hex", "at87f51_2.hex")]
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            ga, gb = grams(dumps[a], 8), grams(dumps[b], 8)
            common = ga & gb
            print("  %-16s vs %-16s: общих %.1f%% (%d)"
                  % (a, b, 100.0 * len(common) / max(1, min(len(ga), len(gb))),
                     len(common)))
    same = dumps.get("at87f51.hex") == dumps.get("at87f51_2.hex")
    print("  at87f51 == at87f51_2 (байт-в-байт):", same)

    print("\n=== контекст целей ETIM в at89c51 / at89c52_2 ===")
    for fn in ("at89c51.hex", "at89c52_2.hex"):
        mem = dumps[fn]
        buf = to_buf(mem, fill=0x00)
        ents = set()
        cfile = os.path.join(DIR, fn[:-4] + ".c")
        txt = open(cfile, encoding="utf-8", errors="replace").read()
        ents = {int(m, 16) for m in re.findall(r"_(?:FUN|LAB)?_?CODE_([0-9a-fA-F]{4})",
                                               txt)}
        ents |= {int(m, 16) for m in re.findall(r"FUN_CODE_([0-9a-fA-F]{4})", txt)}
        ents |= {int(m, 16) for m in re.findall(r"LAB_CODE_([0-9a-fA-F]{4})", txt)}
        print(" -- %s (FUN/LAB: %d)" % (fn, len(ents)))
        for d in ETIM_TARGETS:
            if d not in mem:
                print("    %04X: за границей образа" % d)
                continue
            text, _ = disasm.disassemble_one(buf, d)
            near = max([e for e in ents if e <= d], default=None)
            inside = ("внутри %04X" % near) if near is not None else "до первого FUN"
            print("    %04X: %-16s %-14s %s" % (d, text,
                  "FUN/LAB" if d in ents else "-- не вход", inside))

    print("\n=== стиль декомпиляции (маркеры Ghidra) ===")
    for cfile in ["nm27c512n_decompiled.c"] + [n[:-4] + ".c" for n in dumps]:
        p = os.path.join(HERE, "docs", cfile) if cfile.startswith("nm27c") \
            else os.path.join(DIR, cfile)
        if not os.path.isfile(p):
            continue
        txt = open(p, encoding="utf-8", errors="replace").read()
        print("  %-28s FUN_CODE=%-4d LAB_CODE=%-4d thunk=%-3d jumptable=%-3d "
              "WARNING=%-3d SBUF=%-3d UNRECOVERED=%d"
              % (cfile,
                 len(re.findall(r"FUN_CODE_", txt)),
                 len(re.findall(r"LAB_CODE_", txt)),
                 len(re.findall(r"thunk_", txt)),
                 len(re.findall(r"JUMPTABLE", txt)),
                 len(re.findall(r"WARNING", txt)),
                 len(re.findall(r"\bSBUF\b", txt)),
                 len(re.findall(r"UNRECOVERED", txt))))

    print("\n=== кассовые признаки в декомпиляциях ===")
    markers = {
        "PPI 0x89": r"0x89\b", "PPI 0xa9": r"0xa9\b",
        "стр. 0x91 (клавиатура)": r"0x913\d|0x91\b", "стр. 0x82 (сегменты)": r"0x82\d\d|0x82\b",
        "стр. 0x92": r"0x92\d\d|0x92\b", "стр. 0xa2 (сетка)": r"0xa2\d\d|0xa2\b",
        "стр. 0xa1 (лампы)": r"0xa1\d\d|0xa1\b",
        "SBUF/UART": r"\bSBUF\b", "TMOD": r"\bTMOD\b",
        "клавиатура (скан столбцов)": r"0x9130|0x0002",
    }
    files = [("ETIM nm27c512n", os.path.join(HERE, "docs", "nm27c512n_decompiled.c"))]
    for n in dumps:
        p = os.path.join(DIR, n[:-4] + ".c")
        if os.path.isfile(p):
            files.append((n[:-2], p))
    for title, p in files:
        txt = open(p, encoding="utf-8", errors="replace").read()
        hits = {k: len(re.findall(v, txt, re.I)) for k, v in markers.items()}
        print("  %-18s %s" % (title, {k: v for k, v in hits.items() if v}))


if __name__ == "__main__":
    main()
