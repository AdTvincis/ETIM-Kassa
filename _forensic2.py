# -*- coding: utf-8 -*-
"""Расследование дампов (только чтение): цели вызовов ETIM -> нижняя половина.

Этап 2:
  * все LJMP/LCALL из верхней половины ETIM (обход от точек входа Ghidra
    из docs/nm27c512n_decompiled.c + от 0x8000), гистограмма целей;
  * что лежит по этим адресам в at89c51 / at89c52_2 (входные точки? код?);
  * обратная сверка: обращается ли at89c51 к 0x8000..0xFFFF.
"""
import os
import re
from collections import Counter

from tools import disasm

HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.path.join(HERE, "процессоры")
ACALL_OPS = (0x11, 0x31, 0x51, 0x71, 0x91, 0xB1, 0xD1, 0xF1)
AJMP_OPS = (0x01, 0x21, 0x41, 0x61, 0x81, 0xA1, 0xC1, 0xE1)


def load_hex(path):
    """Intel HEX -> {addr: byte}; битые чексуммы пропускаем (at89c52_2)."""
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
            if rtype != 0:
                if rtype == 1:
                    break
                continue
            for j, b in enumerate(raw[4:4 + count]):
                mem[addr + j] = b
    return mem


def to_buf(mem, fill=0xFF):
    buf = bytearray([fill]) * 0x10000
    for a, b in mem.items():
        buf[a] = b
    return buf


def fun_addresses(c_path):
    """Адреса функций Ghidra (FUN_CODE_xxxx) из декомпиляции."""
    txt = open(c_path, encoding="utf-8", errors="replace").read()
    return sorted({int(m, 16) for m in re.findall(r"FUN_CODE_([0-9a-fA-F]{4})\b", txt)})


def collect_calls(buf, seeds, cap=20000):
    """Линейный обход от каждой точки входа; собираем LJMP/LCALL (абсолютные)."""
    calls = []            # (src, dst, mnem)
    visited = set()
    for seed in seeds:
        pc = seed
        steps = 0
        while steps < 4000:
            steps += 1
            if not (0 <= pc < 0x10000) or pc in visited:
                break
            visited.add(pc)
            try:
                text, size = disasm.disassemble_one(buf, pc)
            except Exception:
                break
            if not size:
                break
            m = re.match(r"(LJMP|LCALL)\s+([0-9A-Fa-f]{4})h", text)
            if m:
                calls.append((pc, int(m.group(2), 16), m.group(1)))
            if text.startswith(("RET", "RETI")):
                break
            if text.startswith(("LJMP", "SJMP", "AJMP", "ACALL")):
                # абсолютные цели уже записаны; линейно дальше не идём
                if not text.startswith(("LJMP",)):
                    break
                break
            pc += size
    return calls, visited


def entry_points(mem):
    """Собственные входные точки образа: векторы + цели LJMP/LCALL/AJMP/ACALL."""
    buf = to_buf(mem)
    ents = {0x0000, 0x0003, 0x000B, 0x0013, 0x001B, 0x0023, 0x002B}
    for pc in sorted(mem):
        op = buf[pc]
        try:
            text, size = disasm.disassemble_one(buf, pc)
        except Exception:
            continue
        m = re.match(r"(LJMP|LCALL|AJMP|ACALL)\s+([0-9A-Fa-f]{4})h", text)
        if m and size and size >= 2:
            tgt = int(m.group(2), 16)
            if 0 <= tgt <= max(mem):
                ents.add(tgt)
    return ents


def decode_ok(buf, addr, n=14):
    """На n инструкций от addr без 00/FF-пустоты и без выхода за границу."""
    pc = addr
    for _ in range(n):
        if not (0 <= pc < 0x10000):
            return False
        b = buf[pc]
        if b in (0x00, 0xFF):
            return False
        try:
            text, size = disasm.disassemble_one(buf, pc)
        except Exception:
            return False
        if not size:
            return False
        pc += size
    return True


def main():
    etim = load_hex(os.path.join(HERE, "firmware", "nm27c512n.hex"))
    etim_buf = to_buf(etim)
    c_path = os.path.join(HERE, "docs", "nm27c512n_decompiled.c")
    seeds = fun_addresses(c_path)
    print("точек входа Ghidra (FUN_CODE):", len(seeds))
    seeds = sorted(set(seeds) | {0x8000})

    calls, visited = collect_calls(etim_buf, seeds)
    print("посещено инструкций:", len(visited), "абсолютных вызовов LJMP/LCALL:", len(calls))

    lower = [(s, d, k) for s, d, k in calls if d < 0x8000]
    print("из них целей в нижнюю половину (0x0000..0x7FFF):", len(lower),
          "уникальных:", len({d for _, d, _ in lower}))
    hist = Counter(d >> 12 for _, d, _ in lower)
    print("по 4КБ-полосам:", dict(sorted(hist.items())))

    in4k = sorted({d for _, d, _ in lower if d < 0x1000})
    print("цели в 0x0000..0x0FFF (диапазон at89c51):", len(in4k))
    print("   ", " ".join("%04X" % d for d in in4k))

    # --- что лежит по этим адресам в at89c51 / at89c52_2 ------------------
    for name in ("at89c51.hex", "at89c52_2.hex"):
        mem = load_hex(os.path.join(DIR, name))
        buf = to_buf(mem, fill=0x00)
        ents = entry_points(mem)
        print("\n=== %s (байт %d, диапазон 0x%04X..0x%04X, входных точек %d) ==="
              % (name, len(mem), min(mem), max(mem), len(ents)))
        hit_entry = [d for d in in4k if d in ents]
        hit_code = [d for d in in4k if decode_ok(buf, d)]
        print("  целей ETIM в собственных входных точках:", len(hit_entry), "из", len(in4k))
        print("  целей ETIM с читаемым кодом (14 инстр.):", len(hit_code), "из", len(in4k))
        # контроль: те же проверки на всех адресах 0x0000..0x0FFF
        all_entries = sum(1 for a in range(0x1000) if a in ents)
        all_code = sum(1 for a in range(0x1000) if decode_ok(buf, a))
        print("  контроль по всему образу: входных точек %d/4096, читаемого кода %d/4096"
              % (all_entries, all_code))
        # первые инструкции по целевым адресам
        for d in in4k[:8]:
            text, size = disasm.disassemble_one(buf, d)
            flag = "ВХОД" if d in ents else ("код" if decode_ok(buf, d) else "мусор")
            print("    %04X: %-22s [%s]" % (d, text, flag))

    # --- обратная сверка: обращается ли at89c51 к верхней половине ---------
    print("\n=== обращения к 0x8000..0xFFFF ===")
    for name in ("at89c51.hex", "at89c52_2.hex", "at87f51.hex", "at27c512r.hex"):
        mem = load_hex(os.path.join(DIR, name))
        buf = to_buf(mem, fill=0x00)
        up = []
        for pc in sorted(mem):
            try:
                text, size = disasm.disassemble_one(buf, pc)
            except Exception:
                continue
            m = re.match(r"(LJMP|LCALL|AJMP|ACALL)\s+([0-9A-Fa-f]{4})h", text)
            if m and int(m.group(2), 16) >= 0x8000:
                up.append((pc, text))
        print("  %-16s LJMP/LCALL в 0x8000..0xFFFF: %d %s"
              % (name, len(up), up[:5]))

    # --- LJMP-цели строго из 0x8000 ("диспетчер") --------------------------
    print("\n=== линейный разбор от 0x8000 (первые 0x200 байт) ===")
    pc = 0x8000
    ljm = []
    for _ in range(200):
        try:
            text, size = disasm.disassemble_one(etim_buf, pc)
        except Exception:
            break
        m = re.match(r"(LJMP|LCALL)\s+([0-9A-Fa-f]{4})h", text)
        if m:
            ljm.append((pc, m.group(1), int(m.group(2), 16)))
        if pc >= 0x8200:
            break
        pc += size if size else 1
    for src, kind, dst in ljm:
        zone = ("0x0000..0x0FFF" if dst < 0x1000 else
                "0x1000..0x7FFF" if dst < 0x8000 else "верхняя")
        print("  %04X: %-5s %04X  [%s]" % (src, kind, dst, zone))


if __name__ == "__main__":
    main()
