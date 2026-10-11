# -*- coding: utf-8 -*-
"""Read-only probe: does the rebased (CPU = record - 0x8000) image contain
plausible printer font tables at CPU 0x6931 / 0x6A31 .. 0x6E31?

Scratch tool - diagnostics only, no project file is modified.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from m8051.rom import parse_intel_hex                      # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEX = os.path.join(ROOT, "firmware", "nm27c512n.hex")

# load with the -0x8000 rebase (record addresses -> CPU addresses)
mem = {}
for addr, data in parse_intel_hex(open(HEX, encoding="latin-1").read()):
    for i, b in enumerate(data):
        mem[(addr - 0x8000) + i] = b

def show(cpu_addr: int, n: int = 96) -> None:
    raw = bytes(mem.get(cpu_addr + i, None) or 0 for i in range(n))
    print(f"CPU 0x{cpu_addr:04X} (record 0x{cpu_addr + 0x8000:04X}):")
    for row in range(0, n, 16):
        chunk = raw[row:row + 16]
        print("  %04X: %s  %s" % (
            cpu_addr + row, chunk.hex(" "),
            "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)))

# the six tables the decompiled printer path indexes: 0x6931, 0x6A31 .. 0x6E31
for base in (0x6931, 0x6A31, 0x6B31, 0x6C31, 0x6D31, 0x6E31):
    present = sum(1 for i in range(0x50) if (base + i) in mem)
    show(base, 64)
    print(f"  bytes present in [0x{base:04X}..0x{base+0x4F:04X}]: {present}/80\n")

# statistics: how "font-like" are they (few bits set, repeated structure)?
import collections                                        # noqa: E402
for base in (0x6931, 0x6E31):
    vals = [mem.get(base + i) for i in range(0x50) if (base + i) in mem]
    if vals:
        print(f"0x{base:04X}: distinct={len(set(vals))} "
              f"max_bits={max(bin(v).count('1') for v in vals)} "
              f"hist={dict(collections.Counter(bin(v).count('1') for v in vals))}")
