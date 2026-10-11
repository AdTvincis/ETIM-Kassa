# -*- coding: utf-8 -*-
"""Builder for the *stand-in* cash-register program (``cashier.asm``).

This module assembles ``firmware/demo/cashier.asm`` with :mod:`tools.asm51`
and writes ``firmware/demo/cashier.hex`` (Intel HEX, base address ``0x0000``)
so the host can load it exactly like any other code image::

    from firmware.demo import build_demo, load_demo_image
    image, symbols = build_demo()          # (bytes, {NAME: value})
    rom.load_block(0x0000, image)

The program is a **демонстрационная замена** (stand-in) for the real ETIM
firmware.  The real image is recovered and boots (see
``m8051/firmware_profile``), but its keyboard path runs through its Timer-1
chain, which the idle firmware never starts in this emulation - so this demo
is what a *fully interactive* cash-register flow (keys -> sale -> receipt)
looks like on the same board.  It is *not* the original firmware and must
always be labelled as such.
"""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

from m8051.rom import parse_intel_hex
from tools.asm51 import DEFAULT_CHARSET, AssemblyResult, assemble_file

__all__ = [
    "HERE",
    "SOURCE",
    "HEX",
    "DEMO_BASE",
    "DEMO_LABEL",
    "PORT_MAP",
    "DISPLAY",
    "KEY_LAYOUT",
    "KEY_CODES",
    "build_result",
    "build_demo",
    "load_demo_image",
]

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "cashier.asm")
HEX = os.path.join(HERE, "cashier.hex")

DEMO_BASE = 0x0000
"""The image starts at 0 with a real ``LJMP START`` reset vector."""

DEMO_LABEL = "ДЕМО-ПРОГРАММА (НЕ ОРИГИНАЛЬНАЯ ПРОШИВКА)"
"""Label the UI must show wherever this image is described."""

#: PPI 8255 addresses as used by ``cashier.asm`` (see the EQU block there).
PORT_MAP = {
    "PPI_PA": 0x0000,       # out: display segment mask / printer byte (mode 1)
    "PPI_PB": 0x0001,       # out: one-hot digit select (and keyboard row)
    "PPI_PC": 0x0002,       # in : keyboard columns, 0 = pressed
    "PPI_CTRL": 0x0003,     # out: 0x89 = display, 0xA9 = printer
    "MODE_DISPLAY": 0x89,
    "MODE_PRINTER": 0xA9,
}

#: Display description: 8 digits, cell 0 is the mode indicator.
DISPLAY = {
    "columns": 8,
    "lines": 1,
    "mode_cell": 0,
    "money_cells": (1, 7),
}

#: 7-segment table the program uses (bit0=a .. bit6=g, bit7=dp, active high).
SEGMENTS = {
    "0": 0x3F, "1": 0x06, "2": 0x5B, "3": 0x4F, "4": 0x66,
    "5": 0x6D, "6": 0x7D, "7": 0x07, "8": 0x7F, "9": 0x6F,
    "-": 0x40, " ": 0x00,
}

#: Keyboard matrix the program scans: 8 rows x 8 columns, row-major.
#: ``""`` marks a slot the demo does not use.  This table must stay in sync
#: with ``KEYMAP`` in ``cashier.asm`` (``tests/test_demo_firmware.py`` decodes
#: the assembled table and checks exactly that).
#:
#: The positions are the ones ``board/keyboard.py`` (hal-ppi) really reports --
#: see the coordinate list above ``KEYMAP`` in ``cashier.asm``: digits in the
#: top-left 3x3 block, "0" at (3,0), "00"/"." at the right edge of rows 0/1,
#: СУММА (0,4), ОПЛ (0,5), ИТОГ (0,6), ПОДЫТОГ (1,6), ОТМЕНА (1,4),
#: ВВОД (2,6), СБРОС (2,7).  Names are the demo's own (``KEY_CODES``); the
#: board calls the ИТОГ key "ITOG", everything else is spelled the same.
KEY_LAYOUT: List[List[str]] = [
    ["7", "8", "9", "X", "СУММА", "ОПЛ", "ИТОГ", "00"],
    ["4", "5", "6", "СКИДКА", "ОТМЕНА", "ВОЗВРАТ", "ПОДЫТОГ", "."],
    ["1", "2", "3", "КАССИР", "СЕРВИС", "РЕЖИМ", "ВВОД", "СБРОС"],
    ["0", "СТРЕЛКА_ВЛЕВО", "СТРЕЛКА_ВПРАВО", "ПРОБЕЛ",
     "ТАБ", "ЧЕК", "КС", "Z"],
    ["ПИТ", "", "", "", "", "", "", ""],
    ["", "", "", "", "", "", "", ""],
    ["", "", "", "", "", "", "", ""],
    ["", "", "", "", "", "", "", ""],
]

#: Internal key codes (see the ``K_*`` EQU block in ``cashier.asm``).
KEY_CODES = {
    "0": 0x00, "1": 0x01, "2": 0x02, "3": 0x03, "4": 0x04,
    "5": 0x05, "6": 0x06, "7": 0x07, "8": 0x08, "9": 0x09,
    "00": 0x0A,
    ".": 0x0B,
    "СБРОС": 0x10,
    "СУММА": 0x11,
    "ПОДЫТОГ": 0x12,
    "ИТОГ": 0x13,
    "ОТМЕНА": 0x14,
    "ОПЛ": 0x15,
    "ВВОД": 0x16,
    "X": 0x17,
    "": 0xFF,
}

#: Names the assembled program actually acts on.
USED_KEYS = tuple(k for k in KEY_CODES if k)


def build_result() -> AssemblyResult:
    """Assemble ``cashier.asm`` and return the full assembly result."""
    return assemble_file(SOURCE, org=DEMO_BASE, charset=DEFAULT_CHARSET)


def build_demo() -> Tuple[bytes, Dict[str, int]]:
    """Assemble the stand-in program, write ``cashier.hex``, return the image."""
    result = build_result()
    with open(HEX, "w", encoding="ascii", newline="\n") as fh:
        fh.write(result.intel_hex())
    return result.image, result.symbols


def load_demo_image() -> bytes:
    """Return the assembled image, rebuilding it if ``cashier.hex`` is stale."""
    if os.path.isfile(HEX):
        try:
            if os.path.getmtime(HEX) >= os.path.getmtime(SOURCE):
                return _image_from_hex(HEX)
        except OSError:                     # pragma: no cover - races
            pass
    image, _ = build_demo()
    return image


def _image_from_hex(path: str) -> bytes:
    with open(path, "r", encoding="ascii") as fh:
        text = fh.read()
    mem: Dict[int, int] = {}
    for addr, data in parse_intel_hex(text):
        for i, byte in enumerate(data):
            mem[(addr + i) & 0xFFFF] = byte
    if not mem:
        raise ValueError(f"{path}: no data records")
    base, end = min(mem), max(mem) + 1
    return bytes(mem.get(a, 0xFF) for a in range(base, end))


if __name__ == "__main__":                  # pragma: no cover - CLI helper
    image, symbols = build_demo()
    print(f"{HEX}: {len(image)} bytes, base 0x{DEMO_BASE:04X}, "
          f"{len(symbols)} symbols")
    print("START = 0x%04X" % symbols.get("START", -1))
