"""The cash-register display: 8 multiplexed alphanumeric digits.

Reverse-engineered from the firmware (see ``docs/hardware_analysis.md``),
the display refresh lives in the timer ISR at ``0x82D9``-``0x831E``::

    8309  CLR  C
    830A  MOV  A,#0AFh
    830C  SUBB A,R0          ; R1 = 0xAF - R0
    830D  MOV  R1,A
    830E  MOV  A,@R1          ; internal RAM 0x58..0x5F  (reverse order)
    830F  MOV  DPH,#92h
    8312  MOVX @DPTR,A        ; -> second anode/segment byte
    8313  MOV  A,@R0          ; internal RAM 0x50..0x57
    8314  MOV  DPH,#82h
    8317  MOVX @DPTR,A        ; -> first anode/segment byte
    8318  MOV  A,R0
    8319  ANL  A,#07h
    831B  MOV  DPH,#0A2h
    831E  MOVX @DPTR,A        ; -> grid/digit selector, 0..7, 8 = blank

so the machine drives **8 digits x 16 segments**.  The board therefore keeps
two segment bytes per cell; :meth:`Display.cell_segments` returns the low byte
(the 7-segment + decimal-point byte) to stay inside the documented 0..255
range, and :meth:`Display.cell_segments16` exposes all 16 bits.

The digit-select patterns the firmware uses are the Gray-coded table
``AIHLDFBC`` that appears at ROM 0x8203 and 0x8266 (values 0x41 0x49 0x48
0x4C 0x44 0x46 0x42 0x43) - i.e. 0x40 | gray(i).  That is a *selector*, not
a segment pattern, and it is handled by :func:`gray_index`.

Rendering
---------
``render_rows`` needs a 5x7 dot matrix per cell, provided by ``FONT5X7``.
``text()`` prefers the exact character the firmware latched; when it only
knows the segment mask it decodes it through the 7-segment table first and
the 14/16-segment table second (the alphanumeric VFD alphabet).
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional, Sequence

__all__ = [
    "Display",
    "SEG7",
    "SEG7_REVERSE",
    "SEG16",
    "SEG16_REVERSE",
    "FONT5X7",
    "gray_index",
    "segments_for",
    "char_for_segments",
    "A1_GRAY_IS_LAMP",
]

#: A write to a 0xA1 page whose payload is the Gray-coded selector
#: ``AIHLDFBC`` (0x41 0x49 0x48 0x4C 0x44 0x46 0x42 0x43) is treated as an
#: annunciator/indicator select rather than as segment data.  Set to False to
#: take every 0xA1 payload literally as a segment byte.
A1_GRAY_IS_LAMP = True
DISPLAY_A1_GRAY_IS_LAMP = A1_GRAY_IS_LAMP      # backwards-compatible alias

# --------------------------------------------------------------------------
# 7-segment alphabet: bit0 = a, bit1 = b, ... bit6 = g, bit7 = decimal point
# (active high).  This is the "low" anode byte (XDATA page 0x82).
# --------------------------------------------------------------------------
SEG_A, SEG_B, SEG_C, SEG_D, SEG_E, SEG_F, SEG_G, SEG_DP = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)

SEG7: Dict[str, int] = {
    "0": 0x3F, "1": 0x06, "2": 0x5B, "3": 0x4F, "4": 0x66,
    "5": 0x6D, "6": 0x7D, "7": 0x07, "8": 0x7F, "9": 0x6F,
    "A": 0x77, "b": 0x7C, "C": 0x39, "c": 0x58, "d": 0x5E, "E": 0x79,
    "F": 0x71, "G": 0x3D, "H": 0x76, "h": 0x74, "I": 0x06, "J": 0x1E,
    "L": 0x38, "n": 0x54, "o": 0x5C, "P": 0x73, "q": 0x67, "r": 0x50,
    "S": 0x6D, "t": 0x78, "U": 0x3E, "u": 0x1C, "V": 0x3E, "y": 0x6E,
    "-": 0x40, "_": 0x08, "=": 0x48, " ": 0x00, "°": 0x63,
    "[": 0x39, "]": 0x0F, "(": 0x39, ")": 0x0F, "'": 0x02, '"': 0x22,
    "?": 0x53, "*": 0x63, "/": 0x52, "\\": 0x64, "|": 0x06,
}
SEG7_REVERSE: Dict[int, str] = {}
for _ch, _mask in SEG7.items():
    SEG7_REVERSE.setdefault(_mask, _ch)


# --------------------------------------------------------------------------
# 16-segment (14 segments + dp + annunciator) alphabet for the alphanumeric
# display.  Bit assignment:
#   0x0001 a top        0x0002 b upper right   0x0004 c lower right
#   0x0008 d bottom     0x0010 e lower left    0x0020 f upper left
#   0x0040 g1 upper mid 0x0080 g2 lower mid
#   0x0100 h (\) upper left diag   0x0200 i (/) upper right diag
#   0x0400 j (/) lower right diag  0x0800 k (\) lower left diag
#   0x1000 l centre lower          0x2000 m centre upper
#   0x4000 dp                      0x8000 sign/annunciator
#
# NOTE: this alphabet is a *reconstruction* (HYPOTHESIS).  The dump does carry
# font data - the 7-segment digits "0".."F" at record 0x9EBA (CPU 0x1EBA,
# bytes verified) and the printer's needle-column tables at CPU
# 0x6931..0x6D31 - but a ready 16-segment table for this Cyrillic alphabet
# has not been identified in it.  So the board keeps its reconstruction and
# falls back to the 7-segment table and then to '?'.
# --------------------------------------------------------------------------
_A, _B, _C, _D, _E, _F, _G1, _G2 = 0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080
_H, _I, _J, _K, _L, _M = 0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000
_DP, _ANN = 0x4000, 0x8000


def _seg(*names: str) -> int:
    table = {"a": _A, "b": _B, "c": _C, "d": _D, "e": _E, "f": _F,
             "g1": _G1, "g2": _G2, "h": _H, "i": _I, "j": _J, "k": _K,
             "l": _L, "m": _M, "dp": _DP}
    out = 0
    for n in names:
        out |= table[n]
    return out


SEG16: Dict[str, int] = {
    # digits
    "0": _seg("a", "b", "c", "d", "e", "f", "i", "k"),
    "1": _seg("b", "c"),
    "2": _seg("a", "b", "g1", "g2", "e", "d"),
    "3": _seg("a", "b", "g2", "c", "d"),
    "4": _seg("f", "g1", "g2", "b", "c"),
    "5": _seg("a", "f", "g1", "g2", "c", "d"),
    "6": _seg("a", "f", "e", "d", "c", "g1", "g2"),
    "7": _seg("a", "b", "c"),
    "8": _seg("a", "b", "c", "d", "e", "f", "g1", "g2", "i", "k"),
    "9": _seg("a", "b", "c", "d", "f", "g1", "g2"),
    # latin
    "A": _seg("a", "b", "c", "e", "f", "g1", "g2"),
    "B": _seg("a", "b", "c", "d", "e", "f", "g2", "i", "l"),
    "C": _seg("a", "d", "e", "f"),
    "D": _seg("a", "b", "c", "d", "e", "f", "i", "k"),
    "E": _seg("a", "d", "e", "f", "g1", "g2"),
    "F": _seg("a", "e", "f", "g1"),
    "G": _seg("a", "c", "d", "e", "f", "g2"),
    "H": _seg("b", "c", "e", "f", "g1", "g2"),
    "I": _seg("b", "c"),
    "J": _seg("b", "c", "d", "e"),
    "K": _seg("e", "f", "i", "j"),
    "L": _seg("d", "e", "f"),
    "M": _seg("b", "c", "e", "f", "h", "i"),
    "N": _seg("b", "c", "e", "f", "h", "j"),
    "O": _seg("a", "b", "c", "d", "e", "f"),
    "P": _seg("a", "b", "e", "f", "g1", "g2"),
    "Q": _seg("a", "b", "c", "d", "e", "f", "j"),
    "R": _seg("a", "b", "e", "f", "g1", "j"),
    "S": _seg("a", "f", "g1", "g2", "c", "d"),
    "T": _seg("a", "l", "m"),
    "U": _seg("b", "c", "d", "e", "f"),
    "V": _seg("e", "f", "j", "k"),
    "W": _seg("b", "c", "e", "f", "j", "k"),
    "X": _seg("h", "i", "j", "k"),
    "Y": _seg("h", "i", "l"),
    "Z": _seg("a", "b", "g1", "g2", "e", "d"),
    # cyrillic (uppercase; lowercase cells show the same shape)
    "А": _seg("a", "b", "c", "e", "f", "g1", "g2"),
    "Б": _seg("a", "e", "f", "d", "g1", "m"),
    "В": _seg("a", "b", "c", "d", "e", "f", "g2", "i", "l"),
    "Г": _seg("a", "e", "f"),
    "Д": _seg("a", "b", "c", "d", "e", "j", "k"),
    "Е": _seg("a", "d", "e", "f", "g1", "g2"),
    "Ж": _seg("b", "c", "e", "f", "g1", "g2", "h", "i", "j", "k"),
    "З": _seg("a", "b", "c", "d", "g2"),
    "И": _seg("b", "c", "e", "f", "h", "i"),
    "Й": _seg("b", "c", "e", "f", "h", "i") | _ANN,
    "К": _seg("e", "f", "i", "j"),
    "Л": _seg("a", "b", "c", "e", "f"),
    "М": _seg("b", "c", "e", "f", "h", "i"),
    "Н": _seg("b", "c", "e", "f", "g1", "g2"),
    "О": _seg("a", "b", "c", "d", "e", "f"),
    "П": _seg("a", "b", "c", "d", "e", "f"),
    "Р": _seg("a", "b", "e", "f", "g1", "g2"),
    "С": _seg("a", "d", "e", "f"),
    "Т": _seg("a", "l", "m"),
    "У": _seg("h", "i", "l"),
    "Ф": _seg("a", "b", "c", "d", "e", "f", "g1", "g2", "m"),
    "Х": _seg("h", "i", "j", "k"),
    "Ц": _seg("b", "c", "d", "e", "f", "j"),
    "Ч": _seg("f", "g1", "g2", "i"),
    "Ш": _seg("b", "c", "e", "f", "d"),
    "Щ": _seg("b", "c", "e", "f", "d", "j"),
    "Ъ": _seg("a", "f", "e", "d", "g1", "m"),
    "Ы": _seg("b", "c", "e", "f", "g1", "g2", "l"),
    "Ь": _seg("e", "f", "d", "g1", "g2"),
    "Э": _seg("a", "b", "c", "d", "g2", "k"),
    "Ю": _seg("b", "c", "e", "f", "g1", "g2", "m"),
    "Я": _seg("a", "b", "d", "e", "f", "i"),
    " ": 0x0000,
}
# add the dp/annunciator helper entries
SEG16["-"] = _seg("g1")
SEG16["."] = _seg("dp")
SEG16["_"] = _seg("d")
SEG16[":"] = _seg("dp")

SEG16_REVERSE: Dict[int, str] = {}
for _ch, _mask in SEG16.items():
    SEG16_REVERSE.setdefault(_mask, _ch)


# Transliteration used by the firmware for Cyrillic text (see the
# "Character encoding" section of board/printer.py; the underlying strings are
# in docs/rom_strings.txt).  The display font only needs the "machine"
# character; map it onto the Cyrillic glyph so text() reads naturally.
TRANSLIT: Dict[str, str] = {
    "a": "А", "b": "Б", "w": "В", "g": "Г", "d": "Д", "e": "Е", "z": "З",
    "i": "И", "j": "Й", "k": "К", "l": "Л", "m": "М", "n": "Н", "o": "О",
    "p": "П", "r": "Р", "s": "С", "t": "Т", "u": "У", "f": "Ф", "h": "Х",
    "c": "Ц", "~": "Ч", "y": "Ы", "x": "Ь", "q": "Я", "}": "Щ",
    "A": "А", "B": "Б", "W": "В", "G": "Г", "D": "Д", "E": "Е", "Z": "З",
    "I": "И", "J": "Й", "K": "К", "L": "Л", "M": "М", "N": "Н", "O": "О",
    "P": "П", "R": "Р", "S": "С", "T": "Т", "U": "У", "F": "Ф", "H": "Х",
    "C": "Ц", "Y": "Ы", "X": "Ь", "Q": "Я",
}


# --------------------------------------------------------------------------
# 5x7 dot-matrix font for render_rows(): 5 bytes per glyph, column major,
# bit0 = top row.  Covers printable ASCII; Cyrillic text is shown using the
# firmware's own transliteration (that is literally what the machine stores).
# --------------------------------------------------------------------------
_FONT5X7_HEX = {
    " ": "0000000000", "!": "00005F0000", '"': "0007000700", "#": "147F147F14",
    "$": "242A7F2A12", "%": "2313086462", "&": "3649552250", "'": "0005030000",
    "(": "001C224100", ")": "0041221C00", "*": "14083E0814", "+": "08083E0808",
    ",": "0050300000", "-": "0808080808", ".": "0060600000", "/": "2010080402",
    "0": "3E5149453E", "1": "00427F4000", "2": "4261514946", "3": "2141454B31",
    "4": "1814127F10", "5": "2745454539", "6": "3C4A494930", "7": "0171090503",
    "8": "3649494936", "9": "064949291E", ":": "0036360000", ";": "0056360000",
    "<": "0814224100", "=": "1414141414", ">": "0041221408", "?": "0201510906",
    "@": "324979413E", "A": "7E1111117E", "B": "7F49494936", "C": "3E41414122",
    "D": "7F4141221C", "E": "7F49494941", "F": "7F09090901", "G": "3E4149497A",
    "H": "7F0808087F", "I": "00417F4100", "J": "2040413F01", "K": "7F08142241",
    "L": "7F40404040", "M": "7F020C027F", "N": "7F0408107F", "O": "3E4141413E",
    "P": "7F09090906", "Q": "3E4151215E", "R": "7F09192946", "S": "4649494931",
    "T": "01017F0101", "U": "3F4040403F", "V": "1F2040201F", "W": "3F4038403F",
    "X": "6314081463", "Y": "0304780403", "Z": "6151494543", "[": "007F414100",
    "\\": "0204081020", "]": "0041417F00", "^": "0402010204", "_": "4040404040",
    "`": "0001020400", "a": "2054545478", "b": "7F48444438", "c": "3844444420",
    "d": "384444487F", "e": "3854545418", "f": "087E090102", "g": "0C5252523E",
    "h": "7F08040478", "i": "00447D4000", "j": "2040443D00", "k": "7F10284400",
    "l": "00417F4000", "m": "7C04180478", "n": "7C08040478", "o": "3844444438",
    "p": "7C14141408", "q": "081414187C", "r": "7C08040408", "s": "4854545420",
    "t": "043F444020", "u": "3C4040207C", "v": "1C2040201C", "w": "3C4030403C",
    "x": "4428102844", "y": "0C5050503C", "z": "4464544C44", "{": "0008364100",
    "|": "00007F0000", "}": "0041360800", "~": "0804081008",
}
# Cyrillic cells are displayed through the firmware transliteration so that a
# 5x7 ASCII font is enough (the machine literally stores 'a','b','w','g',...).
_TRANSLIT_BACK = {
    "А": "a", "Б": "b", "В": "w", "Г": "g", "Д": "d", "Е": "e", "Ж": "z",
    "З": "z", "И": "i", "Й": "j", "К": "k", "Л": "l", "М": "m", "Н": "n",
    "О": "o", "П": "p", "Р": "r", "С": "s", "Т": "t", "У": "u", "Ф": "f",
    "Х": "h", "Ц": "c", "Ч": "~", "Ш": "w", "Щ": "}", "Ъ": "x", "Ы": "y",
    "Ь": "x", "Э": "e", "Ю": "u", "Я": "q",
}

FONT5X7: Dict[str, bytes] = {}
for _ch, _hexs in _FONT5X7_HEX.items():
    FONT5X7[_ch] = bytes.fromhex(_hexs)
for _cyr, _lat in _TRANSLIT_BACK.items():
    FONT5X7.setdefault(_cyr, FONT5X7[_lat])
for _cyr, _lat in zip("абвгдежзийклмнопрстуфхцчшщъыьэюя", "abwgdezzijk lmnoprstufhc~w}xyxeuq".replace(" ", "")):
    FONT5X7.setdefault(_cyr, FONT5X7.get(_lat, FONT5X7["?"]))
_GLYPH_BOX = FONT5X7["?"]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
#: The selector nibbles of the table at ROM 0x8266 ("AIHLDFBC" =
#: 0x41 0x49 0x48 0x4C 0x44 0x46 0x42 0x43).  Ordered by digit index 0..7.
#: The same eight nibbles, with bit 4 / 5 set, are the tables at ROM 0x8118
#: (0x11,0x19,...) and 0x8120 (0x21,0x23,...) - one nibble changes per step.
_SELECT8 = [0x1, 0x9, 0x8, 0xC, 0x4, 0x6, 0x2, 0x3]
_GRAY8 = _SELECT8                        # historical alias


def gray_index(value: int) -> Optional[int]:
    """Decode a firmware digit-select byte (``0x40 | select(i)``) into 0..7."""
    low = value & 0x0F
    if low in _SELECT8:
        return _SELECT8.index(low)
    return None


select_index = gray_index


def segments_for(ch: str) -> int:
    """16-bit segment mask for a character (best effort)."""
    if ch in SEG16:
        return SEG16[ch]
    if ch in TRANSLIT:
        return SEG16.get(TRANSLIT[ch], 0)
    if ch in SEG7:
        return SEG7[ch] & 0xFF
    up = ch.upper()
    if up in SEG16:
        return SEG16[up]
    if up in SEG7:
        return SEG7[up] & 0xFF
    return 0


def char_for_segments(mask: int) -> str:
    """Decode a raw segment mask back into a character ('?' when unknown).

    When only the low byte was written (the normal 7-segment case, and what the
    8255/write-only paths produce) the 7-segment alphabet wins, because e.g.
    ``0x3F`` is '0' on a 7-segment display but would also match the 16-segment
    shape of 'O'.
    """
    mask &= 0xFFFF
    if mask == 0:
        return " "
    low = mask & 0xFF
    seven_only = not (mask & 0x7F00)
    if seven_only:
        if low == SEG_DP:
            # a lone decimal point (the money field's "12.34" separator):
            # SEG7 has no '.' entry and the 0x7F lookup would strip the dp
            # bit, turning the cell into a blank.  Decode it as '.'.
            return "."
        ch = SEG7_REVERSE.get(low & 0x7F)
        if ch is not None:
            return ch
    ch = SEG16_REVERSE.get(mask)
    if ch is not None:
        return ch
    if not seven_only:
        ch = SEG16_REVERSE.get(mask & ~_DP)
        if ch is not None:
            return ch
    ch = SEG7_REVERSE.get(low & 0x7F)
    if ch is not None:
        return ch
    return "?"


# --------------------------------------------------------------------------
# the display itself
# --------------------------------------------------------------------------
class _Cell:
    __slots__ = ("segments", "char", "from_code")

    def __init__(self) -> None:
        self.segments = 0
        self.char = " "
        self.from_code = False


class Display:
    """Multiplexed digit display with a latched segment memory.

    The board presents two different write paths to this object:

    * *raw* (what the real firmware does) - write a low segment byte to page
      0x82, a high byte to page 0x92, then the grid number to page 0xA2;
    * *character* (the 8255 path) - write a character/segment byte to PPI
      port A and the one-hot digit select to port B.
    """

    SEG_DP = SEG_DP

    def __init__(self, columns: int = 8, lines: int = 1) -> None:
        self._lock = threading.RLock()
        self.columns = int(columns)
        self.lines = int(lines)
        self.cells: List[_Cell] = [_Cell() for _ in range(self.columns * self.lines)]
        self.brightness = 0
        self.blank = True
        self.grid = -1
        self.lamps = [0, 0, 0]        # the three 0xA1 "bank" bits
        self.lamp_index = -1
        self.lamp_bank = -1
        self.lamp_byte = 0x00         # last raw byte written to the 0xA1 page
        self.writes = 0
        # pending anode bytes waiting for a grid select
        self.seg0 = 0
        self.seg1 = 0

    # ------------------------------------------------------------- geometry
    @property
    def digits(self) -> int:
        return self.columns * self.lines

    def _slot(self, index: int) -> Optional[_Cell]:
        index = int(index)
        if 0 <= index < len(self.cells):
            return self.cells[index]
        return None

    # ----------------------------------------------------------- write paths
    def write_digit_byte(self, index: int, value: int) -> None:
        """``0xA1<index> = value`` - the primitive behind ``FUN_CODE_810f``.

        ``FUN_CODE_810f(param_1, param_2)`` is decompiled as
        ``*(undefined1 *)CONCAT11(0xa1,param_2) = param_1;`` so the low address
        byte selects the digit and the data byte is the payload.  The payload
        is normally a segment byte, *except* that the firmware also writes the
        Gray-coded selector table ``AIHLDFBC`` (ROM 0x8266: 0x41 0x49 0x48 0x4C
        0x44 0x46 0x42 0x43) here, so a Gray selector with bit 4/5/6 set is
        treated as an annunciator/select write instead of as segments.  The
        heuristic is switchable through ``DISPLAY_A1_GRAY_IS_LAMP``.
        """
        self.writes += 1
        value &= 0xFF
        self.lamp_byte = value
        idx = gray_index(value)
        if DISPLAY_A1_GRAY_IS_LAMP and idx is not None and (value & 0x70) in (0x10, 0x20, 0x40):
            self.lamp_index = idx
            for i, bit in enumerate((0x10, 0x20, 0x40)):
                if value & bit:
                    self.lamp_bank = i
                    self.lamps[i] = idx + 1
            return
        if 0 <= int(index) < self.digits:
            cell = self._slot(index)
            if cell is not None:
                self._apply(cell, value, 0)
            self.grid = int(index)
            self.blank = False

    def write_segment_byte(self, index: int, value: int, high: bool = False) -> None:
        """Anode/segment byte write (pages 0x82 / 0x92 in the RE map).

        The value is only *latched*; the firmware writes both segment bytes and
        then the grid select, so the cell is committed by :meth:`select_grid`
        (ROM order: 0x92, 0x82, then 0xA2 - see 0x8309..0x831E).
        """
        self.writes += 1
        if high:
            self.seg1 = value & 0xFF
        else:
            self.seg0 = value & 0xFF
        self.blank = False

    def latch_segments(self, low: Optional[int] = None, high: Optional[int] = None) -> None:
        """Latch the shared segment byte(s) without touching any digit."""
        self.writes += 1
        if low is not None:
            self.seg0 = low & 0xFF
        if high is not None:
            self.seg1 = high & 0xFF

    def commit_grid(self, index: Optional[int] = None) -> None:
        """Show the latched segments on ``index`` (default: current grid)."""
        if index is None:
            index = self.grid
        if index is None or not (0 <= int(index) < self.digits):
            return
        cell = self._slot(index)
        if cell is not None:
            self._apply(cell, self.seg0, self.seg1)
        self.grid = int(index)
        self.blank = False

    def write_char(self, index: int, code: int) -> None:
        """A character code arrives for ``index`` (PPI port A, "chars" mode)."""
        self.writes += 1
        ch = self._decode_code(code)
        masks = segments_for(ch)
        self.seg0 = masks & 0xFF
        self.seg1 = (masks >> 8) & 0xFF
        cell = self._slot(index)
        if cell is not None:
            self._apply(cell, self.seg0, self.seg1, ch=ch)
        self.blank = False

    def set_segments_at(self, index: int, mask: int, ch: Optional[str] = None) -> None:
        """Raw 16-bit segment mask for one cell (used by tests)."""
        self.writes += 1
        self.seg0 = mask & 0xFF
        self.seg1 = (mask >> 8) & 0xFF
        cell = self._slot(index)
        if cell is not None:
            self._apply(cell, self.seg0, self.seg1, ch=ch)
        self.blank = False

    def _apply(self, cell: _Cell, low: int, high: int, ch: Optional[str] = None) -> None:
        cell.segments = ((high & 0xFF) << 8) | (low & 0xFF)
        cell.char = ch if ch is not None else char_for_segments(cell.segments)
        cell.from_code = ch is not None

    # ------------------------------------------------- grid / lamp selectors
    def select_grid(self, value: int, commit: bool = True) -> None:
        """0xA2xx / PPI port B: 0..7 = active digit, 8 = all grids off.

        ``commit`` decides whether the latched segment bytes are shown on the
        newly selected digit; the 8255 path turns it off when the firmware
        selects the digit *before* writing the segments.

        The ROM only ever emits ``R0 & 7`` (0..7) plus the blank code 8
        (ROM 0x82E1), so any other value - a BCD digit > 7 or garbage -
        blanks the grid instead of addressing a cell the firmware never
        lights.
        """
        value &= 0xFF
        if value > 7:
            self.grid = -1
            self.blank = True
            return
        self.grid = value
        self.blank = False
        if commit:
            cell = self._slot(value)
            if cell is not None:
                self._apply(cell, self.seg0, self.seg1)

    def write_lamp(self, value: int, low: Optional[int] = None) -> None:
        """0xA1xx write: bit7 preserved, bits 0..3 = gray digit, 4..6 = bank."""
        value &= 0xFF
        idx = gray_index(value)
        self.lamp_index = -1 if idx is None else idx
        for i in range(3):
            if value & (0x10 << i):
                self.lamps[i] = (self.lamps[i] or 0)
            else:
                self.lamps[i] = 0
        if self.lamp_index is not None and self.lamp_index >= 0:
            for i in range(3):
                if value & (0x10 << i):
                    self.lamps[i] = self.lamp_index + 1

    def lamp_readback(self) -> int:
        """What a MOVX read of the 0xA1 page returns (bit7 kept by firmware)."""
        base = 0x40
        if 0 <= self.lamp_index < 8:
            base |= _GRAY8[self.lamp_index]
        if self.lamps[0]:
            base |= 0x10
        if self.lamps[1]:
            base |= 0x20
        if self.lamps[2]:
            base |= 0x40
        return base | 0x80

    def set_brightness(self, value: int) -> None:
        self.brightness = value & 0xFF

    # --------------------------------------------------------------- control
    def clear(self) -> None:
        for cell in self.cells:
            cell.segments = 0
            cell.char = " "
            cell.from_code = False
        self.seg0 = self.seg1 = 0
        self.blank = True
        self.grid = -1
        self.lamps = [0, 0, 0]
        self.lamp_index = -1

    # ---------------------------------------------------------- contract API
    def text(self) -> str:
        """Current screen content, exactly ``columns * lines`` characters."""
        return "".join(cell.char for cell in self.cells)[: self.columns * self.lines]

    def cell_segments(self, index: int) -> int:
        """Raw *low* segment byte of a cell (0..255)."""
        cell = self._slot(index)
        return 0 if cell is None else cell.segments & 0xFF

    def cell_segments16(self, index: int) -> int:
        """Full 16-bit segment mask (extension, not part of the base contract)."""
        cell = self._slot(index)
        return 0 if cell is None else cell.segments & 0xFFFF

    def cell_char(self, index: int) -> str:
        cell = self._slot(index)
        return " " if cell is None else cell.char

    def annunciators(self) -> Dict[str, int]:
        """The three 0xA1 lamp banks (bit maps), for the UI's indicator row."""
        return {"bank1": self.lamps[0], "bank2": self.lamps[1], "bank3": self.lamps[2]}

    def glyph_rows(self, ch: str) -> List[str]:
        data = FONT5X7.get(ch)
        if data is None:
            data = FONT5X7.get(ch.upper(), _GLYPH_BOX)
        rows = []
        for r in range(7):
            rows.append("".join("#" if (data[c] >> r) & 1 else "." for c in range(5)))
        return rows

    def render_rows(self, scale: int = 1) -> List[str]:
        """``lines * 7`` rows of '#'/'.' - 5 columns per cell."""
        scale = max(1, int(scale))
        out: List[str] = []
        for line in range(self.lines):
            glyphs = [self.cells[line * self.columns + c] for c in range(self.columns)]
            rows = [self.glyph_rows(cell.char) for cell in glyphs]
            for r in range(7):
                text = "".join(row[r] for row in rows)
                text = "".join(ch * scale for ch in text)
                for _ in range(scale):
                    out.append(text)
        return out

    # ----------------------------------------------------------- diagnostics
    def _decode_code(self, code: int) -> str:
        code &= 0xFF
        ch = chr(code)
        if ch in SEG16 or ch in SEG7 or ch in FONT5X7:
            return ch
        return "?"

    def describe(self) -> str:
        return (f"display {self.columns}x{self.lines} '{self.text()}' "
                f"grid={self.grid} blank={self.blank}")

    def __repr__(self) -> str:      # pragma: no cover - debugging aid
        return f"Display({self.columns}x{self.lines}, text={self.text()!r})"

# --------------------------------------------------------------------------
# thread safety: main.py runs the CPU on a daemon thread while Tk reads
# display.text() / render_rows() from the main thread, so every public entry
# point takes the per-display re-entrant lock.
# --------------------------------------------------------------------------
def _locked(fn):
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)
    wrapper.__name__ = getattr(fn, "__name__", "wrapped")
    wrapper.__doc__ = fn.__doc__
    return wrapper


for _name in (
    "write_digit_byte", "write_segment_byte", "latch_segments", "commit_grid",
    "write_char", "set_segments_at", "select_grid", "write_lamp",
    "lamp_readback", "set_brightness", "clear", "text", "cell_segments",
    "cell_segments16", "cell_char", "annunciators", "glyph_rows",
    "render_rows", "describe",
):
    setattr(Display, _name, _locked(getattr(Display, _name)))