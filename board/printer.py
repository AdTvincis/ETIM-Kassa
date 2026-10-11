"""The receipt printer.

What the firmware actually does
-------------------------------
The character/needle output routine sits at records ``0x81E7``-``0x81F6``
of the hex file (CPU ``0x01E7``-``0x01F6`` after the base-0 rebase; the
addresses below are the record/Ghidra grid, see "Две сетки адресов" in
``docs/architecture.md``)::

    81E7  MOV  DPL,#31h
    81EA  MOV  A,#69h
    81EC  ADD  A,R6          ; R6 = pass 0..4  -> needle table 0x6931+R6*0x100
    81ED  MOV  DPH,A
    81EF  MOV  A,R5          ; R5 = character code
    81F0  MOVC A,@A+DPTR     ; fetch one needle column
    81F1  JZ   81C7h
    81F3  MOV  DPH,#81h
    81F6  MOVX @DPTR,A       ; -> printer data port (page 0x81)
    81F7  SETB P3.4          ; STROBE
    81F9  SETB 17h
    ...
    83F8  CLR  P3.4          ; STROBE released in the ISR epilogue (FUN_CODE_83f0)

So the native port is a write-only latch in XDATA page 0x81 and P3.4 is the
strobe, which the board turns into "print this byte".  The **five** needle
tables live at CPU ``0x6931 / 0x6A31 / 0x6B31 / 0x6C31 / 0x6D31`` (records
``0xE931..0xED31``) - **inside this dump**: every one of the 177 indexable
bytes is present and holds sparse needle-bit patterns, verified byte-wise.
(The old claim of "6 tables ending at 0x6E31, in the missing half" was wrong
twice over: pass ``R6 == 5`` takes a different branch - it writes ``0x55``
to the latch instead of fetching a table - and record ``0xEE31`` at CPU
``0x6E31`` holds code, ``PUSH PSW / ... / LCALL 6F22h``; see
``docs/hardware_evidence.md`` §1.1.)  Each entry is one column of vertical
needles, so the real machine is a dot-matrix printer.  ``PRINTER_DATA_IS_DOTS``
in the WIRING block selects between that raw-column interpretation and the
character-stream interpretation used by the demo firmware.

The 8255 can drive the same printer through port A while the control word is
0xA9 (group A mode 1, strobed output): /OBF on PC7, /ACK on PC6.

Character encoding
------------------
The firmware stores Russian text as a German-style transliteration.  It is
recoverable from the message table of the sibling dump ``winbond_w27c512-45``
(the ``.hex`` itself was removed from the project; its extracted strings are
kept in ``docs/rom_strings.txt``, section ``===== firmware/winbond_w27c512-45.hex
=====``, e.g. ``0000FD47 "kontrolxnaq lenta"``), e.g.::

    kontrolxnaq lenta   -> контрольная лента
    nali~nye w kasse    -> наличные в кассе
    wnesennaq summa     -> внесённая сумма
    fiskalxnyi ot~et    -> фискальный отчёт
    teku}ij itog        -> текущий итог
    wyru~ka             -> выручка

Letters confirmed by those strings are marked CONFIRMED; the five letters
that never appear (ж ш ъ э ю) are HYPOTHESIS (raw evidence:
``docs/rom_strings.txt``; the same table drives the display transliteration
in ``board/display.py``).
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional, Sequence

__all__ = ["ReceiptPrinter", "decode_byte", "decode_text", "ENCODE_TABLE"]

# --------------------------------------------------------------------------
# firmware byte -> readable Russian.  Letters proven by the message table:
# --------------------------------------------------------------------------
_CONFIRMED: Dict[str, str] = {
    "a": "а", "b": "б", "w": "в", "g": "г", "d": "д", "e": "е", "z": "з",
    "i": "и", "j": "й", "k": "к", "l": "л", "m": "м", "n": "н", "o": "о",
    "p": "п", "r": "р", "s": "с", "t": "т", "u": "у", "f": "ф", "h": "х",
    "c": "ц", "y": "ы", "x": "ь", "q": "я", "~": "ч", "}": "щ",
}
# Letters that do not occur anywhere in the recovered strings: best guess.
_SPECULATIVE: Dict[str, str] = {
    "v": "ж", "{": "ш", '"': "ъ", "'": "э", "|": "ю",
}
# Same for upper case (the printer font has both cases).  Punctuation-like
# keys ('~', '}', ...) are their own uppercase, so the case fold must be
# conditional or it would turn '~' into 'Ч' instead of 'ч'.
ENCODE_TABLE: Dict[str, str] = {}
for _src, _dst in {**_CONFIRMED, **_SPECULATIVE}.items():
    ENCODE_TABLE[_src] = _dst
    if _src.upper() != _src:
        ENCODE_TABLE[_src.upper()] = _dst.upper()

#: the reverse mapping, for generating firmware-encoded text (self-test, tools)
ENCODE_BACK: Dict[str, str] = {}
for _a, _b in ENCODE_TABLE.items():
    ENCODE_BACK.setdefault(_b, _a)
# The firmware's single byte for 'ч' ('~') has no separate upper case, so map
# the upper-case Cyrillic letters onto the same code instead of truncating
# ord() to 8 bits (which would silently invent a different character).
for _a, _b in ENCODE_TABLE.items():
    ENCODE_BACK.setdefault(_b.upper(), _a)
for _cyr, _lat in (("ё", "e"), ("Ё", "E")):
    ENCODE_BACK.setdefault(_cyr, _lat)


def decode_byte(value: int) -> str:
    """One firmware byte as readable text (digits/punctuation unchanged)."""
    ch = chr(value & 0xFF)
    return ENCODE_TABLE.get(ch, ch)


def decode_text(data: Sequence[int]) -> str:
    return "".join(decode_byte(b) for b in data)


def encode_text(text: str) -> bytes:
    """Readable Russian -> the firmware's transliterated byte stream."""
    out = bytearray()
    for ch in text:
        out.append(ord(ENCODE_BACK.get(ch, ch)) & 0xFF)
    return bytes(out)


class ReceiptPrinter:
    """A paper-tape printer, 40 columns, with the firmware's font encoding.

    Edge cases hardened during the board revision:

    * ``columns`` is clamped to at least 1, so a degenerate width (0/negative)
      can never produce one paper line per byte or an unbounded line;
    * ``0x00`` (NUL) is ignored like ``BEL``: C-strings end with it and a
      firmware that prints the terminator must not punch a hole into the tape;
    * ``0x0D`` (CR) is the carriage-return quirk: the head moves back to
      column 0 while the already-printed text **stays on the tape** - later
      bytes overwrite it in place, exactly like a real impact printer.  So
      ``"ABC\\rXY\\n"`` prints ``"XYC"`` and a plain CRLF stream
      (``"ABC\\r\\n"``) commits the intact line ``"ABC"`` instead of an
      empty one; CR with the head already at column 0 (and CR swallowed by
      ``ESC``) is a no-op;
    * :meth:`_render` decodes both text encodings that legitimately share the
      tape: pure-ASCII lines are the ROM's transliteration, lines with 8-bit
      bytes are KOI8-R (``tools/asm51.py``'s charset) instead of latin-1
      mojibake.
    """

    def __init__(self, columns: int = 40, decode: bool = True,
                 busy_cycles: int = 0) -> None:
        self._lock = threading.RLock()
        self.columns = max(1, int(columns))
        self.decode = bool(decode)
        self.busy_cycles = int(busy_cycles)
        self._busy = 0
        self._lines: List[bytes] = []          # completed lines, raw bytes
        self._line = bytearray()
        self._pos = 0                           # print head inside _line
        self._dot_lines: List[List[int]] = []  # only used in dot mode
        self._dot_columns: List[int] = []
        self.bytes_written = 0
        self.feed_lines = 0
        self.escape = False

    # --------------------------------------------------------------- printing
    def write_byte(self, value: int) -> None:
        value &= 0xFF
        with self._lock:
            self.bytes_written += 1
            self._busy = self.busy_cycles
            if self.escape:
                self.escape = False
                return
            if value == 0x1B:                     # ESC: swallow the next byte
                self.escape = True
                return
            if value == 0x0A:                     # LF
                self._newline()
                return
            if value == 0x0D:                     # CR - the 0x0D quirk:
                # the head returns to column 0 while the printed text stays
                # on the tape; following bytes overwrite it in place.  A CRLF
                # stream therefore commits the intact line ("ABC\r\n" prints
                # "ABC"), and "ABC\rXY\n" prints "XYC" - a real printer never
                # loses what it already struck.  CR with the head already at
                # column 0 is a no-op.
                self._pos = 0
                return
            if value == 0x08:                     # BS: head one column left
                if self._pos > 0:
                    if self._pos == len(self._line):
                        self._line.pop()          # at the end: erase the byte
                    self._pos -= 1
                return
            if value == 0x0C:                     # FF
                self._newline()
                self.feed(1)
                return
            if value == 0x09:                     # HT: head to the next ×8
                to_fill = (((self._pos // 8) + 1) * 8) - self._pos
                for _ in range(to_fill):
                    self._put(0x20)
                return
            if value == 0x07:                     # BEL
                return
            if value == 0x00:                     # NUL: string terminator /
                return                            # padding, never a column
            self._put(value)

    def _put(self, value: int) -> None:
        """Strike one column at the head position and advance it.

        Overwriting (head in the middle, after CR) keeps the rest of the line
        buffer; appending grows it.  Reaching the right margin commits the
        line exactly like the append-only model always did.
        """
        if self._pos < len(self._line):
            self._line[self._pos] = value
        else:
            self._line.append(value)
        self._pos += 1
        if self._pos >= self.columns:
            self._newline()

    def write_bytes(self, data: Sequence[int]) -> None:
        for b in data:
            self.write_byte(b)

    def write_column(self, value: int) -> None:
        """Dot-matrix mode: one column of vertical needles (native path)."""
        with self._lock:
            self.bytes_written += 1
            self._dot_columns.append(value & 0xFF)
            if len(self._dot_columns) >= self.columns * 5:
                self._dot_lines.append(self._dot_columns)
                self._dot_columns = []

    def newline(self) -> None:
        with self._lock:
            self._newline()

    def _newline(self) -> None:
        self._lines.append(bytes(self._line))
        self._line.clear()
        self._pos = 0                       # new line: head back to column 0

    def write_text(self, text: str) -> None:
        """Print readable text, encoding it back into the firmware's font."""
        self.write_bytes(encode_text(text))

    # ----------------------------------------------------------------- paper
    def feed(self, lines: int = 1) -> None:
        with self._lock:
            for _ in range(max(0, int(lines))):
                self._newline()
                self.feed_lines += 1

    def _render(self, raw: bytes) -> str:
        if not self.decode:
            return raw.decode("latin-1")
        # Two encodings legitimately share the tape:
        #  * the real ROM keeps Russian in German-style transliteration, which
        #    is pure ASCII ("nali~nye w kasse") - ENCODE_TABLE folds it;
        #  * 8-bit bytes cannot be transliteration (that table has no keys
        #    above 0x7F), so they belong to a KOI8-R stream - the charset
        #    tools/asm51.py and the stand-in demo use.  Decoding them as
        #    latin-1 is what produced the "Ëáóóá" mojibake, so route such
        #    lines through KOI8-R instead.
        if any(b >= 0x80 for b in raw):
            return raw.decode("koi8-r")
        return decode_text(raw)

    def paper(self) -> List[str]:
        """All printed lines, top to bottom (readable Russian)."""
        with self._lock:
            out = [self._render(line) for line in self._lines]
            if self._line:
                out.append(self._render(bytes(self._line)))
            elif self.feed_lines and out and out[-1] == "":
                pass
            return out

    def raw_paper(self) -> List[str]:
        """Same list but without the Cyrillic transliteration."""
        with self._lock:
            out = [line.decode("latin-1") for line in self._lines]
            if self._line:
                out.append(self._line.decode("latin-1"))
            return out

    def text(self) -> str:
        return "\n".join(self.paper())

    def dot_paper(self) -> List[str]:
        """Dot-matrix columns rendered as 8 row strings (native path)."""
        with self._lock:
            lines = list(self._dot_lines) + ([self._dot_columns] if self._dot_columns else [])
        out = []
        for cols in lines:
            for bit in range(8):
                out.append("".join("#" if (c >> bit) & 1 else "." for c in cols))
            out.append("")
        return out

    def clear(self) -> None:
        with self._lock:
            self._lines.clear()
            self._line.clear()
            self._pos = 0
            self._dot_lines.clear()
            self._dot_columns.clear()
            self.feed_lines = 0
            self.bytes_written = 0

    # ------------------------------------------------------------------ busy
    def is_busy(self) -> bool:
        """The board never wedges the firmware: busy clears on tick()."""
        with self._lock:
            return self._busy > 0

    def tick(self, cycles: int) -> None:
        # Горячий путь (зовётся почти на каждой инструкции): пока принтер
        # не занят, дешёвое чтение атомарно под GIL и замок не нужен.
        if not self._busy:
            return
        with self._lock:
            if self._busy:
                self._busy = max(0, self._busy - int(cycles))

    # ----------------------------------------------------------- diagnostics
    def describe(self) -> str:
        return (f"printer {self.columns} col, {len(self._lines)} lines, "
                f"{self.bytes_written} bytes, busy={self.is_busy()}")

    def __repr__(self) -> str:      # pragma: no cover - debugging aid
        return f"ReceiptPrinter({self.columns} col, {len(self.paper())} lines)"
