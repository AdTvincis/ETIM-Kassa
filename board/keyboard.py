"""The cash-register keyboard: an 8x8 scanned matrix.

Evidence from the firmware (see ``docs/hardware_analysis.md``):

* the scan runs inside the multiplex ISR at ROM ``0x838B``-``0x839D``::

      838B  MOV  A,R0
      838C  ANL  A,#07h        ; row = scan counter & 7
      838E  ORL  A,#30h
      8390  MOV  R1,A
      8391  MOV  1Ah,@R1       ; previous value, internal RAM 0x30+row
      8393  MOV  DPH,#91h
      8396  MOV  DPL,A
      8398  MOVX A,@DPTR        ; read the column byte of that row
      8399  CPL  A              ; columns are ACTIVE LOW

* detected keys are decoded and pushed into a ring buffer in external RAM
  (``0x83E0``: ``MOV DPH,#0Ch / MOV DPL,4Fh / MOVX @DPTR,A``) that the main
  program pops at ``0xDCD5``; ``CLR EX0`` around that access shows the machine
  raises INT0 for a key event.

The board exposes the matrix in two ways, both driving this one object:

* native: read XDATA ``0x9130 + row`` -> column byte (active low);
* 8255:   PPI port C -> column byte of the row selected by port B.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

__all__ = ["Keyboard", "KEYS", "LAYOUT", "ALIASES"]

# Row-major layout of the emulated keyboard, 8 columns per row.
# An empty string is a physically unpopulated position.
LAYOUT: List[List[str]] = [
    ["7", "8", "9", "X", "СУММА", "ОПЛ", "ITOG", "00"],
    ["4", "5", "6", "СКИДКА", "ОТМЕНА", "ВОЗВРАТ", "ПОДЫТОГ", "."],
    ["1", "2", "3", "КАССИР", "СЕРВИС", "РЕЖИМ", "ВВОД", "СБРОС"],
    ["0", "СТРЕЛКА_ВЛЕВО", "СТРЕЛКА_ВПРАВО", "ПРОБЕЛ", "ТАБ", "ЧЕК", "КС", "Z"],
    ["ПИТ", "", "", "", "", "", "", ""],
    ["", "", "", "", "", "", "", ""],
    ["", "", "", "", "", "", "", ""],
    ["", "", "", "", "", "", "", ""],
]

# Names accepted by press()/release() even though they are not physical keys.
ALIASES: Dict[str, str] = {
    "ИТОГ": "ITOG", "СУММ": "СУММА", "ОПЛАТА": "ОПЛ",
    "XREPORT": "КС", "ZREPORT": "Z", "FEED": "ПИТ", "RECEIPT": "ЧЕК",
    "ENTER": "ВВОД", "CLEAR": "СБРОС", "SUBTOTAL": "ПОДЫТОГ",
    "MODE": "РЕЖИМ", "SERVICE": "СЕРВИС", "CASHIER": "КАССИР",
    "DISCOUNT": "СКИДКА", "CANCEL": "ОТМЕНА", "PAY": "ОПЛ", "MULT": "X",
    "RETURN": "ВОЗВРАТ", "LEFT": "СТРЕЛКА_ВЛЕВО", "RIGHT": "СТРЕЛКА_ВПРАВО",
    "SPACE": "ПРОБЕЛ", "TAB": "ТАБ",
}

KEYS: List[str] = [name for row in LAYOUT for name in row if name]


class Keyboard:
    """An 8x8 matrix of normally-open contacts to ground.

    ``press`` closes a contact: the column bit of that (row, column) reads
    **0** while the row is driven.  Pressing a key that has no physical
    position is accepted and remembered so the UI never has to special-case
    the layout ("a contact into thin air", as the board contract allows).
    """

    rows = 8
    cols = 8
    #: a momentary tap() keeps the contact closed this many machine cycles
    tap_cycles = 40_000

    def __init__(self, layout: Optional[List[List[str]]] = None) -> None:
        self._lock = threading.RLock()
        self.layout = [list(r) for r in (layout if layout is not None else LAYOUT)]
        self._pos: Dict[str, Tuple[int, int]] = {}
        for r, row in enumerate(self.layout):
            for c, name in enumerate(row):
                if name:
                    self._pos.setdefault(name, (r, c))
        self.keys: List[str] = [n for row in self.layout for n in row if n]
        self._pressed: Dict[str, bool] = {name: False for name in self.keys}
        self._loose: Dict[str, bool] = {}
        self._tap_until: Dict[str, int] = {}
        # Кэш байтов колонок по строкам: шина читает page 0x91 десятки тысяч
        # раз за прогон (бенч: 24K чтений x 3.9us), а состояние меняется
        # только при нажатии/отпускании.  Обмен списка — атомарная замена
        # ссылки: читатель-поток получает либо старый список (одно устаревшее
        # значение, как у реального сканера), либо новый с None.
        self._col_cache: List[object] = [None] * self.rows
        # Имена клеток наперёд (с допаддингом пустыми строками до 8 колонок):
        # read_columns зовётся прошивкой на каждое сканирование матрицы, и
        # раньше каждый вызов платил 8 методов key_at() + IndexError-веток
        # (бенч: 6.1 us/call; см. tools/_bench.py).
        self._row_names: Tuple[Tuple[str, ...], ...] = tuple(
            tuple((row[c] if c < len(row) else "")
                  for c in range(self.cols))
            for row in self.layout
        )
        self.press_count = 0
        self.release_count = 0
        self.event_count = 0            # the board turns this into INT0

    # ------------------------------------------------------------- positions
    @staticmethod
    def _canonical(name: str) -> str:
        return ALIASES.get(name, name)

    def position(self, name: str) -> Optional[Tuple[int, int]]:
        return self._pos.get(self._canonical(name))

    def key_at(self, row: int, col: int) -> str:
        try:
            return self.layout[row][col]
        except IndexError:
            return ""

    def row_of(self, name: str) -> Optional[int]:
        pos = self.position(name)
        return None if pos is None else pos[0]

    def col_of(self, name: str) -> Optional[int]:
        pos = self.position(name)
        return None if pos is None else pos[1]

    # --------------------------------------------------------------- presses
    def press(self, name: str) -> None:
        name = self._canonical(name)
        if not name:
            return                         # empty key name: no contact exists
        with self._lock:
            if name in self._pressed:
                was, self._pressed[name] = self._pressed[name], True
            else:
                was, self._loose[name] = self._loose.get(name, False), True
            if not was:
                self.press_count += 1
                self.event_count += 1
        self._invalidate_columns()

    def release(self, name: str) -> None:
        name = self._canonical(name)
        if not name:
            return
        with self._lock:
            if name in self._pressed:
                was, self._pressed[name] = self._pressed[name], False
            else:
                was, self._loose[name] = self._loose.get(name, False), False
            if was:
                self.release_count += 1
                self.event_count += 1
        self._invalidate_columns()

    def tap(self, name: str) -> None:
        """Momentary press used by mouse clicks.

        The contact stays closed for :attr:`tap_cycles` machine cycles so a
        polling firmware cannot miss it; :meth:`tick` re-opens it.  The name
        is canonicalised *before* it is remembered, so tapping through an
        alias (``tap("ИТОГ")`` -> key ``ITOG``) expires on ``tick()`` instead
        of leaving the real key stuck down forever.
        """
        name = self._canonical(name)
        if not name:
            return
        self.press(name)
        with self._lock:
            self._tap_until[name] = self.tap_cycles

    # -------------------------------------------------------------- scanning
    def is_pressed(self, name: str) -> bool:
        name = self._canonical(name)
        with self._lock:
            if name in self._pressed:
                return bool(self._pressed[name])
            return bool(self._loose.get(name, False))

    def pressed_keys(self) -> List[str]:
        with self._lock:
            out = [n for n in self.keys if self._pressed.get(n)]
            out += [n for n, v in self._loose.items() if v]
            return out

    def any_pressed(self) -> bool:
        with self._lock:
            return any(self._pressed.values()) or any(self._loose.values())

    def _invalidate_columns(self) -> None:
        """Сбросить кэш колонок (вызывать при любом изменении нажатий)."""
        self._col_cache = [None] * self.rows

    def read_columns(self, row: int) -> int:
        """Column byte for ``row``: bit = 1 idle (pull-up), 0 = contact closed.

        Unpopulated positions are not connected to anything, so they stay high.

        Горячий путь: результат кэшируется до следующего изменения нажатий
        (см. :meth:`_invalidate_columns`).  Без замка: здесь только статический
        кортеж имён и ``dict.get`` — атомарные под GIL; прежний ``with`` стоил
        RLock-вход на каждое чтение страницы клавиатуры.
        """
        if row < 0 or row >= self.rows:
            return 0xFF
        cache = self._col_cache
        hit = cache[row]
        if hit is not None:
            return hit          # type: ignore[return-value]
        cols = 0
        names = self._row_names[row]
        pressed = self._pressed
        loose = self._loose
        for c, name in enumerate(names):
            if name and (pressed.get(name) or loose.get(name, False)):
                cols |= 1 << c
        value = (~cols) & 0xFF
        cache[row] = value
        return value

    def row_bits(self) -> int:
        """Bitmap of rows that currently have at least one key down."""
        bits = 0
        with self._lock:
            for name, (r, _c) in self._pos.items():
                if self._pressed.get(name):
                    bits |= 1 << r
            if any(self._loose.values()):
                bits |= 0xFF
        return bits & 0xFF

    def scan(self) -> List[Tuple[int, int, str]]:
        """Every closed contact as ``(row, column, name)``."""
        out: List[Tuple[int, int, str]] = []
        with self._lock:
            for name, (r, c) in self._pos.items():
                if self._pressed.get(name):
                    out.append((r, c, name))
        return sorted(out)

    # ------------------------------------------------------------------ time
    def tick(self, cycles: int) -> None:
        """Expire momentary taps so a mouse click behaves like a real press."""
        # Горячий путь: пока тапов нет (обычное состояние), замок не берём —
        # tick зовётся почти на каждой инструкции (tools/_bench.py).
        if not self._tap_until:
            return
        with self._lock:
            if not self._tap_until:
                return
            for name in list(self._tap_until):
                left = self._tap_until[name] - cycles
                if left <= 0:
                    del self._tap_until[name]
                    self._invalidate_columns()
                    if name in self._pressed:
                        self._pressed[name] = False
                    else:
                        self._loose[name] = False
                else:
                    self._tap_until[name] = left

    def clear(self) -> None:
        with self._lock:
            for n in self._pressed:
                self._pressed[n] = False
            for n in self._loose:
                self._loose[n] = False
            self._tap_until.clear()
        self._invalidate_columns()

    def describe(self) -> str:
        down = self.pressed_keys()
        return f"keyboard {self.rows}x{self.cols}, down={down or '-'}"

    def __repr__(self) -> str:      # pragma: no cover - debugging aid
        return f"Keyboard(keys={len(self.keys)}, down={self.pressed_keys()})"
