# -*- coding: utf-8 -*-
"""Индикатор кассы: чёрный «вакуумно-люминесцентный» экран на ``tk.Canvas``.

Виджет рисует содержимое ``board.display`` по контракту
``docs/board_contract.md``:

* основной путь — ``display.render_rows(scale=1)``: список строк из ``'#'``,
  ``'.'`` и ``' '`` (5 колонок x 7 строк на знакоместо), рисуем как точечную
  матрицу (как настоящее железо);
* запасной путь — только ``display.text()``: рисуем семисегментные знаки
  собственного рендерера (см. :data:`SEGMENTS`).

Оба пути дают одинаковые габариты знакоместа (5x7), поэтому геометрия
считается один раз.
"""

from __future__ import annotations

import tkinter as tk

from . import theme

__all__ = ["ScreenWidget", "SEGMENTS", "FONT_5X7", "render_segments"]

#: Ширина знакоместа в «точках» матрицы.
CELL_W = 5
#: Высота знакоместа в «точках» матрицы.
CELL_H = 7
#: Толщина сегмента в «точках» (семисегментный запасной рендерер).
SEG_T = 1

# --------------------------------------------------------------------------
# Точечно-матричный знакогенератор 5x7 (основной рендерер)
# --------------------------------------------------------------------------
# Каждый символ — 7 строк по 5 точек; любой непробельный символ = зажжённая
# точка. Набор рассчитан на экран кассы: цифры, знаки, латиница и кириллица.
# Семисегментная маска не может читаемо показать «ИТОГ»/«СУММА», поэтому
# основной путь — эта матрица (как в реальных ВЛИ-индикаторах).

FONT_5X7 = {
    " ": ("     ",) * 7,
    # --- цифры и знаки ---
    "0": (" ### ", "#   #", "#  ##", "# # #", "##  #", "#   #", " ### "),
    "1": ("  #  ", " ##  ", "  #  ", "  #  ", "  #  ", "  #  ", " ### "),
    "2": (" ### ", "#   #", "    #", "   # ", "  #  ", " #   ", "#####"),
    "3": ("#####", "   # ", "  #  ", "   # ", "    #", "#   #", " ### "),
    "4": ("   # ", "  ## ", " # # ", "#  # ", "#####", "   # ", "   # "),
    "5": ("#####", "#    ", "#### ", "    #", "    #", "#   #", " ### "),
    "6": ("  ## ", " #   ", "#    ", "#### ", "#   #", "#   #", " ### "),
    "7": ("#####", "    #", "   # ", "  #  ", " #   ", " #   ", " #   "),
    "8": (" ### ", "#   #", "#   #", " ### ", "#   #", "#   #", " ### "),
    "9": (" ### ", "#   #", "#   #", " ####", "    #", "   # ", " ##  "),
    ".": ("     ", "     ", "     ", "     ", "     ", " ##  ", " ##  "),
    ",": ("     ", "     ", "     ", "     ", "     ", " ##  ", " ##  "),
    "-": ("     ", "     ", "     ", " ### ", "     ", "     ", "     "),
    "_": ("     ", "     ", "     ", "     ", "     ", "     ", "#####"),
    "=": ("     ", " ### ", "     ", " ### ", "     ", "     ", "     "),
    "+": ("     ", "  #  ", "  #  ", "#####", "  #  ", "  #  ", "     "),
    "*": ("     ", "#   #", " # # ", "  #  ", " # # ", "#   #", "     "),
    "/": ("    #", "    #", "   # ", "  #  ", " #   ", "#    ", "#    "),
    ":": ("     ", " ##  ", " ##  ", "     ", " ##  ", " ##  ", "     "),
    ";": ("     ", " ##  ", " ##  ", "     ", " ##  ", " ##  ", " #   "),
    "!": ("  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "     ", "  #  "),
    "?": (" ### ", "#   #", "    #", "   # ", "  #  ", "     ", "  #  "),
    "'": ("  #  ", "  #  ", "     ", "     ", "     ", "     ", "     "),
    "(": ("   # ", "  #  ", " #   ", " #   ", " #   ", "  #  ", "   # "),
    ")": (" #   ", "  #  ", "   # ", "   # ", "   # ", "  #  ", " #   "),
    "%": ("##  #", "##  #", "   # ", "  #  ", " #   ", "#  ##", "#  ##"),
    "<": ("   # ", "  #  ", " #   ", "#    ", " #   ", "  #  ", "   # "),
    ">": (" #   ", "  #  ", "   # ", "    #", "   # ", "  #  ", " #   "),
    # --- латиница (заглавные; строчные приводятся к заглавным) ---
    "A": (" ### ", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"),
    "B": ("#### ", "#   #", "#   #", "#### ", "#   #", "#   #", "#### "),
    "C": (" ### ", "#   #", "#    ", "#    ", "#    ", "#   #", " ### "),
    "D": ("#### ", "#   #", "#   #", "#   #", "#   #", "#   #", "#### "),
    "E": ("#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#####"),
    "F": ("#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#    "),
    "G": (" ### ", "#   #", "#    ", "# ###", "#   #", "#   #", " ####"),
    "H": ("#   #", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"),
    "I": (" ### ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", " ### "),
    "J": ("    #", "    #", "    #", "    #", "#   #", "#   #", " ### "),
    "K": ("#   #", "#  # ", "# #  ", "##   ", "# #  ", "#  # ", "#   #"),
    "L": ("#    ", "#    ", "#    ", "#    ", "#    ", "#    ", "#####"),
    "M": ("#   #", "## ##", "# # #", "#   #", "#   #", "#   #", "#   #"),
    "N": ("#   #", "##  #", "# # #", "#  ##", "#   #", "#   #", "#   #"),
    "O": (" ### ", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "),
    "P": ("#### ", "#   #", "#   #", "#### ", "#    ", "#    ", "#    "),
    "Q": (" ### ", "#   #", "#   #", "#   #", "# # #", "#  # ", " ## #"),
    "R": ("#### ", "#   #", "#   #", "#### ", "# #  ", "#  # ", "#   #"),
    "S": (" ####", "#    ", "#    ", " ### ", "    #", "    #", "#### "),
    "T": ("#####", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  "),
    "U": ("#   #", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "),
    "V": ("#   #", "#   #", "#   #", "#   #", "#   #", " # # ", "  #  "),
    "W": ("#   #", "#   #", "#   #", "# # #", "# # #", "## ##", "#   #"),
    "X": ("#   #", "#   #", " # # ", "  #  ", " # # ", "#   #", "#   #"),
    "Y": ("#   #", "#   #", " # # ", "  #  ", "  #  ", "  #  ", "  #  "),
    "Z": ("#####", "    #", "   # ", "  #  ", " #   ", "#    ", "#####"),
    # --- кириллица ---
    "А": (" ### ", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"),
    "Б": ("#### ", "#    ", "#    ", "#### ", "#   #", "#   #", "#### "),
    "В": ("#### ", "#   #", "#   #", "#### ", "#   #", "#   #", "#### "),
    "Г": ("#####", "#    ", "#    ", "#    ", "#    ", "#    ", "#    "),
    "Д": ("  ###", " #  #", " #  #", " #  #", " #  #", "#####", "#   #"),
    "Е": ("#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#####"),
    "Ё": ("#   #", "#####", "#    ", "#### ", "#    ", "#    ", "#####"),
    "Ж": ("# # #", "# # #", "# # #", "#####", "# # #", "# # #", "# # #"),
    "З": (" ### ", "#   #", "    #", "  ## ", "    #", "#   #", " ### "),
    "И": ("#   #", "#   #", "#  ##", "# # #", "##  #", "#   #", "#   #"),
    "Й": (" # # ", "#####", "#  ##", "# # #", "##  #", "#   #", "#   #"),
    "К": ("#   #", "#  # ", "# #  ", "##   ", "# #  ", "#  # ", "#   #"),
    "Л": ("  ###", " #  #", " #  #", " #  #", " #  #", " #  #", "#   #"),
    "М": ("#   #", "## ##", "# # #", "#   #", "#   #", "#   #", "#   #"),
    "Н": ("#   #", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"),
    "О": (" ### ", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "),
    "П": ("#####", "#   #", "#   #", "#   #", "#   #", "#   #", "#   #"),
    "Р": ("#### ", "#   #", "#   #", "#### ", "#    ", "#    ", "#    "),
    "С": (" ### ", "#   #", "#    ", "#    ", "#    ", "#   #", " ### "),
    "Т": ("#####", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  "),
    "У": ("#   #", "#   #", "#   #", " ####", "    #", "   # ", " ##  "),
    "Ф": ("  #  ", " ### ", "# # #", "# # #", "# # #", " ### ", "  #  "),
    "Х": ("#   #", "#   #", " # # ", "  #  ", " # # ", "#   #", "#   #"),
    "Ц": ("#  # ", "#  # ", "#  # ", "#  # ", "#  # ", "#####", "    #"),
    "Ч": ("#   #", "#   #", "#   #", " ####", "    #", "    #", "    #"),
    "Ш": ("# # #", "# # #", "# # #", "# # #", "# # #", "# # #", "#####"),
    "Щ": ("# # #", "# # #", "# # #", "# # #", "# # #", "#####", "    #"),
    "Ъ": ("##   ", " #   ", " #   ", " ### ", " #  #", " #  #", " ### "),
    "Ы": ("#   #", "#   #", "#   #", "# # #", "#  ##", "#   #", "#   #"),
    "Ь": ("#    ", "#    ", "#    ", "#### ", "#   #", "#   #", "#### "),
    "Э": (" ### ", "#   #", "    #", "  ###", "    #", "#   #", " ### "),
    "Ю": ("#  # ", "# # #", "# # #", "### #", "# # #", "# # #", "#  # "),
    "Я": (" ####", "#   #", "#   #", " ####", "  # #", " #  #", "#   #"),
}

# --------------------------------------------------------------------------
# Семисегментный рендерер (запасной путь, когда render_rows() недоступен)
# --------------------------------------------------------------------------
#
#            a
#          f   b
#            g
#          e   c
#            d
#
# Бит 0 = a, 1 = b, ... 6 = g. Совпадает с типовой маской знакоместа.

_SEG = {
    "a": 1 << 0,
    "b": 1 << 1,
    "c": 1 << 2,
    "d": 1 << 3,
    "e": 1 << 4,
    "f": 1 << 5,
    "g": 1 << 6,
}


def _mk(*letters: str) -> int:
    mask = 0
    for letter in letters:
        mask |= _SEG[letter]
    return mask


SEGMENTS: dict[str, int] = {
    " ": 0,
    "-": _mk("g"),
    "_": _mk("d"),
    "=": _mk("d", "g"),
    "0": _mk("a", "b", "c", "d", "e", "f"),
    "1": _mk("b", "c"),
    "2": _mk("a", "b", "g", "e", "d"),
    "3": _mk("a", "b", "g", "c", "d"),
    "4": _mk("f", "g", "b", "c"),
    "5": _mk("a", "f", "g", "c", "d"),
    "6": _mk("a", "f", "g", "e", "c", "d"),
    "7": _mk("a", "b", "c"),
    "8": _mk("a", "b", "c", "d", "e", "f", "g"),
    "9": _mk("a", "b", "c", "d", "f", "g"),
    ".": _mk("c") | (1 << 7),   # точка — отдельный «сегмент» dp
    ",": _mk("c") | (1 << 7),
    ":": _mk("c") | (1 << 7),
    "'": _mk("b"),
    # латиница
    "A": _mk("a", "b", "c", "e", "f", "g"),
    "B": _mk("c", "d", "e", "f", "g"),
    "C": _mk("a", "d", "e", "f"),
    "D": _mk("b", "c", "d", "e", "g"),
    "E": _mk("a", "d", "e", "f", "g"),
    "F": _mk("a", "e", "f", "g"),
    "G": _mk("a", "c", "d", "e", "f"),
    "H": _mk("b", "c", "e", "f", "g"),
    "I": _mk("b", "c"),
    "J": _mk("b", "c", "d", "e"),
    "K": _mk("e", "f", "g"),
    "L": _mk("d", "e", "f"),
    "N": _mk("a", "b", "c", "e", "f"),
    "O": _mk("a", "b", "c", "d", "e", "f"),
    "P": _mk("a", "b", "e", "f", "g"),
    "Q": _mk("a", "b", "c", "f", "g"),
    "R": _mk("e", "g"),
    "S": _mk("a", "c", "d", "f", "g"),
    "T": _mk("d", "e", "f", "g"),
    "U": _mk("b", "c", "d", "e", "f"),
    "V": _mk("c", "d", "e"),
    "Y": _mk("b", "c", "d", "f", "g"),
    "Z": _mk("a", "b", "d", "e", "g"),
    # кириллица (семисегментное приближение, как на реальных ценниках)
    "А": _mk("a", "b", "c", "e", "f", "g"),
    "Б": _mk("c", "d", "e", "f", "g"),
    "В": _mk("c", "d", "e", "f", "g"),
    "Г": _mk("a", "e", "f"),
    "Д": _mk("b", "c", "d", "e", "g"),
    "Е": _mk("a", "d", "e", "f", "g"),
    "Ж": _mk("b", "c", "e", "f", "g"),
    "З": _mk("a", "b", "c", "d", "g"),
    "И": _mk("b", "c", "e", "f"),
    "Й": _mk("b", "c", "e", "f"),
    "К": _mk("e", "f", "g"),
    "Л": _mk("c", "e", "f"),
    "М": _mk("a", "c", "e"),
    "Н": _mk("b", "c", "e", "f", "g"),
    "О": _mk("a", "b", "c", "d", "e", "f"),
    "П": _mk("a", "b", "e", "f"),
    "Р": _mk("a", "b", "e", "f", "g"),
    "С": _mk("a", "d", "e", "f"),
    "Т": _mk("d", "e", "f", "g"),
    "У": _mk("b", "c", "d", "f", "g"),
    "Ф": _mk("a", "e", "f", "g"),
    "Х": _mk("b", "c", "e", "f", "g"),
    "Ц": _mk("b", "c", "d", "e", "f"),
    "Ч": _mk("b", "c", "f", "g"),
    "Ш": _mk("b", "c", "d", "e", "f"),
    "Щ": _mk("b", "c", "d", "e", "f"),
    "Ъ": _mk("a", "b", "c", "d", "f"),
    "Ы": _mk("b", "c", "d", "f", "g"),
    "Ь": _mk("c", "d", "e", "f", "g"),
    "Э": _mk("a", "b", "c", "d", "e", "g"),
    "Ю": _mk("b", "c", "d", "e", "f", "g"),
    "Я": _mk("b", "c", "d", "f", "g"),
}


def _build_glyphs() -> dict:
    """Собрать знакоместа 5x7: настоящий точечно-матричный знакогенератор.

    Семисегментная маска не способна читаемо показать кириллицу («ИТОГ»,
    «СУММА», «СБРОС»), поэтому основной знакогенератор — матрица 5x7, как в
    реальных ВЛИ-индикаторах касс. Сначала берём собственноручный знакогенератор
    :data:`FONT_5X7`, затем (для символов, которых в нём нет) — семисегментную
    аппроксимацию из :data:`SEGMENTS`.
    """
    glyphs: dict = {}

    def bits_from_rows(rows) -> tuple:
        out = []
        for row in rows:
            value = 0
            for x in range(CELL_W):
                if x < len(row) and row[x] != " ":
                    value |= 1 << (CELL_W - 1 - x)
            out.append(value)
        while len(out) < CELL_H:
            out.append(0)
        return tuple(out[:CELL_H])

    for char, rows in FONT_5X7.items():
        glyphs[char] = bits_from_rows(rows)

    # Семисегментный запасной вариант (символы вне точечного знакогенератора).
    for char, mask in SEGMENTS.items():
        if char in glyphs:
            continue
        grid = [0] * CELL_H
        if mask & _SEG["a"]:
            grid[0] |= 0b01110
        if mask & _SEG["g"]:
            grid[3] |= 0b01110
        if mask & _SEG["d"]:
            grid[6] |= 0b01110
        if mask & _SEG["f"]:
            grid[1] |= 0b10000
            grid[2] |= 0b10000
        if mask & _SEG["b"]:
            grid[1] |= 0b00001
            grid[2] |= 0b00001
        if mask & _SEG["e"]:
            grid[4] |= 0b10000
            grid[5] |= 0b10000
        if mask & _SEG["c"]:
            grid[4] |= 0b00001
            grid[5] |= 0b00001
        if mask & (1 << 7):  # десятичная точка в правом нижнем углу
            grid[CELL_H - 1] |= 0b00001
        glyphs[char] = tuple(grid)
    return glyphs


#: Битовые карты знакомест: строка -> 5 бит (старший бит — левая точка).
_GLYPHS: dict = _build_glyphs()

#: Знакоместо для неизвестного символа — пустое (экран не «врёт»).
_BLANK: tuple = (0,) * CELL_H


def render_segments(char: str) -> list[str]:
    """Отрисовать один символ как ``CELL_H`` строк по ``CELL_W`` (``'#'``/``' '``).

    Формат совпадает с ``display.render_rows()``. Неизвестный символ даёт
    пустое знакоместо, чтобы на экране не появлялось мусора.
    """
    if not char:
        bits = _BLANK
    else:
        bits = _GLYPHS.get(char)
        if bits is None:
            bits = _GLYPHS.get(char.upper(), _BLANK)
    return ["".join("#" if bits[y] & (1 << (CELL_W - 1 - x)) else " "
                    for x in range(CELL_W)) for y in range(CELL_H)]


class ScreenWidget(tk.Frame):
    """Экран кассы: чёрное поле с зелёными знаками + рамка корпуса.

    Публичные методы:

    * :meth:`set_text` — показать готовый текст (используется, если у платы
      есть только ``display.text()``);
    * :meth:`set_rows` — показать строки ``'#'/'.'/' '`` из
      ``display.render_rows()``;
    * :meth:`update_from_display` — обновить из ``display`` целиком (с
      автоматическим выбором пути).
    """

    BG = theme.COLORS["screen_bg"]

    #: Размер «точки» матрицы по умолчанию (px). Знакоместо = 5x7 точек.
    DEFAULT_CELL = 16
    #: Минимальный размер точки внизу/сверху (когда экран ужимают).
    MIN_CELL = 2

    def __init__(self, parent, columns: int = 20, lines: int = 1, cell: int | None = None, **kwargs):
        super().__init__(
            parent,
            bg=theme.COLORS["screen_frame"],
            relief="raised",
            bd=4,
            highlightthickness=0,
            **kwargs,
        )
        self.columns = max(1, int(columns))
        self.lines = max(1, int(lines))
        cell = self.DEFAULT_CELL if cell is None else max(self.MIN_CELL, int(cell))
        #: Размер точки по горизонтали и по вертикали. Отдельные величины
        #: позволяют занять экраном всю доступную площадь (как у железного
        #: индикатора), поэтому это просто прямоугольная точка.
        self.cell_w = cell
        self.cell_h = cell
        self._cell_key = cell

        self._text = ""
        self._rows: list[str] | None = None
        self._last_key = None

        inner = tk.Frame(self, bg=theme.COLORS["screen_frame"])
        inner.pack(fill="both", expand=True, padx=3, pady=3)

        width, height = self._canvas_size()
        self.canvas = tk.Canvas(
            inner,
            width=width,
            height=height,
            bg=self.BG,
            highlightthickness=0,
            bd=0,
        )
        # Канву НЕ растягиваем на всю панель: экран индикатора — ровно тот
        # прямоугольник, что нарисован (габариты = _canvas_size()), и он стоит
        # по центру панели. Иначе справа от зажжённых точек оставалась бы
        # «мертвая» полоса фона без сетки.
        self.canvas.pack()

        self._caption = tk.Label(
            self,
            text="ИНДИКАТОР",
            bg=theme.COLORS["screen_frame"],
            fg=theme.COLORS["screen_caption"],
            font=theme.FONTS["label_small"],
        )
        self._caption.pack(side="bottom", pady=(0, 1))

        self._last_key = None
        self.redraw()

    # -- геометрия ---------------------------------------------------------

    @staticmethod
    def _fit_cell(columns: int, max_width: int, lines: int = 1, max_height: int = 190) -> int:
        """Подобрать размер «точки» так, чтобы канва влезла в бюджет.

        Ширина канвы = ``columns * 6 * cell + 2 * cell`` (5 точек знака + 1
        зазор), высота = ``lines * 8 * cell + 2 * cell``. Ограничиваем и по
        ширине, и по высоте, иначе матрица уезжает за пределы канвы.
        """
        columns = max(1, int(columns))
        lines = max(1, int(lines))
        by_width = max_width // (columns * (CELL_W + 1)) if max_width else ScreenWidget.DEFAULT_CELL
        by_height = max_height // (lines * (CELL_H + 1)) if max_height else ScreenWidget.DEFAULT_CELL
        cell = min(by_width, by_height)
        return max(3, min(ScreenWidget.DEFAULT_CELL, int(cell)))

    @property
    def cell(self) -> int:
        """Единый размер точки (для тестов и простых вызовов)."""
        return max(self.cell_w, self.cell_h)

    @property
    def cell_x(self) -> int:
        return self.cell_w

    @property
    def cell_y(self) -> int:
        return self.cell_h

    def _canvas_size(self) -> tuple[int, int]:
        width = 2 * self.cell_w + self.columns * (CELL_W + 1) * self.cell_w
        height = 2 * self.cell_h + self.lines * (CELL_H + 1) * self.cell_h
        return width, height

    def _fit_cells(self, max_width: int, max_height: int) -> tuple:
        """Подобрать (cell_w, cell_h) под доступный прямоугольник.

        Точка может быть прямоугольной: так экран занимает всю площадь, как
        железный индикатор. Но если доступной высоты заметно больше, чем нужно
        по ширине, точку по вертикали не раздуваем сильнее чем в 1.6 раза,
        чтобы знаки не растягивались в столбики.
        """
        columns = max(1, self.columns)
        lines = max(1, self.lines)
        cell_w = int(max_width) // (columns * (CELL_W + 1)) if max_width else self.DEFAULT_CELL
        cell_h = int(max_height) // (lines * (CELL_H + 1)) if max_height else self.DEFAULT_CELL
        cell_w = max(self.MIN_CELL, min(self.DEFAULT_CELL, cell_w))
        cell_h = max(self.MIN_CELL, min(self.DEFAULT_CELL, cell_h))
        if cell_h > cell_w * 1.6:
            cell_h = max(self.MIN_CELL, int(cell_w * 1.6))
        return cell_w, cell_h

    def set_geometry(self, columns=None, lines=None, cell=None, max_width=None, max_height=None) -> None:
        """Перестроить размер экрана (например, под размер окна)."""
        if columns is not None:
            self.columns = max(1, int(columns))
        if lines is not None:
            self.lines = max(1, int(lines))
        if cell is not None:
            value = max(self.MIN_CELL, int(cell))
            self.cell_w = self.cell_h = value
            self._cell_key = value
        elif max_width or max_height:
            self.cell_w, self.cell_h = self._fit_cells(
                max_width or 0, max_height or 0
            )
            self._cell_key = None
        width, height = self._canvas_size()
        self.canvas.configure(width=width, height=height)
        self._last_key = None
        self.redraw()

    def fit_to_width(self, max_width: int, max_height: int = 190) -> None:
        """Вписать экран в доступный прямоугольник (вызывается при resize)."""
        if (not max_width or max_width < 40) and (not max_height or max_height < 40):
            return
        cell_w, cell_h = self._fit_cells(int(max_width or 0), int(max_height or 0))
        if (cell_w, cell_h) != (self.cell_w, self.cell_h):
            self.cell_w, self.cell_h = cell_w, cell_h
            self._cell_key = None
            width, height = self._canvas_size()
            self.canvas.configure(width=width, height=height)
            self._last_key = None
            self.redraw()

    # -- данные ------------------------------------------------------------

    def set_text(self, text) -> None:
        """Показать текст как семисегментные знаки."""
        self._text = "" if text is None else str(text)
        self._rows = None
        self.redraw()

    def set_rows(self, rows) -> None:
        """Показать точечную матрицу (список строк ``'#'/'.'/' '``)."""
        if isinstance(rows, str):
            rows = rows.splitlines()
        self._rows = [str(r) for r in rows] if rows is not None else None
        self.redraw()

    def update_from_display(self, display) -> tuple:
        """Обновить экран из объекта ``display`` по контракту платы.

        Никогда не бросает исключение: при любой проблеме оставляет последнее
        удачное изображение.

        Возвращает ``(обновлено, последняя_ошибка)``: хост может показать
        ошибку платы, не опрашивая ``display`` второй раз.
        """
        if display is None:
            return False, None
        last_error = None
        try:
            rows = self._read_render_rows(display)
        except Exception as exc:  # страховка: _read_render_rows всё ловит сам
            rows = None
            last_error = exc
        if rows is not None:
            self.set_rows(rows)
            return True, last_error
        try:
            text = display.text()
        except Exception as exc:
            return False, exc
        if text is None:
            return False, last_error
        self.set_text(text)
        return True, last_error

    def _read_render_rows(self, display) -> list[str] | None:
        """Аккуратно прочитать ``render_rows(scale=1)`` и проверить формат.

        Плата обязана вернуть ``lines*7`` строк по 5 символов на знакоместо.
        Если формат не совпадает (или метод падает) — возвращаем ``None``,
        и экран рисуется запасным семисегментным рендерером из ``text()``.
        """
        render = getattr(display, "render_rows", None)
        if not callable(render):
            return None
        try:
            raw = render(1)
        except Exception:
            try:
                raw = render()
            except Exception:
                return None
        if isinstance(raw, str):
            raw = raw.splitlines()
        if not isinstance(raw, (list, tuple)) or not raw:
            return None
        rows = [str(r) for r in raw]
        # Приводим к числу знакомест экрана (не доверяем плате в мелочах).
        expected = self.lines * CELL_H
        if len(rows) < expected:
            return None
        rows = rows[:expected]
        per_line = self.columns * CELL_W
        normalised: list[str] = []
        for row in rows:
            if not row:
                row = " " * per_line
            if len(row) < per_line:
                row = row + " " * (per_line - len(row))
            normalised.append(row[:per_line])
        # Пустая матрица (всё пробелы) допустима, но бесполезна: тогда лучше
        # показать текст, если он есть.
        if not any(ch not in " ." for ch in "".join(normalised)):
            try:
                text = display.text()
            except Exception:
                text = None
            if text and str(text).strip():
                return None
        return normalised

    # -- отрисовка ---------------------------------------------------------

    def redraw(self) -> None:
        """Полностью перерисовать экран (дёшево: рисуем только при изменении)."""
        state = self._matrix()
        key = (self.columns, self.lines, self.cell_w, self.cell_h, tuple(state))
        if key == self._last_key:
            return
        self._last_key = key

        canvas = self.canvas
        canvas.delete("all")
        # Габариты берём из той же формулы, что и _canvas_size(): winfo_req*
        # во время configure может отставать, и матрица уехала бы за канву.
        width, height = self._canvas_size()

        # лёгкое «свечение люминофора» подложкой
        canvas.create_rectangle(0, 0, width, height, fill=self.BG, outline="")

        x0 = self.cell_w
        y0 = self.cell_h
        matrix = state
        colour = theme.COLORS["screen_on"]
        # '.' — ТЁМНАЯ точка (конвенция проекта: render_rows отдаёт '#'/'.'), и
        # раньше она ошибочно входила в набор: ch in lit было истинно для
        # каждой точки => на канве рисовались ВСЕ 280 пикселей и экран выглядел
        # «целиком заряженным», без различимых цифр.  Горят только '#', '*', '●', '□'.
        lit = "#*●□"
        # matrix: lines * CELL_H строк, по columns * CELL_W точек в каждой.
        cell_w = self.cell_w
        cell_h = self.cell_h
        for row_index, row in enumerate(matrix):
            li = row_index // CELL_H          # номер строки индикатора
            if li >= self.lines:
                break
            y = row_index % CELL_H            # строка точек внутри знакоместа
            py = y0 + li * (CELL_H + 1) * cell_h + y * cell_h
            for x, ch in enumerate(row):
                if ch in lit:
                    # Между знакоместами рисуем пустой столбец точек — иначе
                    # содержимое уезжает влево, а в _canvas_size() зазор уже
                    # заложен (columns * (CELL_W + 1) * cell).
                    px = x0 + (x + x // CELL_W) * cell_w
                    canvas.create_rectangle(
                        px, py, px + cell_w, py + cell_h, fill=colour, outline=""
                    )
        self._draw_grid_hint()
        canvas.configure(scrollregion=(0, 0, width, height))

    def _SEG_COLOUR(self, x: int, y: int) -> str:  # noqa: N802 - простая палитра
        return theme.COLORS["screen_on"]

    def _draw_grid_hint(self) -> None:
        """Незажжённые точки матрицы — чтобы экран читался как настоящее табло.

        Рисуем их позади зажжённых (``tag_lower``); каждая точка — маленький
        квадратик тёмно-зелёного цвета, как негорящая точка реальной матрицы.
        """
        canvas = self.canvas
        cell_w = self.cell_w
        cell_h = self.cell_h
        dim = theme.COLORS["screen_dim"]
        dot_w = max(1, cell_w - max(1, cell_w // 4))
        dot_h = max(1, cell_h - max(1, cell_h // 4))
        pad_w = (cell_w - dot_w) // 2
        pad_h = (cell_h - dot_h) // 2
        for li in range(self.lines):
            top = cell_h + li * (CELL_H + 1) * cell_h
            for y in range(CELL_H):
                for x in range(self.columns * CELL_W):
                    # тот же зазор между знакоместами, что и в redraw()
                    left = cell_w + (x + x // CELL_W) * cell_w + pad_w
                    upper = top + y * cell_h + pad_h
                    canvas.create_rectangle(
                        left, upper, left + dot_w, upper + dot_h, fill=dim, outline=""
                    )
        try:
            canvas.tag_lower("all")
        except tk.TclError:
            pass

    def _matrix(self) -> list[str]:
        """Матрица ``'#'/' '`` по строкам экрана (``lines * CELL_H`` строк)."""
        rows = self._rows
        if rows is None:
            if not self._text:
                rows = [" " * (self.columns * CELL_W)] * (self.lines * CELL_H)
            else:
                lines = self._split_text(self._text)
                rows = []
                for line in lines:
                    for y in range(CELL_H):
                        rows.append("".join(render_segments(ch)[y] for ch in line))
        per_line = self.columns * CELL_W
        blank = " " * per_line
        fixed = [row[:per_line].ljust(per_line) for row in rows]
        # Ровно lines*CELL_H строк: лишнее отбрасываем, нехватку добиваем
        # пустыми строками — матрица обязана иметь форму экрана даже при
        # «короткой» или пустой ленте от платы.
        if len(fixed) < self.lines * CELL_H:
            fixed += [blank] * (self.lines * CELL_H - len(fixed))
        return fixed[: self.lines * CELL_H]

    def _split_text(self, text: str) -> list[str]:
        parts = str(text).split("\n")
        if len(parts) < self.lines:
            parts += [""] * (self.lines - len(parts))
        return [p.ljust(self.columns)[: self.columns] for p in parts[: self.lines]]
