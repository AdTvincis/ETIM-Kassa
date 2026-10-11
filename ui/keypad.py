# -*- coding: utf-8 -*-
"""Панель клавиатуры кассы: классические объёмные кнопки разных цветов.

Раскладка строится **по** ``keyboard.keys`` (источник правды — контракт
``docs/board_contract.md``). Кнопка, которой нет в ``keys``, не создаётся;
лишние клавиши из ``keys`` попадают в служебный ряд, ничего не теряется.

Мышь: клик -> ``keyboard.tap(name)``.
Физическая клавиатура: ``<KeyPress>``/``<KeyRelease>`` -> ``press``/``release``.
"""

from __future__ import annotations

import tkinter as tk

from . import theme

__all__ = ["KeypadFrame", "KEY_DEFS", "build_layout", "KEY_COLOURS", "KEY_LABELS"]

# --------------------------------------------------------------------------
# Соответствие «имя клавиши из keys» -> (подпись, цвет, размер, ряд)
# --------------------------------------------------------------------------

#: Человеческие подписи для служебных клавиш.
KEY_LABELS = {
    "СУММА": "СУММА",
    "SUMM": "СУММА",
    "ОПЛ": "ОПЛ",
    "PAY": "ОПЛ",
    "X": "X",
    "MULT": "X",
    "ITOG": "ИТОГ",
    "ИТОГ": "ИТОГ",
    "ОТМЕНА": "ОТМЕНА",
    "CANCEL": "ОТМЕНА",
    "ВОЗВРАТ": "ВОЗВРАТ",
    "RETURN": "ВОЗВРАТ",
    "СКИДКА": "СКИДКА",
    "DISCOUNT": "СКИДКА",
    "КАССИР": "КАССИР",
    "CASHIER": "КАССИР",
    "СЕРВИС": "СЕРВИС",
    "SERVICE": "СЕРВИС",
    "РЕЖИМ": "РЕЖИМ",
    "MODE": "РЕЖИМ",
    "ВВОД": "ВВОД",
    "ENTER": "ВВОД",
    "СБРОС": "СБРОС",
    "CLEAR": "СБРОС",
    "ПОДЫТОГ": "ПОДЫТОГ",
    "SUBTOTAL": "ПОДЫТОГ",
    "ЧЕК": "ЧЕК",
    "RECEIPT": "ЧЕК",
    "КС": "КС",
    "XREPORT": "КС",
    "Z": "Z",
    "ZREPORT": "Z",
    "ПИТ": "ПИТ",
    "FEED": "ПИТ",
    "СТРЕЛКА_ВЛЕВО": "\u25c0",
    "LEFT": "\u25c0",
    "СТРЕЛКА_ВПРАВО": "\u25b6",
    "RIGHT": "\u25b6",
    "ПРОБЕЛ": "ПРОБЕЛ",
    "SPACE": "ПРОБЕЛ",
    "ТАБ": "ТАБ",
    "TAB": "ТАБ",
}

#: Цвет кнопки по имени клавиши.
KEY_COLOURS = {
    "СУММА": "arithmetic", "SUMM": "arithmetic",
    "ОПЛ": "arithmetic", "PAY": "arithmetic",
    "X": "arithmetic", "MULT": "arithmetic",
    "ПОДЫТОГ": "arithmetic", "SUBTOTAL": "arithmetic",
    "ИТОГ": "service", "ITOG": "service",
    "ВВОД": "service", "ENTER": "service",
    "ВОЗВРАТ": "service", "RETURN": "service",
    "СКИДКА": "service", "DISCOUNT": "service",
    "ОТМЕНА": "danger", "CANCEL": "danger",
    "СБРОС": "danger", "CLEAR": "danger",
    "КАССИР": "mode", "CASHIER": "mode",
    "СЕРВИС": "mode", "SERVICE": "mode",
    "РЕЖИМ": "mode", "MODE": "mode",
    "ЧЕК": "printer", "RECEIPT": "printer",
    "КС": "printer", "XREPORT": "printer",
    "Z": "printer", "ZREPORT": "printer",
    "ПИТ": "printer", "FEED": "printer",
}

#: Раскладка: цифровой блок 4x3 (+ «00» и «.»), затем правая колонка.
_NUM_ROWS = [["7", "8", "9"], ["4", "5", "6"], ["1", "2", "3"], ["0", "00", "."]]

#: Правая колонка действий, сверху вниз (7 клавиш — по высоте цифрового блока).
_ACTION_COLUMN = ["СУММА", "ОПЛ", "X", "ИТОГ", "ВВОД", "СБРОС", "ОТМЕНА"]

#: Нижний служебный ряд.
_SERVICE_ROW = ["КАССИР", "СЕРВИС", "РЕЖИМ", "ЧЕК", "КС", "Z", "ПИТ"]

#: Клавиши навигации/пробела (могут быть в keys).
_NAV_ROW = ["СТРЕЛКА_ВЛЕВО", "СТРЕЛКА_ВПРАВО", "ПРОБЕЛ", "ТАБ"]

#: Внутренние отступы блока клавиатуры. Взяты меньше, чем ``METRICS["gap"]``
#: (6 px): на экране 4:3 каждый пиксель высоты на счету, а сами метрики
#: кнопок (``key_w``/``key_h``) не трогаем — меняется только раскладка.
_PAD = 4

#: Сколько столбиков разрезает длинный вертикальный ряд клавиш.
_GRID_COLUMNS = 2


def _label(name: str) -> str:
    if name in KEY_LABELS:
        return KEY_LABELS[name]
    return name.replace("_", " ")


def _kind_for(name: str) -> str:
    if name in KEY_COLOURS:
        return KEY_COLOURS[name]
    if name.isdigit():
        return "digit"
    if name in ("00", "."):
        return "digit_alt"
    if name.startswith("СТРЕЛКА") or name in ("ПРОБЕЛ", "ТАБ", "SPACE", "TAB", "LEFT", "RIGHT"):
        return "nav"
    return "plain"


def build_layout(keys) -> dict:
    """Разложить ``keys`` по блокам раскладки.

    Возвращает словарь с ключами ``"digits"`` (список рядов цифр),
    ``"actions"`` (правая колонка), ``"service"`` (нижний ряд),
    ``"nav"`` (ряд навигации), ``"extra"`` (всё, что не попало по местам).

    Отсутствующие в ``keys`` клавиши пропускаются.
    """
    available = [str(k) for k in (keys or [])]
    present = set(available)

    # Английские синонимы: если плата отдаёт ITOG вместо ИТОГ — берём то, что есть.
    synonyms = {
        "СУММА": ("СУММА", "SUMM"),
        "ОПЛ": ("ОПЛ", "PAY"),
        "X": ("X", "MULT"),
        "ИТОГ": ("ИТОГ", "ITOG"),
        "ВВОД": ("ВВОД", "ENTER"),
        "СБРОС": ("СБРОС", "CLEAR"),
        "ОТМЕНА": ("ОТМЕНА", "CANCEL"),
        "ПОДЫТОГ": ("ПОДЫТОГ", "SUBTOTAL"),
        "КАССИР": ("КАССИР", "CASHIER"),
        "СЕРВИС": ("СЕРВИС", "SERVICE"),
        "РЕЖИМ": ("РЕЖИМ", "MODE"),
        "ЧЕК": ("ЧЕК", "RECEIPT"),
        "КС": ("КС", "XREPORT"),
        "Z": ("Z", "ZREPORT"),
        "ПИТ": ("ПИТ", "FEED"),
        "СТРЕЛКА_ВЛЕВО": ("СТРЕЛКА_ВЛЕВО", "LEFT"),
        "СТРЕЛКА_ВПРАВО": ("СТРЕЛКА_ВПРАВО", "RIGHT"),
        "ПРОБЕЛ": ("ПРОБЕЛ", "SPACE"),
        "ТАБ": ("ТАБ", "TAB"),
    }

    used: set[str] = set()

    def pick(name: str):
        for candidate in synonyms.get(name, (name,)):
            if candidate in present and candidate not in used:
                used.add(candidate)
                return candidate
        return None

    digits: list[list[str]] = []
    for row in _NUM_ROWS:
        built = []
        for name in row:
            chosen = pick(name)
            if chosen is not None:
                built.append(chosen)
        if built:
            digits.append(built)

    actions = []
    for name in _ACTION_COLUMN:
        chosen = pick(name)
        if chosen is not None:
            actions.append(chosen)

    service = []
    for name in _SERVICE_ROW:
        chosen = pick(name)
        if chosen is not None:
            service.append(chosen)

    nav = []
    for name in _NAV_ROW:
        chosen = pick(name)
        if chosen is not None:
            nav.append(chosen)

    extra = [k for k in available if k not in used]
    return {
        "digits": digits,
        "actions": actions,
        "service": service,
        "nav": nav,
        "extra": extra,
        "all": available,
    }


class KeypadFrame(tk.Frame):
    """Панель клавиатуры.

    Параметры
    ---------
    parent : родитель
    keyboard : объект клавиатуры платы (``keys``, ``press``, ``release``,
        ``tap``) либо ``None`` (тогда кнопки только рисуются);
    on_key : необязательный обработчик ``on_key(name, action)`` для логов,
        где ``action`` — ``"tap"``/``"press"``/``"release"``.
    """

    def __init__(self, parent, keyboard=None, on_key=None, columns_hint=None, **kwargs):
        super().__init__(
            parent,
            bg=theme.COLORS["bg_panel"],
            relief="raised",
            bd=3,
            highlightthickness=0,
            **kwargs,
        )
        self.keyboard = keyboard
        self.on_key = on_key
        self.buttons: dict[str, tk.Button] = {}
        self._pressed: set[str] = set()
        self._bindings: list[tuple[str, str]] = []

        keys = list(getattr(keyboard, "keys", None) or []) if keyboard is not None else []
        self.keys = keys
        self.layout = build_layout(keys)

        self._build()

    # -- построение --------------------------------------------------------

    def _build(self) -> None:
        """Собрать панель клавиатуры.

        Компоновка под экран 4:3 (1024x768 / 1280x960): длинные вертикальные
        ряды разрезаны на 2 столбика, а служебный ряд поднят в тот же блок,
        что и цифры/действия. Раньше одна колонка из 7 клавиш действий
        задавала высоту всего блока (625 px), и на 4:3 низ клавиатуры
        (ОТМЕНА, служебный ряд, навигация) уезжал за край окна. Состав не
        менялся: все 33 клавиши на месте, метрики кнопок не тронуты.
        """
        body = tk.Frame(self, bg=theme.COLORS["bg_panel"])
        body.pack(fill="both", expand=True, padx=_PAD, pady=_PAD)

        main = tk.Frame(body, bg=theme.COLORS["bg_panel"])
        main.pack(side="top", anchor="w")

        # --- цифровой блок ------------------------------------------------
        digits = tk.Frame(main, bg=theme.COLORS["bg_panel"])
        digits.pack(side="left", anchor="n")
        for row in self.layout["digits"]:
            row_frame = tk.Frame(digits, bg=theme.COLORS["bg_panel"])
            row_frame.pack(side="top", anchor="w")
            for name in row:
                self._add_key(
                    row_frame,
                    name,
                    wide=theme.METRICS["key_w"],
                    high=theme.METRICS["key_h"],
                )

        # --- действия: 2 столбика вместо одной высокой колонки ------------
        # Вертикальная экономия: колонка из 7 клавиш -> два столбика по 4.
        self._pack_grid(
            main,
            self.layout["actions"],
            columns=_GRID_COLUMNS,
            wide=theme.METRICS["key_w_action"],
            high=theme.METRICS["key_h_action"],
            font=theme.FONTS["button_big"],
            pady=1,
        )

        # --- служебный ряд: тем же блоком, тоже 2 столбика ----------------
        if self.layout["service"]:
            self._pack_grid(
                main,
                self.layout["service"],
                columns=_GRID_COLUMNS,
                wide=self._fit_width(
                    self.layout["service"],
                    theme.FONTS["button"],
                    theme.METRICS["key_w_service"],
                ),
                high=theme.METRICS["key_h_service"],
                font=theme.FONTS["button"],
            )

        # --- навигация / пробел + клавиши без места в основной раскладке ---
        # Один низкий ряд (клавиши высотой в одну строку) — он дешёвый по
        # высоте, поэтому остаётся отдельным.
        tail = list(self.layout["nav"]) + list(self.layout["extra"])
        if tail:
            nav = tk.Frame(body, bg=theme.COLORS["bg_panel"])
            nav.pack(side="top", anchor="w", pady=(_PAD // 2, 0))
            width = self._fit_width(
                tail, theme.FONTS["button_small"], theme.METRICS["key_w_service"]
            )
            for name in tail:
                self._add_key(
                    nav,
                    name,
                    wide=width,
                    high=1,
                    font=theme.FONTS["button_small"],
                    pack_side="left",
                    pady=1,
                )

    def _pack_grid(self, parent, names, columns: int = _GRID_COLUMNS,
                   wide=None, high=None, font=None, pady: int = 2) -> None:
        """Упаковать ``names`` в сетку из ``columns`` столбиков слева направо.

        Каждый столбик — вертикальная стопка клавиш, порядок сохраняется
        (читается сверху вниз внутри столбика). Высота ряда падает с
        ``len(names)`` клавиш до ``ceil(len(names) / columns)``, а ширина
        блока почти не меняется — по ней и так определяется самый широкий
        ряд панели. Пустой список клавиш ничего не создаёт.
        ``pady`` — просвет между клавишами внутри столбика (1 экономит
        высоту на 4:3, 2 — обычный вид).
        """
        if not names:
            return
        columns = max(1, int(columns))
        per_column = -(-len(names) // columns)
        grid = tk.Frame(parent, bg=theme.COLORS["bg_panel"])
        grid.pack(side="left", anchor="n", padx=(theme.METRICS["gap"] * 2, 0))
        for start in range(0, len(names), per_column):
            column = tk.Frame(grid, bg=theme.COLORS["bg_panel"])
            column.pack(side="left", anchor="n", padx=(0, _PAD // 2))
            for name in names[start:start + per_column]:
                self._add_key(
                    column,
                    name,
                    wide=wide,
                    high=high,
                    font=font,
                    pack_side="top",
                    pady=pady,
                )

    def _fit_width(self, names, font, minimum: int) -> int:
        """Ширина кнопки в текстовых единицах под самую длинную подпись.

        Иначе подпись («ПОДЫТОГ», «ВОЗВРАТ») обрезается, если фиксированной
        ширины не хватает. Считаем по метрикам реального шрифта Tk:
        ``widget width`` в Tk — это N ширин символа «0» данного шрифта.
        """
        try:
            import tkinter.font as tkfont

            tk_font = tkfont.Font(root=self, font=font)
            wanted = max(tk_font.measure(_label(name)) for name in names) + 8
            per_char = int(tk_font.measure("0"))
        except Exception:
            return max(minimum, 6)
        if per_char <= 0:
            return max(minimum, 6)
        return max(minimum, -(-wanted // per_char))

    def _add_key(self, parent, name, wide, high, font=None, pack_side=None,
                 pady: int = 2) -> tk.Button:
        kind = _kind_for(name)
        label = _label(name)
        button = theme.make_button(
            parent,
            text=label,
            command=lambda n=name: self.tap(n),
            colour=kind,
            width=wide,
            height=high,
            font=font or theme.FONTS["button"],
        )
        button.pack(
            side=pack_side or "left",
            padx=2,
            # просвет по вертикали: 2 — обычный вид, 1 — плотнее, ради
            # высоты блока на экране 4:3 (сама кнопка при этом не меняется)
            pady=pady,
        )
        # Для нажатий мышью «вдавливаем» кнопку на время удержания.
        button.bind(
            "<ButtonPress-1>",
            lambda _e, n=name, b=button: self._visual_press(n, b),
            add="+",
        )
        button.bind(
            "<ButtonRelease-1>",
            lambda _e, n=name, b=button: self._visual_release(n, b),
            add="+",
        )
        self.buttons[name] = button
        return button

    # -- действия ----------------------------------------------------------

    def tap(self, name: str) -> None:
        """Клик мышью: отдать плате ``keyboard.tap(name)``."""
        if self.keyboard is not None:
            try:
                self.keyboard.tap(name)
            except Exception:
                pass
        self._notify(name, "tap")

    def press(self, name: str) -> None:
        """Физическая клавиша нажата."""
        if self.keyboard is not None:
            try:
                self.keyboard.press(name)
            except Exception:
                pass
        self._notify(name, "press")

    def release(self, name: str) -> None:
        """Физическая клавиша отпущена."""
        if self.keyboard is not None:
            try:
                self.keyboard.release(name)
            except Exception:
                pass
        self._notify(name, "release")

    def _notify(self, name: str, action: str) -> None:
        if self.on_key is not None:
            try:
                self.on_key(name, action)
            except Exception:
                pass

    def _visual_press(self, name: str, button) -> None:
        self._pressed.add(name)
        try:
            button.configure(relief="sunken")
        except tk.TclError:
            pass

    def _visual_release(self, name: str, button) -> None:
        self._pressed.discard(name)
        try:
            button.configure(relief="raised")
        except tk.TclError:
            pass

    # -- физическая клавиатура --------------------------------------------

    def bind_physical(self, widget, bindings=None, include_defaults=True) -> None:
        """Привязать физическую клавиатуру к ``press``/``release``.

        ``widget`` — обычно корневое окно. ``bindings`` — список пар
        ``("<Return>", "ВВОД")``; при ``include_defaults=True`` к ним
        добавляется стандартный набор.
        """
        mapping = list(DEFAULT_BINDINGS) if include_defaults else []
        mapping.extend(bindings or [])
        for sequence, name in mapping:
            key_names = name if isinstance(name, (list, tuple)) else [name]
            for key_name in key_names:
                if key_name not in self.buttons:
                    continue
                widget.bind(
                    sequence,
                    lambda _e, n=key_name: self.press(n),
                    add="+",
                )
                widget.bind(
                    _release_sequence(sequence),
                    lambda _e, n=key_name: self.release(n),
                    add="+",
                )
                self._bindings.append((sequence, key_name))

    def reset_visuals(self) -> None:
        """Вернуть все кнопки в выпуклое состояние (например, при потере фокуса)."""
        for name, button in self.buttons.items():
            try:
                button.configure(relief="raised")
            except tk.TclError:
                pass
        self._pressed.clear()


def _release_sequence(sequence: str) -> str:
    """``"<KeyPress-Return>"`` -> ``"<KeyRelease-Return>"``."""
    if "KeyPress" in sequence:
        return sequence.replace("KeyPress", "KeyRelease")
    return sequence.replace("<", "<KeyRelease-", 1)


#: Клавиши физической клавиатуры -> имена клавиш кассы.
DEFAULT_BINDINGS: list[tuple[str, object]] = [
    ("<KeyPress-0>", "0"),
    ("<KeyPress-1>", "1"),
    ("<KeyPress-2>", "2"),
    ("<KeyPress-3>", "3"),
    ("<KeyPress-4>", "4"),
    ("<KeyPress-5>", "5"),
    ("<KeyPress-6>", "6"),
    ("<KeyPress-7>", "7"),
    ("<KeyPress-8>", "8"),
    ("<KeyPress-9>", "9"),
    ("<period>", "."),
    ("<comma>", "."),
    ("<Return>", ("ВВОД", "ENTER")),
    ("<KP_Enter>", ("ВВОД", "ENTER")),
    ("<Escape>", ("СБРОС", "CLEAR", "ОТМЕНА", "CANCEL")),
    ("<BackSpace>", ("СБРОС", "CLEAR")),
    ("<Delete>", ("ОТМЕНА", "CANCEL")),
    ("<Left>", ("СТРЕЛКА_ВЛЕВО", "LEFT")),
    ("<Right>", ("СТРЕЛКА_ВПРАВО", "RIGHT")),
    ("<space>", ("ПРОБЕЛ", "SPACE")),
    ("<Tab>", ("ТАБ", "TAB")),
    ("<F1>", ("КАССИР", "CASHIER")),
    ("<F2>", ("СЕРВИС", "SERVICE")),
    ("<F3>", ("РЕЖИМ", "MODE")),
    ("<F4>", ("ЧЕК", "RECEIPT")),
    # F5 зарезервировано под «Обновить экран» (см. ui/app.py: меню и <F5>).
    # Раньше здесь стоял КС, и одно нажатие F5 одновременно «печатало»
    # X-отчёт на плате — у КС теперь своя свободная клавиша F8.
    ("<F8>", ("КС", "XREPORT")),
    ("<F6>", ("Z", "ZREPORT")),
    ("<F7>", ("ПИТ", "FEED")),
]
