# -*- coding: utf-8 -*-
"""Тёмная тема кассы ЭТИМ: цвета, шрифты, метрики и классические кнопки.

Требование заказчика: **классические объёмные квадратные кнопки Tkinter**
(``tk.Button``, ``relief="raised"``, толстая рамка ``bd``, серый «пластик»,
при нажатии ``relief="sunken"``), тёмный фон, кнопки разных цветов.

Вся стилизация кнопок живёт только здесь — остальные модули вызывают
:func:`make_button` / :func:`make_frame`.
"""

from __future__ import annotations

import tkinter as tk

__all__ = [
    "COLORS",
    "FONTS",
    "METRICS",
    "BEVEL_LIGHT",
    "BEVEL_DARK",
    "BUTTON_COLORS",
    "make_button",
    "make_frame",
    "apply_root_style",
    "lighten",
    "darken",
    "BUTTON_KINDS",
]

# --------------------------------------------------------------------------
# Цвета
# --------------------------------------------------------------------------

COLORS = {
    # фон
    "bg": "#1e1e22",
    "bg_panel": "#26262c",
    "bg_panel2": "#2e2e35",
    "bg_sunken": "#15151a",
    # текст / рамки
    "fg": "#e8e8ee",
    "fg_dim": "#a0a0ac",
    "fg_bright": "#ffffff",
    "border": "#0d0d10",
    "separator": "#3a3a44",
    # экран (вакуумно-люминесцентный, зеленовато-голубой)
    "screen_bg": "#050906",
    "screen_glow": "#39ff9c",
    "screen_on": "#4dffa6",
    "screen_dim": "#123020",
    "screen_frame": "#101014",
    "screen_caption": "#c8ffd8",
    # бумага чека
    "paper": "#f6f1df",
    "paper_shadow": "#cfc7ad",
    "paper_fg": "#1b1b16",
    "paper_fg_dim": "#6b6656",
    "receipt_bg": "#17171b",
    # строка состояния
    "status_bg": "#101014",
    "status_fg": "#b9b9c6",
    # светодиод принтера
    "led_off": "#3a1010",
    "led_on": "#ff4040",
    # меню
    "menu_bg": "#26262c",
    "menu_fg": "#e8e8ee",
}

# --------------------------------------------------------------------------
# Шрифты (кортежи Tk: не требуют корневого окна на момент импорта)
# --------------------------------------------------------------------------

FONTS = {
    "title": ("Segoe UI", 15, "bold"),
    "subtitle": ("Segoe UI", 9),
    "label": ("Segoe UI", 9, "bold"),
    "label_small": ("Segoe UI", 8),
    "button": ("Segoe UI", 11, "bold"),
    "button_big": ("Segoe UI", 12, "bold"),
    "button_small": ("Segoe UI", 9, "bold"),
    "symbol": ("Segoe UI Symbol", 11, "bold"),
    "screen": ("Consolas", 34, "bold"),
    "screen_small": ("Consolas", 12, "bold"),
    "receipt": ("Courier New", 10),
    "receipt_bold": ("Courier New", 10, "bold"),
    "mono": ("Consolas", 9),
    "status": ("Segoe UI", 9),
}

# --------------------------------------------------------------------------
# Метрики
# --------------------------------------------------------------------------

METRICS = {
    "button_bd": 4,          # толщина объёмной рамки классической кнопки
    "button_bd_small": 3,
    "button_padx": 8,        # внутренние отступы (px)
    "button_pady": 3,
    "button_relief": "raised",
    "button_active_relief": "sunken",
    "button_takefocus": 0,
    "frame_relief": "raised",
    "frame_bd": 2,
    "gap": 6,
    "key_w": 4,              # ширина цифровой кнопки в текстовых единицах
    "key_h": 2,              # высота цифровой кнопки в текстовых строках
    "key_w_action": 9,
    "key_h_action": 2,
    # Служебный ряд (7 клавиш) плюс ряд дополнительных клавиш («ВОЗВРАТ»,
    # «СКИДКА», «ПОДЫТОГ») должен целиком влезать в панель клавиатуры, иначе
    # последняя клавиша уезжает за край окна и обрезается.
    "key_w_service": 4,
    "key_h_service": 2,
}

# Полутона рамки классической кнопки (используются в кастомной отрисовке).
BEVEL_LIGHT = "#b9b9c4"
BEVEL_DARK = "#08080a"

# --------------------------------------------------------------------------
# Цвета кнопок по назначению («кнопочки разного цвета»)
# --------------------------------------------------------------------------

BUTTON_COLORS = {
    # цифры — серо-синий «пластик»
    "digit": {"bg": "#5a6b8c", "fg": "#ffffff", "active_bg": "#48597a"},
    # «00» и «.» — чуть иначе, чтобы выделялись внутри цифрового блока
    "digit_alt": {"bg": "#61769b", "fg": "#ffffff", "active_bg": "#4a5f85"},
    # арифметика/суммы
    "arithmetic": {"bg": "#a87a2a", "fg": "#fff6e0", "active_bg": "#8b6320"},
    # служебные/отчёты
    "service": {"bg": "#3f7d5a", "fg": "#eafff2", "active_bg": "#32644a"},
    # режимы (кассир/сервис/режим)
    "mode": {"bg": "#4f6f8f", "fg": "#f0f8ff", "active_bg": "#3f5b78"},
    # принтер (чек, КС, Z, ПИТ)
    "printer": {"bg": "#7a5f96", "fg": "#f8f2ff", "active_bg": "#654e7d"},
    # курсор/навигация
    "nav": {"bg": "#55555f", "fg": "#f0f0f6", "active_bg": "#43434c"},
    # отмена/сброс — КРАСНАЯ
    "danger": {"bg": "#b03030", "fg": "#fff0f0", "active_bg": "#8c2424"},
    # обычная серая кнопка (меню, «Очистить»)
    "plain": {"bg": "#6e6e78", "fg": "#ffffff", "active_bg": "#5a5a64"},
}

BUTTON_KINDS = tuple(BUTTON_COLORS)


def _clamp_byte(value: int) -> int:
    return 0 if value < 0 else 255 if value > 255 else int(value)


def lighten(colour: str, amount: int = 28) -> str:
    """Осветлить цвет ``#rrggbb`` (для граней объёмной кнопки)."""
    try:
        raw = colour.lstrip("#")
        if len(raw) != 6:
            return colour
        r, g, b = (int(raw[i:i + 2], 16) for i in (0, 2, 4))
    except (ValueError, TypeError):
        return colour
    r, g, b = (_clamp_byte(r + amount), _clamp_byte(g + amount), _clamp_byte(b + amount))
    return "#%02x%02x%02x" % (r, g, b)


def darken(colour: str, amount: int = 28) -> str:
    """Затемнить цвет ``#rrggbb``."""
    return lighten(colour, -abs(amount))


# --------------------------------------------------------------------------
# Классические кнопки
# --------------------------------------------------------------------------


def make_button(parent, text, command, colour, width=None, height=None, **kwargs):
    """Создать **классическую объёмную** ``tk.Button``.

    Параметры
    ---------
    parent : виджет-родитель
    text : подпись («СУММА», «7», «ОТМЕНА», …)
    command : вызываемый объект без аргументов (или ``None``)
    colour : имя цвета из :data:`BUTTON_COLORS`, словарь ``{"bg","fg","active_bg"}``
        либо строка ``#rrggbb``
    width, height : размеры в текстовых единицах Tk (``None`` — по умолчанию Tk)
    kwargs : любые прочие опции ``tk.Button`` (например ``font``,
        ``padx``, ``pady``, ``wraplength``)

    Возвращает готовую ``tk.Button`` с ``relief="raised"`` и ``bd=4``.
    Нажатие визуально «вдавливает» кнопку (``relief="sunken"``).
    """
    style = resolve_colour(colour)
    bg = style["bg"]
    fg = style["fg"]
    active_bg = style.get("active_bg") or darken(bg)

    font = kwargs.pop("font", FONTS["button"])
    bd = kwargs.pop("bd", METRICS["button_bd"])
    relief = kwargs.pop("relief", METRICS["button_relief"])
    padx = kwargs.pop("padx", METRICS["button_padx"])
    pady = kwargs.pop("pady", METRICS["button_pady"])

    btn = tk.Button(
        parent,
        text=text,
        command=command,
        width=width,
        height=height,
        font=font,
        bg=bg,
        fg=fg,
        activebackground=active_bg,
        activeforeground=fg,
        relief=relief,
        bd=bd,
        padx=padx,
        pady=pady,
        takefocus=kwargs.pop("takefocus", METRICS["button_takefocus"]),
        highlightthickness=kwargs.pop("highlightthickness", 1),
        highlightbackground=BEVEL_DARK,
        highlightcolor=BEVEL_DARK,
        disabledforeground=COLORS["fg_dim"],
        cursor=kwargs.pop("cursor", "hand2"),
        **kwargs,
    )

    # Классический «вдавливающийся» эффект.
    btn.bind(
        "<ButtonPress-1>",
        lambda _e, b=btn: _set_relief(b, METRICS["button_active_relief"]),
        add="+",
    )
    btn.bind(
        "<ButtonRelease-1>",
        lambda _e, b=btn: _set_relief(b, METRICS["button_relief"]),
        add="+",
    )
    # Кнопка должна оставаться «выпуклой», если курсор ушёл с неё нажатой.
    btn.bind("<Leave>", lambda _e, b=btn: _set_relief(b, METRICS["button_relief"]), add="+")
    return btn


def _set_relief(button, relief: str) -> None:
    try:
        button.configure(relief=relief)
    except tk.TclError:  # виджет уже уничтожен
        pass


def resolve_colour(colour):
    """Привести описание цвета к словарю ``{"bg","fg","active_bg"}``."""
    if isinstance(colour, dict):
        style = dict(colour)
        style.setdefault("fg", "#ffffff")
        return style
    if isinstance(colour, str) and colour in BUTTON_COLORS:
        return dict(BUTTON_COLORS[colour])
    if isinstance(colour, str) and colour.startswith("#"):
        return {"bg": colour, "fg": "#ffffff", "active_bg": darken(colour)}
    return dict(BUTTON_COLORS["plain"])


def make_frame(parent, relief=None, bd=None, bg=None, **kwargs):
    """Рамка в стиле темы (по умолчанию — выпуклая, толщиной 2)."""
    return tk.Frame(
        parent,
        bg=bg if bg is not None else COLORS["bg_panel"],
        relief=relief if relief is not None else METRICS["frame_relief"],
        bd=bd if bd is not None else METRICS["frame_bd"],
        **kwargs,
    )


def make_sunken(parent, **kwargs):
    """Утопленная панель (для «железа» корпуса)."""
    return make_frame(parent, relief="sunken", bg=COLORS["bg_sunken"], **kwargs)


def apply_root_style(root) -> None:
    """Общие настройки корневого окна: тёмный фон, шрифт меню.

    Внимание: шрифты здесь задаются **именами** (``font.nametofont``), а не
    через ``option_add("*Font", ...)``. Строка вида ``"Segoe UI 9"`` попадает
    в базу опций Tk без фигурных скобок и ломает разбор опций у всех
    последующих виджетов (``tk.Menu`` падает с ``expected integer but got
    "UI"``). Настраиваем только те два шрифта, что нужны меню.
    """
    try:
        root.configure(bg=COLORS["bg"])
    except tk.TclError:
        return
    for option, value in (
        ("*Background", COLORS["bg"]),
        ("*Foreground", COLORS["fg"]),
        ("*Menu.Background", COLORS["menu_bg"]),
        ("*Menu.Foreground", COLORS["menu_fg"]),
        ("*Menu.ActiveBackground", COLORS["bg_panel2"]),
        ("*Menu.ActiveForeground", COLORS["fg_bright"]),
        ("*Menu.SelectBackground", COLORS["bg_panel2"]),
    ):
        try:
            root.option_add(option, value)
        except tk.TclError:
            pass
    # Шрифты меню — через именованные шрифты (безопасно для option database).
    try:
        import tkinter.font as tkfont

        for name in ("TkMenuFont", "TkHeadingFont"):
            try:
                tkfont.nametofont(name).configure(family="Segoe UI", size=9)
            except tk.TclError:
                pass
    except Exception:
        pass
