# -*- coding: utf-8 -*-
"""``firmware.demo`` -- ДЕМОНСТРАЦИОННАЯ (stand-in) программа кассы.

Это **не** оригинальная прошивка.  Дамп ``firmware/nm27c512n.hex`` после
rebasing — нижние 32 КиБ CPU (``0x0000..0x7FFF``; записи hex лежат по
смещениям ``0x8000..0xFFFF``, вектор сброса ``LJMP 0x0A06`` настоящий и
исполняем), верхней половины ``0x8000..0xFFFF`` в нём нет, а сканирование
клавиатуры и принтер декомпиляцией покрыты не полностью.  Поэтому для
детерминированных тестов платы и UI собрана замена — настоящий машинный код
MCS-51, собранный :mod:`tools.asm51`.

Публичный API::

    from firmware.demo import build_demo, load_demo_image, DEMO_LABEL

    image, symbols = build_demo()   # (bytes, {NAME: value}); пишет cashier.hex
    image = load_demo_image()       # то же, но без пересборки, если hex свежий

Константы :data:`PORT_MAP`, :data:`DISPLAY`, :data:`KEY_LAYOUT`,
:data:`KEY_CODES`, :data:`SEGMENTS` описывают аппаратные допущения программы
(ППИ 8255, индикатор, матрица клавиатуры) и предназначены для тестов и UI.
"""

from __future__ import annotations

from .build import (  # noqa: F401
    DEMO_BASE,
    DEMO_LABEL,
    DISPLAY,
    HEX,
    HERE,
    KEY_CODES,
    KEY_LAYOUT,
    PORT_MAP,
    SEGMENTS,
    SOURCE,
    USED_KEYS,
    build_demo,
    build_result,
    load_demo_image,
)

__all__ = [
    "DEMO_BASE",
    "DEMO_LABEL",
    "DISPLAY",
    "KEY_CODES",
    "KEY_LAYOUT",
    "PORT_MAP",
    "SEGMENTS",
    "SOURCE",
    "HEX",
    "USED_KEYS",
    "build_demo",
    "build_result",
    "load_demo_image",
]
