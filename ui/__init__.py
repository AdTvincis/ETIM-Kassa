"""Tkinter-интерфейс кассы ЭТИМ.

Модули:

* :mod:`ui.theme`   — тёмная тема, цвета, шрифты и фабрика классических
  объёмных кнопок ``tk.Button``.
* :mod:`ui.screen`  — индикатор кассы (вакуумно-люминесцентный вид).
* :mod:`ui.keypad`  — панель клавиатуры (строится по ``keyboard.keys``).
* :mod:`ui.receipt` — область бумажной ленты чека.
* :mod:`ui.app`     — :class:`ui.app.CashRegisterApp` — главное окно.

Импорт этого пакета (и ``ui.app``) **не** создаёт окно Tk: окно появляется
только при создании :class:`ui.app.CashRegisterApp` / вызове ``run()``.
"""

__all__ = ["theme", "screen", "keypad", "receipt", "app"]
