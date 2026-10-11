# -*- coding: utf-8 -*-
"""Главное окно кассы ЭТИМ: :class:`CashRegisterApp`.

Окно собирает вместе:

* шапку с названием и кнопками режима;
* индикатор :class:`ui.screen.ScreenWidget`;
* клавиатуру :class:`ui.keypad.KeypadFrame`;
* чек :class:`ui.receipt.ReceiptView`;
* строку состояния и меню.

Контракт для хоста (``main.py``)::

    app = CashRegisterApp(board, title="ЭТИМ — Касса", on_quit=callback)
    app.refresh()      # дёшево, никогда не бросает исключение
    app.run()          # tk mainloop()

Импорт модуля **не** создаёт окно. ``refresh()`` можно звать сколько угодно раз
и из любого числа мест: он идемпотентен и терпит изменение ``board`` между
вызовами.
"""

from __future__ import annotations

import tkinter as tk

from . import theme
from .keypad import KeypadFrame
from .receipt import ReceiptView
from .screen import ScreenWidget

__all__ = ["CashRegisterApp"]

#: Подписи режимов индикатора (сколько знакомест/строк показывает экран).
DISPLAY_MODES = [
    ("20 x 1  (касса)", 20, 1),
    ("20 x 2  (касса, 2 строки)", 20, 2),
    ("16 x 1  (ценник)", 16, 1),
    ("8 x 1   (табло)", 8, 1),
    ("40 x 1  (широкий)", 40, 1),
]

DEFAULT_REFRESH_MS = 50


class CashRegisterApp:
    """Окно кассы. Создаёт виджеты в ``__init__``, запускается ``run()``."""

    def __init__(self, board, title: str = "ЭТИМ — Касса", on_quit=None):
        self.board = board
        self.on_quit = on_quit
        self.title = title
        self._refresh_ms = DEFAULT_REFRESH_MS
        self._after_id = None
        self._closed = False
        self._last_status = None
        self._last_key = None
        self._counter = 0
        #: True, если пользователь сам выбрал индикатор в списке режимов.
        self._manual_mode = False

        self.display = getattr(board, "display", None)
        self.keyboard = getattr(board, "keyboard", None)
        self.printer = getattr(board, "printer", None)

        self.root = tk.Tk()
        theme.apply_root_style(self.root)
        try:
            self.root.title(title)
        except tk.TclError:
            pass
        self.root.configure(bg=theme.COLORS["bg"])
        self.root.minsize(760, 640)
        self._set_initial_geometry()

        self._build_menu()
        self._build_layout()
        self._bind_events()
        self._fit_window_to_content()
        self.refresh()
        self._schedule()

    def _set_initial_geometry(self) -> None:
        """Начальный размер окна: не больше рабочего стола."""
        try:
            screen_w = int(self.root.winfo_screenwidth())
            screen_h = int(self.root.winfo_screenheight())
        except tk.TclError:
            screen_w, screen_h = 1280, 800
        width = max(900, min(1280, screen_w - 40))
        height = max(660, min(900, screen_h - 80))
        try:
            self.root.geometry("%dx%d" % (width, height))
        except tk.TclError:
            pass

    def _fit_window_to_content(self) -> None:
        """Подогнать окно под содержимое, но не больше рабочего стола.

        Клавиатура кассы (33 клавиши) выше «разумного» окна, поэтому пусть окно
        примет свой натуральный размер: Tk сам сложит запросы всех виджетов.
        """
        try:
            self.root.update_idletasks()
            need_w = int(self.root.winfo_reqwidth())
            need_h = int(self.root.winfo_reqheight())
            screen_w = int(self.root.winfo_screenwidth())
            screen_h = int(self.root.winfo_screenheight())
        except tk.TclError:
            return
        width = max(900, min(need_w + 8, screen_w - 40))
        height = max(660, min(need_h + 8, screen_h - 80))
        try:
            self.root.geometry("%dx%d" % (width, height))
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Построение окна
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        menu = tk.Menu(menubar, tearoff=0)
        menu.add_command(label="Обновить экран    F5", command=self.refresh)
        menu.add_command(label="Очистить чек", command=self._clear_receipt)
        menu.add_separator()
        menu.add_command(label="Выход", command=self.quit)
        menubar.add_cascade(label="Касса", menu=menu)

        view = tk.Menu(menubar, tearoff=0)
        view.add_command(label="Только экран", command=lambda: self._set_receipt_visible(False))
        view.add_command(label="Экран и чек", command=lambda: self._set_receipt_visible(True))
        menubar.add_cascade(label="Вид", menu=view)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self._show_about)
        menubar.add_cascade(label="Справка", menu=help_menu)

        try:
            self.root.configure(menu=menubar)
        except tk.TclError:
            pass
        self.menubar = menubar

    def _build_layout(self) -> None:
        # ---- шапка -------------------------------------------------------
        header = tk.Frame(self.root, bg=theme.COLORS["bg_panel"], relief="raised", bd=2)
        header.pack(side="top", fill="x")
        tk.Label(
            header,
            text="КАССА  \u00ab\u042d\u0422\u0418\u041c\u00bb",
            bg=theme.COLORS["bg_panel"],
            fg=theme.COLORS["fg_bright"],
            font=theme.FONTS["title"],
        ).pack(side="left", padx=12, pady=6)
        tk.Label(
            header,
            text="\u0410\u041e \u00ab\u042d\u0422\u0418\u041c\u00bb, \u0421\u0430\u043d\u043a\u0442-\u041f\u0435\u0442\u0435\u0440\u0431\u0443\u0440\u0433, 1994-95  \u2022  \u044d\u043c\u0443\u043b\u044f\u0442\u043e\u0440 AT89C55VD",
            bg=theme.COLORS["bg_panel"],
            fg=theme.COLORS["fg_dim"],
            font=theme.FONTS["subtitle"],
        ).pack(side="left", padx=(0, 12))

        mode_label = tk.Label(
            header,
            text="\u0418\u041d\u0414\u0418\u041a\u0410\u0422\u041e\u0420:",
            bg=theme.COLORS["bg_panel"],
            fg=theme.COLORS["fg_dim"],
            font=theme.FONTS["label_small"],
        )
        mode_label.pack(side="right", padx=(6, 8))
        self.mode_var = tk.StringVar(value=DISPLAY_MODES[0][0])
        mode_box = tk.OptionMenu(header, self.mode_var, *[m[0] for m in DISPLAY_MODES])
        mode_box.configure(
            bg=theme.COLORS["bg_panel2"],
            fg=theme.COLORS["fg"],
            activebackground=theme.COLORS["bg_panel2"],
            activeforeground=theme.COLORS["fg_bright"],
            font=theme.FONTS["label_small"],
            highlightthickness=1,
            bd=2,
            relief="raised",
        )
        mode_box.pack(side="right", pady=6)
        self.mode_box = mode_box
        self.mode_var.trace_add("write", lambda *_: self._apply_display_mode())

        # ---- корпус кассы ------------------------------------------------
        # Раскладка корпуса:
        #   +--------------------------------------------------+
        #   |                ИНДИКАТОР (во всю ширину)          |
        #   +------------------+-------------------------------+
        #   |    КЛАВИАТУРА    |          ЧЕК                   |
        #   +------------------+-------------------------------+
        shell = tk.Frame(self.root, bg=theme.COLORS["bg"])
        shell.pack(side="top", fill="both", expand=True, padx=8, pady=8)

        # ---- экран (верхний ряд, во всю ширину) --------------------------
        screen_panel = tk.Frame(
            shell, bg=theme.COLORS["bg_panel"], relief="raised", bd=3
        )
        screen_panel.pack(side="top", fill="x")

        tk.Label(
            screen_panel,
            text="\u0418\u041d\u0414\u0418\u041a\u0410\u0422\u041e\u0420 \u041a\u0410\u0421\u0421\u042b",
            bg=theme.COLORS["bg_panel"],
            fg=theme.COLORS["fg"],
            font=theme.FONTS["label"],
        ).pack(side="top", anchor="w", padx=6, pady=(4, 2))

        columns, lines = self._display_geometry()
        self.screen = ScreenWidget(screen_panel, columns=columns, lines=lines)
        self.screen.pack(side="top", fill="x", padx=6, pady=(0, 6), anchor="n")
        self._screen_panel = screen_panel

        # ---- нижний ряд: клавиатура слева, чек справа --------------------
        lower = tk.Frame(shell, bg=theme.COLORS["bg"])
        lower.pack(side="top", fill="both", expand=True, pady=(10, 0))

        keypad_panel = tk.Frame(lower, bg=theme.COLORS["bg"])
        keypad_panel.pack(side="left", fill="both", anchor="n")
        tk.Label(
            keypad_panel,
            text="КЛАВИАТУРА",
            bg=theme.COLORS["bg"],
            fg=theme.COLORS["fg"],
            font=theme.FONTS["label"],
        ).pack(side="top", anchor="w", padx=2, pady=(0, 2))
        self.keypad = KeypadFrame(
            keypad_panel,
            keyboard=self.keyboard,
            on_key=self._on_key,
        )
        self.keypad.pack(side="top", fill="x", anchor="n")

        # ---- чек ---------------------------------------------------------
        self.receipt = ReceiptView(lower, printer=self.printer, on_action=self._on_receipt_action)
        self.receipt.pack(side="left", fill="both", expand=True, padx=(10, 0))

        # ---- строка состояния --------------------------------------------
        status = tk.Frame(self.root, bg=theme.COLORS["status_bg"], relief="sunken", bd=2)
        status.pack(side="bottom", fill="x")
        self.status_var = tk.StringVar(value="Готово")
        tk.Label(
            status,
            textvariable=self.status_var,
            bg=theme.COLORS["status_bg"],
            fg=theme.COLORS["status_fg"],
            font=theme.FONTS["status"],
            anchor="w",
        ).pack(side="left", padx=8, pady=2)
        self.clock_var = tk.StringVar(value="")
        tk.Label(
            status,
            textvariable=self.clock_var,
            bg=theme.COLORS["status_bg"],
            fg=theme.COLORS["status_fg"],
            font=theme.FONTS["mono"],
            anchor="e",
        ).pack(side="right", padx=8)

    def _bind_events(self) -> None:
        self.keypad.bind_physical(self.root)
        self.root.bind("<F5>", lambda _e: self.refresh(), add="+")
        self.root.bind("<Configure>", self._on_root_configure, add="+")
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        self.root.bind("<Control-q>", lambda _e: self.quit(), add="+")
        self.root.bind(
            "<FocusOut>", lambda _e: self.keypad.reset_visuals(), add="+"
        )

    # ------------------------------------------------------------------
    # Геометрия экрана
    # ------------------------------------------------------------------

    def _on_root_configure(self, event=None) -> None:
        """Вписать экран в доступный прямоугольник при изменении размера окна."""
        if event is not None and getattr(event, "widget", None) is not self.root:
            return
        try:
            height = int(self.root.winfo_height())
        except tk.TclError:
            height = 0
        try:
            width = int(self.root.winfo_width())
        except tk.TclError:
            return
        # Экран занимает верхний ряд во всю ширину окна (минус отступы и рамки
        # с запасом 6 %), а по высоте — верхнюю часть окна.
        max_width = int(max(160, (width - 60) * 0.94))
        self.screen.fit_to_width(max_width, max(120, height - 500))

    def _display_geometry(self) -> tuple[int, int]:
        columns = getattr(self.display, "columns", None)
        lines = getattr(self.display, "lines", None)
        try:
            columns = int(columns)
        except (TypeError, ValueError):
            columns = 20
        try:
            lines = int(lines)
        except (TypeError, ValueError):
            lines = 1
        if not 1 <= columns <= 80:
            columns = 20
        if not 1 <= lines <= 4:
            lines = 1
        return columns, lines

    def _apply_display_mode(self) -> None:
        self._manual_mode = True
        for label, columns, lines in DISPLAY_MODES:
            if label == self.mode_var.get():
                height = 0
                try:
                    height = int(self.root.winfo_height())
                except tk.TclError:
                    pass
                self.screen.set_geometry(
                    columns=columns,
                    lines=lines,
                    max_width=max(160, int((self.root.winfo_width() or 900) * 0.94)),
                    max_height=max(120, height - 500) if height else 190,
                )
                self._update_status(force=True)
                return

    # ------------------------------------------------------------------
    # Реакция на действия
    # ------------------------------------------------------------------

    def _on_key(self, name: str, action: str) -> None:
        self._last_key = name
        if action == "tap":
            self._update_status(force=True)

    def _on_receipt_action(self, action: str) -> None:
        self._update_status(force=True)

    def _sync_display_shape(self) -> None:
        """Следовать за реальной геометрией платы, пока режим не выбран вручную.

        У настоящей платы экран 8x1; у моковой — 20x2. Как только пользователь
        выбрал вариант в списке, автоследование отключается.
        """
        if self._manual_mode:
            return
        columns, lines = self._display_geometry()
        if (columns, lines) == (self.screen.columns, self.screen.lines):
            return
        height = 0
        try:
            height = int(self.root.winfo_height())
        except tk.TclError:
            pass
        width = 0
        try:
            width = int(self.root.winfo_width())
        except tk.TclError:
            pass
        self.screen.set_geometry(
            columns=columns,
            lines=lines,
            max_width=max(160, int((width or 900) * 0.94)),
            max_height=max(120, height - 500) if height else 190,
        )

    def _clear_receipt(self) -> None:
        self.receipt.clear_paper()
        self._update_status(force=True)

    def _set_receipt_visible(self, visible: bool) -> None:
        if visible:
            self.receipt.pack(side="left", fill="both", expand=True, padx=(10, 0))
        else:
            self.receipt.pack_forget()

    def _show_about(self) -> None:
        try:
            from tkinter import messagebox

            messagebox.showinfo(
                "О программе",
                "Эмулятор кассы АО \u00abЭТИМ\u00bb (Санкт-Петербург), 1994-95.\n"
                "Процессор AT89C55VD (MCS-51), ПЗУ 27C512.\n"
                "Интерфейс: Tkinter, классические объёмные кнопки.",
                parent=self.root,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Периодическое обновление
    # ------------------------------------------------------------------

    def _schedule(self) -> None:
        if self._closed or self._refresh_ms is None or self._refresh_ms <= 0:
            return
        try:
            self._after_id = self.root.after(self._refresh_ms, self._tick)
        except tk.TclError:
            self._after_id = None

    def _tick(self) -> None:
        self._after_id = None
        if self._closed:
            return
        try:
            self.refresh()
        finally:
            self._schedule()

    def refresh(self) -> None:
        """Перерисовать экран и чек из платы. Дёшево, никогда не бросает.

        Хост (``main.py``) вызывает метод каждые ~50 мс. Если плата ещё не
        прошла ``boot()`` (пустая/нулевая) или её методы бросают исключения,
        показываем текст ошибки на экране и в строке состояния, не падая.
        """
        if self._closed:
            return
        self._counter += 1

        try:
            self._sync_display_shape()
        except Exception:
            pass

        fatal = None
        try:
            ok, last_error = self.screen.update_from_display(self.display)
            if not ok and last_error is not None:
                fatal = last_error
                try:
                    self.screen.set_text("\u041e\u0428\u0418\u0411\u041a\u0410 \u042d\u041a\u0420\u0410\u041d\u0410")
                except Exception:
                    pass
        except Exception as exc:
            fatal = exc
            try:
                self.screen.set_text("\u041e\u0428\u0418\u0411\u041a\u0410 \u042d\u041a\u0420\u0410\u041d\u0410")
            except Exception:
                pass
        try:
            self.receipt.update_from_printer(self.printer)
        except Exception as exc:
            fatal = fatal or exc
        try:
            if fatal is not None:
                self.error_text = "display/printer: %s" % (fatal,)
            elif self.display is None:
                self.error_text = "\u043d\u0435\u0442 \u043e\u0431\u044a\u0435\u043a\u0442\u0430 display"
            else:
                self.error_text = None
        except Exception:
            self.error_text = None
        try:
            self._update_status()
        except Exception:
            pass
        try:
            self.clock_var.set("цикл %d" % self._counter)
        except Exception:
            pass

    def _read_board_status(self):
        """Необязательный статус платы: ``status()`` (dict или строка).

        Поддерживаем и ``status()``, и ``status_text()``; любые исключения и
        неожиданные типы молча игнорируются — хост обещает только
        ``.display/.keyboard/.printer``.
        """
        for attr in ("status", "status_text"):
            getter = getattr(self.board, attr, None)
            if not callable(getter):
                continue
            try:
                value = getter()
            except Exception:
                continue
            if isinstance(value, dict):
                parts = [str(value[key]) for key in ("source", "reason") if value.get(key)]
                if parts:
                    return " \u2022 ".join(parts)
            elif isinstance(value, str) and value:
                return value
        return None

    def _update_status(self, force: bool = False) -> None:
        parts = []
        mode = self._read_board_status()
        if mode:
            parts.append(mode)
        if getattr(self, "error_text", None):
            parts.append("\u041e\u0428\u0418\u0411\u041a\u0410: %s" % self.error_text)
        parts.append("клавиш: %d" % len(getattr(self.keypad, "buttons", {}) or {}))
        if self._last_key:
            parts.append("последняя: %s" % self._last_key)
        printer_state = "\u0433\u043e\u0442\u043e\u0432"
        if self.printer is not None:
            try:
                printer_state = "\u0437\u0430\u043d\u044f\u0442" if self.printer.is_busy() else "\u0433\u043e\u0442\u043e\u0432"
            except Exception:
                printer_state = "\u043d/\u0434"
        parts.append("\u043f\u0440\u0438\u043d\u0442\u0435\u0440: %s" % printer_state)
        parts.append(
            "\u044d\u043a\u0440\u0430\u043d: %d x %d" % (self.screen.columns, self.screen.lines)
        )
        status = "   \u2022   ".join(parts)
        if force or status != self._last_status:
            self._last_status = status
            try:
                self.status_var.set(status)
            except tk.TclError:
                pass

    # ------------------------------------------------------------------
    # Жизненный цикл
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Запустить ``tk`` mainloop до закрытия окна."""
        try:
            self.root.mainloop()
        finally:
            self._closed = True

    def quit(self) -> None:
        """Закрыть окно: сначала позвать ``on_quit``, потом уничтожить виджеты."""
        if self._closed:
            return
        self._closed = True
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None
        if self.on_quit is not None:
            try:
                self.on_quit()
            except Exception:
                pass
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    #: Совместимость с типичным именем метода у Tk-приложений.
    destroy = quit
