# -*- coding: utf-8 -*-
"""Область бумажной ленты чека: ``printer.paper()`` на светлой «бумаге».

Виджет прокручиваемый (``tk.Text`` + полоса прокрутки), моноширинный шрифт,
автопрокрутка вниз при появлении новых строк, действие «Очистить» вызывает
``printer.clear()``, действие «ПИТ» вызывает ``printer.feed(1)`` — как клавиша
подачи бумаги на настоящей кассе.

Прокрутка «в руках кассира»: пока он не довёл ленту до конца, новые строки
чека **не** вырывают у него ползунок; как только лента возвращается в низ,
автопрокрутка включается снова. Неверный формат ленты (число, объект вместо
списка строк) не ломает панель — бумага остаётся на последнем удачном
изображении, как у индикатора.
"""

from __future__ import annotations

import tkinter as tk

from . import theme

__all__ = ["ReceiptView"]


class ReceiptView(tk.Frame):
    """Панель чека.

    Публичные методы:

    * :meth:`set_lines` — показать ленту (список строк), с автопрокруткой;
    * :meth:`update_from_printer` — прочитать ``printer.paper()`` / ``text()``;
    * :meth:`clear_paper` — вызвать ``printer.clear()`` и очистить виджет;
    * :meth:`feed` — вызвать ``printer.feed(n)``.
    """

    def __init__(self, parent, printer=None, on_action=None, **kwargs):
        super().__init__(
            parent,
            bg=theme.COLORS["receipt_bg"],
            relief="raised",
            bd=3,
            highlightthickness=0,
            **kwargs,
        )
        self.printer = printer
        self.on_action = on_action
        self._rendered: tuple[str, ...] | None = None
        self._autoscroll = True
        #: Пока True, изменения прокрутки считаются нашими, а не пользовательскими.
        self._programmatic = False

        # --- заголовок панели с кнопками «ПИТ» / «Очистить» --------------
        head = tk.Frame(self, bg=theme.COLORS["receipt_bg"])
        head.pack(side="top", fill="x", padx=4, pady=(4, 2))

        tk.Label(
            head,
            text="ЧЕК  (бумажная лента)",
            bg=theme.COLORS["receipt_bg"],
            fg=theme.COLORS["fg"],
            font=theme.FONTS["label"],
        ).pack(side="left")

        theme.make_button(
            head,
            text="Очистить",
            command=self.clear_paper,
            colour="plain",
            width=9,
            height=1,
            font=theme.FONTS["button_small"],
        ).pack(side="right", padx=(4, 0))

        theme.make_button(
            head,
            text="ПИТ \u2193",
            command=self.feed,
            colour="printer",
            width=7,
            height=1,
            font=theme.FONTS["button_small"],
        ).pack(side="right")

        self.led = tk.Canvas(
            head,
            width=12,
            height=12,
            bg=theme.COLORS["receipt_bg"],
            highlightthickness=0,
            bd=0,
        )
        self.led.pack(side="right", padx=(0, 6))
        self._led_item = self.led.create_oval(2, 2, 10, 10, fill=theme.COLORS["led_off"], outline="")

        # --- «бумага» -----------------------------------------------------
        paper_frame = tk.Frame(self, bg=theme.COLORS["paper_shadow"])
        paper_frame.pack(side="top", fill="both", expand=True, padx=4, pady=(2, 4))

        # Текстовое поле не растягиваем по ширине панели: чековая лента узкая,
        # а остальное место должно остаться фоном «корпуса», а не бумагой.
        paper_shadow = tk.Frame(paper_frame, bg=theme.COLORS["paper_shadow"])
        paper_shadow.pack(side="left", fill="y")

        self.text = tk.Text(
            paper_shadow,
            bg=theme.COLORS["paper"],
            fg=theme.COLORS["paper_fg"],
            font=theme.FONTS["receipt"],
            relief="sunken",
            bd=3,
            wrap="none",
            width=40,
            height=10,
            insertbackground=theme.COLORS["paper_fg"],
            padx=8,
            pady=6,
            highlightthickness=0,
            state="disabled",
            cursor="arrow",
        )
        # прокрутка бумаги идёт по вертикали, поэтому поле тянем по высоте
        self._paper_shadow = paper_shadow
        scroll = tk.Scrollbar(paper_frame, command=self.text.yview, width=14)
        self.text.configure(yscrollcommand=self._on_yscroll)
        scroll.pack(side="right", fill="y")
        # ширина бумаги задана шрифтом (width=40), по горизонтали не растягиваем
        self.text.pack(side="left", fill="y")
        self._scroll = scroll

        # Шапка «чека» на бумаге — как отпечатанная типографским способом.
        self._header = (
            "\u0410\u041e \"\u042d\u0422\u0418\u041c\"  \u0421\u041f\u0431",
            "------------------------------",
        )
        self._write_lines(list(self._header))

    # -- данные ------------------------------------------------------------

    def set_lines(self, lines) -> None:
        """Показать строки ленты (автопрокрутка вниз, пока кассир внизу).

        Неверный формат не роняет панель: принимаются только ``list``/``tuple``
        строк, ``str`` (режется по переводам строки) и ``bytes`` (читаются как
        UTF-8). Всё остальное — ``int``, словарь, чужой объект — игнорируется,
        бумага остаётся на последнем удачном изображении.
        """
        if lines is None:
            lines = []
        if isinstance(lines, (bytes, bytearray)):
            lines = bytes(lines).decode("utf-8", "replace")
        if isinstance(lines, str):
            lines = lines.split("\n")
        elif not isinstance(lines, (list, tuple)):
            # Не лента — оставляем прежнюю бумагу (и обновляем лампу).
            self._update_led()
            return
        rendered = tuple(str(line) for line in lines)
        if rendered == self._rendered:
            self._update_led()
            return
        self._rendered = rendered
        self._write_lines(list(self._header) + list(rendered), force_scroll=self._autoscroll)

    def update_from_printer(self, printer=None) -> None:
        """Прочитать ленту из ``printer`` (по контракту: ``paper()`` или ``text()``)."""
        printer = printer if printer is not None else self.printer
        if printer is None:
            return
        lines = None
        paper = getattr(printer, "paper", None)
        if callable(paper):
            try:
                lines = paper()
            except Exception:
                lines = None
        if not isinstance(lines, (list, tuple)):
            # Ни списка, ни кортежа (None, строка, число, байты) — это не
            # лента: пробуем запасной text(). Он может содержать "\\n"
            # внутри одной строки, поэтому режем по переводам строки.
            text_attr = getattr(printer, "text", None)
            if callable(text_attr):
                try:
                    value = text_attr()
                except Exception:
                    value = None
                if value is not None:
                    lines = str(value).split("\n")
        self.set_lines([] if lines is None else lines)
        self._update_led(printer)

    def _update_led(self, printer=None) -> None:
        printer = printer if printer is not None else self.printer
        busy = False
        if printer is not None:
            try:
                busy = bool(printer.is_busy())
            except Exception:
                busy = False
        colour = theme.COLORS["led_on"] if busy else theme.COLORS["led_off"]
        try:
            self.led.itemconfigure(self._led_item, fill=colour)
        except tk.TclError:
            pass

    # -- внутреннее --------------------------------------------------------

    def _on_yscroll(self, first, last) -> None:
        """``yscrollcommand``: двигаем ползунок и замечаем руки кассира.

        Свои прокрутки (при переписывании бумаги) идут под флагом
        ``_programmatic`` и на ``_autoscroll`` не влияют.
        """
        scroll = getattr(self, "_scroll", None)
        if scroll is not None:
            try:
                scroll.set(first, last)
            except tk.TclError:
                pass
        if getattr(self, "_programmatic", False):
            return
        try:
            bottom = float(last)
        except (TypeError, ValueError):
            return
        # Лента уведена от низа -> не дёргаем её за собой новыми строками.
        self._autoscroll = bottom >= 0.999

    def _write_lines(self, lines, force_scroll: bool = True) -> None:
        text = self.text
        keep_top = None
        if not force_scroll:
            # Переписывание бумаги сбрасывает вид в начало — сохраняем то,
            # где кассир остановился, и возвращаем его после вставки.
            try:
                keep_top = float(text.yview()[0])
            except (tk.TclError, TypeError, ValueError, IndexError):
                keep_top = None
        self._programmatic = True
        try:
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("1.0", "\n".join(lines))
            text.configure(state="disabled")
        except tk.TclError:
            self._programmatic = False
            return
        if force_scroll:
            self.scroll_to_bottom()
        elif keep_top is not None:
            try:
                text.yview_moveto(keep_top)
            except tk.TclError:
                pass
        self._programmatic = False

    def scroll_to_bottom(self) -> None:
        try:
            self.text.see("end-1c")
        except tk.TclError:
            pass

    # -- действия ----------------------------------------------------------

    def clear_paper(self) -> None:
        """Очистить бумагу: ``printer.clear()`` + очистка виджета."""
        if self.printer is not None:
            clear = getattr(self.printer, "clear", None)
            if callable(clear):
                try:
                    clear()
                except Exception:
                    pass
        self._rendered = ()
        self._write_lines(list(self._header))
        if self.on_action is not None:
            try:
                self.on_action("clear")
            except Exception:
                pass

    def feed(self) -> None:
        """Подать бумагу: ``printer.feed(1)``."""
        if self.printer is not None:
            feed = getattr(self.printer, "feed", None)
            if callable(feed):
                try:
                    feed(1)
                except TypeError:
                    try:
                        feed()
                    except Exception:
                        pass
                except Exception:
                    pass
        self.update_from_printer()
        if self.on_action is not None:
            try:
                self.on_action("feed")
            except Exception:
                pass

    def get_text(self) -> str:
        """Текущее содержимое виджета (для тестов)."""
        try:
            return self.text.get("1.0", "end-1c")
        except tk.TclError:
            return ""
