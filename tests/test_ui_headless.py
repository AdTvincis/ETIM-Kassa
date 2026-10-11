# -*- coding: utf-8 -*-
"""Headless-тесты интерфейса Tkinter (``ui/``) с mock-платой.

Тесты не требуют дисплея: если ``tkinter.Tk()`` не создаётся, тест помечается
``unittest.SkipTest``. Никакие файлы ``board/`` не импортируются — mock
реализует **ровно** контракт ``docs/board_contract.md``.

Запуск::

    python -m unittest tests.test_ui_headless -v
"""

from __future__ import annotations

import os
import unittest

# --- 1. Импорт не должен падать и не должен создавать окно ---------------

import ui.app as ui_app  # noqa: E402
from ui import keypad as ui_keypad  # noqa: E402
from ui import receipt as ui_receipt  # noqa: E402
from ui import screen as ui_screen  # noqa: E402
from ui import theme as ui_theme  # noqa: E402


def _tk_available():
    """Вернуть (True, tk) если дисплей есть, иначе (False, причина)."""
    try:
        import tkinter as tk
    except Exception as exc:  # pragma: no cover - tkinter есть в stdlib
        return False, "tkinter недоступен: %r" % (exc,)
    try:
        root = tk.Tk()
        # Ни одного ВИДИМОГО окна (заказ пользователя): проверка создания
        # работает и у withdraw-корня.
        root.withdraw()
    except Exception as exc:
        return False, "нет дисплея/Tk: %r" % (exc,)
    try:
        root.destroy()
    except Exception:
        pass
    return True, tk


TK_OK, TK_REASON = _tk_available()


# --------------------------------------------------------------------------
# Mock-плата: только контракт docs/board_contract.md
# --------------------------------------------------------------------------


class MockDisplay:
    """``board.display`` по контракту: columns/lines/text/render_rows/cell_segments."""

    def __init__(self, columns=20, lines=1):
        self.columns = columns
        self.lines = lines
        self._text = " " * (columns * lines)

    # -- управление (только для теста) ------------------------------------
    def set_text(self, text: str) -> None:
        self._text = (text or "").ljust(self.columns * self.lines)[: self.columns * self.lines]

    # -- контракт ---------------------------------------------------------
    def text(self) -> str:
        return self._text

    def cell_segments(self, index: int) -> int:
        return 0

    def render_rows(self, scale: int = 1) -> list:
        rows = []
        for line_no in range(self.lines):
            line = self._text[line_no * self.columns:(line_no + 1) * self.columns]
            cells = []
            for ch in line:
                cells.append(ui_screen.render_segments(ch))
            for y in range(ui_screen.CELL_H):
                rows.append("".join(cell[y] for cell in cells))
        return rows


class MockKeyboard:
    """``board.keyboard``: keys/press/release/tap/is_pressed."""

    KEYS = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "00", ".",
        "СУММА", "ОПЛ", "X", "ИТОГ", "ОТМЕНА", "ВОЗВРАТ", "СКИДКА",
        "КАССИР", "СЕРВИС", "РЕЖИМ", "ВВОД", "СБРОС", "ПОДЫТОГ",
        "ЧЕК", "КС", "Z", "ПИТ",
        "СТРЕЛКА_ВЛЕВО", "СТРЕЛКА_ВПРАВО", "ПРОБЕЛ", "ТАБ",
    ]

    def __init__(self):
        self.keys = list(self.KEYS)
        self.pressed = set()
        self.log = []
        self._held = set()

    def press(self, name: str) -> None:
        self.pressed.add(name)
        self._held.add(name)
        self.log.append(("press", name))

    def release(self, name: str) -> None:
        self.pressed.discard(name)
        self._held.discard(name)
        self.log.append(("release", name))

    def tap(self, name: str) -> None:
        self.press(name)
        self.release(name)
        self.log.append(("tap", name))

    def is_pressed(self, name: str) -> bool:
        return name in self.pressed


class MockPrinter:
    """``board.printer``: feed/paper/text/clear/is_busy."""

    WIDTH = 20

    def __init__(self):
        self._lines = [""]
        self.busy = False
        self.feeds = 0
        self.cleared = 0

    def feed(self, lines: int = 1) -> None:
        self.feeds += int(lines or 1)
        for _ in range(int(lines or 1)):
            self._lines.append("")

    def paper(self) -> list:
        return list(self._lines)

    def text(self) -> str:
        return "\n".join(self._lines)

    def clear(self) -> None:
        self.cleared += 1
        self._lines = [""]

    def is_busy(self) -> bool:
        return self.busy

    # -- управление (только для теста) ------------------------------------
    def type_char(self, ch: str) -> None:
        if len(self._lines[-1]) >= self.WIDTH:
            self._lines.append("")
        self._lines[-1] += ch

    def type_line(self, line: str) -> None:
        for ch in line:
            self.type_char(ch)


class MockBoard:
    """Сборка mock-платы: display + keyboard + printer (+ status_text)."""

    def __init__(self):
        self.display = MockDisplay()
        self.keyboard = MockKeyboard()
        self.printer = MockPrinter()

    def status_text(self) -> str:
        return "РЕЖИМ: КАССА"


# --------------------------------------------------------------------------
# Тесты
# --------------------------------------------------------------------------


class TestUiModuleShape(unittest.TestCase):
    """Структура модулей и headless-безопасность импорта."""

    def test_imports_do_not_create_windows(self):
        if not TK_OK:
            self.skipTest(TK_REASON)
        import tkinter as tk

        # Импорт уже выполнен на уровне модуля: окон быть не должно.
        root = tk.Tk()
        # Полностью за экраном (заказ пользователя: никаких видимых окон),
        # но mapped — тесты ниже проверяют winfo_ismapped().
        root.geometry("+-30000+-30000")
        try:
            before = len(root.winfo_children())
            import importlib

            importlib.reload(ui_theme)
            importlib.reload(ui_screen)
            importlib.reload(ui_keypad)
            importlib.reload(ui_receipt)
            importlib.reload(ui_app)
            self.assertEqual(before, len(root.winfo_children()))
        finally:
            root.destroy()

    def test_constructor_signature(self):
        import inspect

        params = list(inspect.signature(ui_app.CashRegisterApp.__init__).parameters)
        self.assertEqual(params[:2], ["self", "board"])
        self.assertIn("title", params)
        self.assertIn("on_quit", params)
        self.assertTrue(callable(ui_app.CashRegisterApp.refresh))
        self.assertTrue(callable(ui_app.CashRegisterApp.run))

    def test_segments_renderer_shape(self):
        rows = ui_screen.render_segments("8")
        self.assertEqual(len(rows), ui_screen.CELL_H)
        self.assertTrue(all(len(r) == ui_screen.CELL_W for r in rows))
        self.assertTrue(all(ch in "# " for r in rows for ch in r))
        blank = ui_screen.render_segments(" ")
        self.assertTrue(all(ch == " " for r in blank for ch in r))

    def test_build_layout_from_keys(self):
        layout = ui_keypad.build_layout(MockKeyboard.KEYS)
        flat = [k for row in layout["digits"] for k in row]
        for digit in list("0123456789") + ["00", "."]:
            self.assertIn(digit, flat, "нет цифры %r в раскладке" % digit)
        for name in ("СУММА", "ОПЛ", "X", "ИТОГ", "ВВОД", "СБРОС", "ОТМЕНА"):
            self.assertIn(name, layout["actions"], "нет клавиши %r в колонке" % name)
        for name in ("КАССИР", "СЕРВИС", "РЕЖИМ", "ЧЕК", "КС", "Z", "ПИТ"):
            self.assertIn(name, layout["service"], "нет клавиши %r в служебном ряду" % name)
        # ПОДЫТОГ, ВОЗВРАТ и СКИДКА мест в основной раскладке не имеют и
        # уходят в служебный ряд (ничего не теряется)
        self.assertEqual(layout["extra"], ["ВОЗВРАТ", "СКИДКА", "ПОДЫТОГ"])

    def test_build_layout_english_synonyms(self):
        layout = ui_keypad.build_layout(
            ["0", "1", "SUMM", "PAY", "MULT", "ITOG", "ENTER", "CLEAR", "CANCEL", "SUBTOTAL"]
        )
        self.assertIn("SUMM", layout["actions"], "SUMM/СУММА должна попасть в колонку")
        self.assertIn("PAY", layout["actions"])
        self.assertIn("MULT", layout["actions"])
        self.assertIn("ITOG", layout["actions"])
        self.assertIn("CANCEL", layout["actions"])
        # ПОДЫТОГ/SUBTOTAL места в колонке не имеет — уходит в служебный ряд
        self.assertIn("SUBTOTAL", layout["extra"])
        self.assertEqual(set(layout["extra"]), {"SUBTOTAL"})
        self.assertEqual([k for row in layout["digits"] for k in row], ["1", "0"])

    def test_layout_keeps_unknown_keys(self):
        layout = ui_keypad.build_layout(["7", "ФАНТАЗИЯ"])
        self.assertIn("ФАНТАЗИЯ", layout["extra"])


@unittest.skipUnless(TK_OK, TK_REASON)
class TestAppWithMockBoard(unittest.TestCase):
    """Сборка настоящего окна с mock-платой."""

    def setUp(self):
        self.board = MockBoard()
        self.app = ui_app.CashRegisterApp(self.board, on_quit=self._on_quit)
        self.quit_called = False
        # Синтетические события Tk (event_generate) доставляются только
        # отображённым виджетам и только окну, которое реально имеет фокус
        # ввода. В одном процессе Tk-окон создаётся много (по одному на тест),
        # поэтому каждый раз явно прогоняем геометрию и забираем фокус.
        self.app.root.deiconify()
        self.app.root.update()
        self.app.root.focus_force()
        self.app.root.update()

    def _on_quit(self):
        self.quit_called = True

    def tearDown(self):
        try:
            self.app.quit()
        except Exception:
            pass

    # -- 1. базовая сборка и повторный refresh ----------------------------

    def test_build_and_refresh_repeatedly(self):
        self.assertIsInstance(self.app.root, object)
        for _ in range(5):
            self.app.refresh()
        self.assertGreater(self.app._counter, 0)

    def test_window_has_required_parts(self):
        for attr in ("screen", "keypad", "receipt", "status_var", "root"):
            self.assertTrue(hasattr(self.app, attr), "нет атрибута %s" % attr)
        self.assertGreater(len(self.app.keypad.buttons), 20)

    # -- 2. все кнопки классические и объёмные ----------------------------

    def test_buttons_are_classic_raised(self):
        for name, button in self.app.keypad.buttons.items():
            self.assertEqual(button.cget("relief"), "raised", "%s: не raised" % name)
            self.assertGreaterEqual(int(button.cget("bd")), 4, "%s: тонкая рамка" % name)
            self.assertTrue(str(button.cget("bg")).startswith("#"), "%s: нет цвета" % name)

    def test_buttons_have_different_colours(self):
        colours = {str(b.cget("bg")) for b in self.app.keypad.buttons.values()}
        self.assertGreaterEqual(len(colours), 4, "кнопки должны быть разного цвета: %r" % colours)
        cancel = self.app.keypad.buttons.get("ОТМЕНА")
        self.assertIsNotNone(cancel)
        self.assertIn("b0", str(cancel.cget("bg")).lower())

    def test_button_press_sinks_visually(self):
        button = self.app.keypad.buttons["7"]
        self.assertTrue(button.winfo_ismapped(), "кнопка не отображена — события не дойдут")
        cx, cy = self._centre(button)
        button.event_generate("<ButtonPress-1>", x=cx, y=cy, when="now")
        self.app.root.update()
        self.assertEqual(button.cget("relief"), "sunken")
        button.event_generate("<ButtonRelease-1>", x=cx, y=cy, when="now")
        self.app.root.update()
        self.assertEqual(button.cget("relief"), "raised")

    @staticmethod
    def _centre(widget):
        """Координаты центра виджета для синтетического клика.

        Без явных ``x``/``y`` Tk считает курсор в точке (0,0), и
        ``tk::ButtonUp`` не вызывает команду (``Priv(window)`` не тот).
        """
        width = max(1, widget.winfo_width())
        height = max(1, widget.winfo_height())
        return width // 2, height // 2

    # -- 3. нажатия клавиш ------------------------------------------------

    def test_tap_via_button_command(self):
        """Клик мышью = вызов команды кнопки; команда обязана дойти до платы."""
        keys = ["7", "8", "00", ".", "СУММА", "ОПЛ", "ИТОГ", "ВВОД", "ОТМЕНА", "ПИТ"]
        for name in keys:
            self.app.keypad.buttons[name].invoke()
        for name in keys:
            self.assertIn(("tap", name), self.board.keyboard.log, "нет tap(%r)" % name)

    def test_mouse_click_on_button(self):
        """Синтетический клик мышью: кнопка вдавливается и возвращается."""
        button = self.app.keypad.buttons["5"]
        cx, cy = self._centre(button)
        self.assertEqual(button.cget("relief"), "raised")
        button.event_generate("<ButtonPress-1>", x=cx, y=cy, when="now")
        self.app.root.update()
        self.assertEqual(button.cget("relief"), "sunken", "кнопка не вдавилась")
        button.event_generate("<ButtonRelease-1>", x=cx, y=cy, when="now")
        self.app.root.update()
        self.assertEqual(button.cget("relief"), "raised", "кнопка не вернулась")

    def test_button_command_is_wired_to_keyboard_tap(self):
        """Команда каждой кнопки действительно вызывает keyboard.tap(name)."""
        for name in ["5", "ПИТ", "ОТМЕНА", "СУММА"]:
            self.board.keyboard.log.clear()
            self.app.keypad.buttons[name].invoke()
            self.assertIn(("tap", name), self.board.keyboard.log, "нет tap(%r)" % name)

    def test_physical_keyboard_press_release(self):
        self.app.root.event_generate("<KeyPress-3>", when="now")
        self.app.root.update()
        self.assertTrue(self.board.keyboard.is_pressed("3"))
        self.app.root.event_generate("<KeyRelease-3>", when="now")
        self.app.root.update()
        self.assertFalse(self.board.keyboard.is_pressed("3"))

        self.app.root.event_generate("<KeyPress-Return>", when="now")
        self.app.root.update()
        self.assertTrue(self.board.keyboard.is_pressed("ВВОД"))
        self.app.root.event_generate("<KeyRelease-Return>", when="now")
        self.app.root.update()
        self.assertFalse(self.board.keyboard.is_pressed("ВВОД"))

    def test_physical_keys_are_bound(self):
        """Проверка самой привязки физической клавиатуры (без event_generate)."""
        bound_sequences = {seq for seq, _ in self.app.keypad._bindings}
        for seq in ("<KeyPress-0>", "<period>", "<Return>", "<Escape>", "<Left>", "<space>"):
            self.assertIn(seq, bound_sequences)
        # привязки ведут именно к клавиатуре платы
        self.app.keypad.press("СБРОС")
        self.assertTrue(self.board.keyboard.is_pressed("СБРОС"))
        self.app.keypad.release("СБРОС")

    def test_press_release_api_directly(self):
        self.app.keypad.press("9")
        self.assertTrue(self.board.keyboard.is_pressed("9"))
        self.app.keypad.release("9")
        self.assertFalse(self.board.keyboard.is_pressed("9"))

    # -- 4. экран ----------------------------------------------------------

    def test_screen_follows_display_text(self):
        self.board.display.set_text("ИТОГ        1234.56")
        self.app.refresh()
        self.assertEqual(self.app.screen._matrix()[0][:5], ui_screen.render_segments("И")[0])
        self.assertGreater(len(self.app.screen._matrix()), 0)

    def test_screen_survives_broken_render_rows(self):
        broken = BrokenRowsDisplay(columns=20, lines=1)
        self.app.screen.set_geometry(columns=20, lines=1)
        self.app.screen.update_from_display(broken)
        self.assertIsNotNone(self.app.screen._matrix())
        self.app.refresh()  # не должен бросить

    def test_refresh_skips_screen_work_when_text_unchanged(self):
        """Новое гарантия скорости: пока текст индикатора не изменился,
        ``refresh()`` не идёт в тяжёлый путь ``update_from_display``
        (``render_rows`` + пересборка матрицы) — рисуем только при
        реальном изменении содержимого.  Раньше каждый тик (50 мс) строил
        матрицу заново, даже когда экран стоял без изменений."""
        calls = {"n": 0}
        real_render = self.board.display.render_rows

        def counting_render(scale=1):
            calls["n"] += 1
            return real_render(scale)

        self.board.display.render_rows = counting_render
        self.board.display.set_text("ИТОГ        1234.56")
        self.app.refresh()                      # изменилось -> полный путь
        first = calls["n"]
        self.assertGreater(first, 0, "первый refresh обязан отрисовать экран")
        for _ in range(3):
            self.app.refresh()                  # без изменений -> без отрисовки
        self.assertEqual(
            calls["n"], first,
            "refresh перерисовывает неизменённый индикатор (render_rows x%d)" % calls["n"],
        )
        self.board.display.set_text("ИТОГ        1234.57")
        self.app.refresh()                      # новое содержимое -> снова полный путь
        self.assertGreater(calls["n"], first, "изменение текста не дошло до экрана")

    def test_refresh_reports_changed_text_after_an_error(self):
        """Ошибка платы не «залипает»: после неё следующий refresh с живым
        содержимым обязан снова проходить полным путём, убрать «ОШИБКА» и
        показать живой экран (кэш текста сбрасывается при ошибке)."""
        state = {"fail": True}
        display = self.board.display
        real_text = display.text
        real_render = display.render_rows

        def flaky_text():
            if state["fail"]:
                raise RuntimeError("display сломался")
            return real_text()

        def flaky_render(scale=1):
            if state["fail"]:
                raise RuntimeError("display сломался")
            return real_render(scale)

        display.text = flaky_text
        display.render_rows = flaky_render
        # оба пути чтения упали -> fatal -> «ОШИБКА ЭКРАНА» в статусе
        self.app.refresh()
        self.assertTrue(self.app.error_text)
        self.assertIn("ОШИБКА", self.app.status_var.get())
        state["fail"] = False                   # плата ожила с новым текстом
        display.set_text("ВОССТАНОВЛЕН")
        self.app.refresh()
        self.assertIsNone(self.app.error_text,
                         "ошибка должна уйти после восстановления платы")
        matrix = "".join(self.app.screen._matrix())
        self.assertIn("#", matrix, "живой экран не показался после ошибки")

    # -- 5. чек ------------------------------------------------------------

    def test_receipt_updates_from_printer(self):
        for ch in "ХЛЕБ 12.50":
            self.board.printer.type_char(ch)
        self.app.refresh()
        widget_text = self.app.receipt.get_text()
        self.assertIn("ХЛЕБ 12.50", widget_text)

        # принтер шириной 20 знаков переносит строку — проверяем по началу
        self.board.printer.type_line("МОЛОКО 55.00")
        self.app.refresh()
        self.assertIn("МОЛОКО", self.app.receipt.get_text())
        self.assertIn("ХЛЕБ 12.50", self.app.receipt.get_text())

    def test_receipt_wrapped_line_reaches_bottom(self):
        # ширина ленты 20 знаков: "ПЕЧЕНЬЕ 123.45" (14) + "ЧАЙ 7.00" переносится
        self.board.printer.type_line("ПЕЧЕНЬЕ 123.45")
        self.board.printer.type_line("ЧАЙ 7.00")
        self.app.refresh()
        text = self.app.receipt.get_text()
        self.assertIn("ПЕЧЕНЬЕ 123.45", text)
        self.assertIn("ЧАЙ 7.", text)
        # содержимое совпадает с тем, что отдаёт плата, строка в строку
        paper = self.board.printer.paper()
        self.assertEqual(text.split("\n")[2:], paper)
        # автопрокрутка: конец ленты виден (yview смотрит в самый низ)
        self.assertGreaterEqual(self.app.receipt.text.yview()[1], 0.9)

    def test_receipt_only_redraws_on_change(self):
        self.board.printer.type_line("СЫР 99.90")
        self.app.refresh()
        first = self.app.receipt._rendered
        self.app.refresh()
        self.assertEqual(first, self.app.receipt._rendered)

    def test_receipt_clear_button_calls_printer_clear(self):
        self.board.printer.type_line("ТОВАР 1.00")
        self.app.refresh()
        self.assertIn("ТОВАР", self.app.receipt.get_text())
        self.app._clear_receipt()
        self.assertEqual(self.board.printer.cleared, 1)
        self.assertNotIn("ТОВАР", self.app.receipt.get_text())

    def test_receipt_feed(self):
        before = self.board.printer.feeds
        self.app.receipt.feed()
        self.assertEqual(self.board.printer.feeds, before + 1)
        self.app.refresh()

    # -- 6. устойчивость refresh ------------------------------------------

    def test_refresh_never_raises_on_hostile_board(self):
        hostile = HostileBoard()
        app = ui_app.CashRegisterApp(hostile, on_quit=None)
        try:
            for _ in range(3):
                app.refresh()  # каждый вызов обязан молчать
        finally:
            app.quit()

    def test_refresh_tolerates_missing_attributes(self):
        class Bare:
            pass

        app = ui_app.CashRegisterApp(Bare(), on_quit=None)
        try:
            app.refresh()
            app.refresh()
        finally:
            app.quit()

    def test_refresh_tolerates_display_changing_shape(self):
        self.app.refresh()
        self.board.display.columns = 12  # плата «сменила» геометрию
        self.board.display.set_text("123456789012")
        self.app.refresh()
        self.app.refresh()

    def test_quit_calls_callback_once(self):
        self.app.quit()
        self.app.quit()
        self.assertTrue(self.quit_called)

    def test_display_mode_switch(self):
        self.app.mode_var.set(ui_app.DISPLAY_MODES[1][0])
        self.app.root.update()
        self.app.refresh()
        self.assertEqual(self.app.screen.columns, ui_app.DISPLAY_MODES[1][1])
        self.assertEqual(self.app.screen.lines, ui_app.DISPLAY_MODES[1][2])

    def test_status_bar_populated(self):
        self.app.refresh()
        self.assertTrue(self.app.status_var.get())
        self.assertIn("принтер", self.app.status_var.get())

    # -- 7. требования хоста (main.py), зафиксированы Lead'ом --------------

    def test_status_dict_from_board(self):
        """``board.status()`` -> dict: берём source/reason, ничего не ломаем."""
        self.board.status = lambda: {"source": "ROM", "reason": "нет нижней половины"}
        self.app.refresh()
        self.assertIn("ROM", self.app.status_var.get())

    def test_status_dict_via_status_text(self):
        self.board.status_text = lambda: {"source": "X", "reason": "Y"}
        self.app.refresh()
        status = self.app.status_var.get()
        self.assertIn("X", status)
        self.assertIn("Y", status)

    def test_status_raising_is_ignored(self):
        def boom():
            raise RuntimeError("status сломан")
        self.board.status = boom
        self.app.refresh()
        self.assertTrue(self.app.status_var.get())

    def test_refresh_reports_display_error_on_screen(self):
        class BadDisplay:
            columns, lines = 20, 1

            def text(self):
                raise RuntimeError("display.text() упал")

            def render_rows(self, scale=1):
                raise RuntimeError("display.render_rows() упал")

        hostile = HostileBoard()
        app = ui_app.CashRegisterApp(hostile)
        try:
            app.refresh()
            self.assertTrue(app.error_text, "ошибка платы должна попасть в состояние")
            self.assertIn("ОШИБКА", app.status_var.get())
            # экран не пустой: показан текст ошибки
            self.assertTrue(any(app.screen._matrix()))
        finally:
            app.quit()

    def test_refresh_before_boot_with_zero_board(self):
        """Плата до boot(): всё нули/пусто — refresh обязан молчать."""
        class ZeroDisplay:
            columns = 20
            lines = 1

            def __init__(self):
                self._t = "\x00" * 20

            def text(self):
                return self._t

            def render_rows(self, scale=1):
                return [" " * 100] * 7

        class ZeroBoard:
            def __init__(self):
                self.display = ZeroDisplay()
                self.keyboard = MockKeyboard()
                self.printer = MockPrinter()

        app = ui_app.CashRegisterApp(ZeroBoard())
        try:
            for _ in range(3):
                app.refresh()
        finally:
            app.quit()

    def test_refresh_without_printer_or_keyboard(self):
        class OnlyDisplay:
            columns, lines = 20, 1

            def text(self):
                return " " * 20

        app = ui_app.CashRegisterApp(OnlyDisplay())
        try:
            app.refresh()
            self.assertEqual(app.keypad.buttons, {})
        finally:
            app.quit()

    def test_window_has_protocol_handler(self):
        protocol = self.app.root.protocol("WM_DELETE_WINDOW")
        self.assertTrue(protocol)
        self.assertNotEqual(protocol, "")

    def test_run_method_is_callable(self):
        self.assertTrue(callable(self.app.run))
        self.assertTrue(callable(self.app.refresh))


# --------------------------------------------------------------------------
# Крайние состояния: пустой/длинный чек, неверный ввод, переключение режимов
# --------------------------------------------------------------------------


class BrokenKeyboard:
    """Клавиатура без раскладки (``keys is None``), у которой всё падает."""

    keys = None

    def press(self, name):
        raise RuntimeError("press упал")

    def release(self, name):
        raise RuntimeError("release упал")

    def tap(self, name):
        raise RuntimeError("tap упал")


class _TkFixture(unittest.TestCase):
    """База дешёвых виджетных тестов: собственное маленькое окно Tk."""

    GEOMETRY = "900x500+30+40"

    def setUp(self):
        import tkinter as tk

        self.tk = tk
        self.root = tk.Tk()
        # Размер из GEOMETRY, но позиция — полностью за экраном: пользователю
        # нельзя показывать окна (заказ), при этом корень остаётся mapped,
        # чтобы winfo_ismapped() и геометрические проверки работали как раньше.
        size = self.GEOMETRY.split("+", 1)[0]
        self.root.geometry(size + "+-30000+-30000")
        self.root.update_idletasks()
        self.root.update()

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass


@unittest.skipUnless(TK_OK, TK_REASON)
class TestReceiptEdgeCases(_TkFixture):
    """Пустая и длинная лента, прокрутка, неверный формат ``paper()``."""

    def setUp(self):
        super().setUp()
        self.printer = MockPrinter()
        self.receipt = ui_receipt.ReceiptView(self.root, printer=self.printer)
        self.receipt.pack(side="top", fill="both", expand=True, padx=4, pady=4)
        self.root.update_idletasks()
        self.root.update()

    def _fill(self, count: int) -> None:
        """Напечатать ``count`` строк ровно по ширине ленты (без переносов)."""
        width = self.printer.WIDTH
        for index in range(count):
            self.printer.type_line(("ТОВАР %03d 10.00" % index).ljust(width))
        self.receipt.update_from_printer()

    # -- пустой чек --------------------------------------------------------

    def test_empty_receipt_shows_header_only(self):
        self.receipt.clear_paper()
        self.receipt.update_from_printer()
        lines = self.receipt.get_text().split("\n")
        self.assertEqual(lines[0], '\u0410\u041e "\u042d\u0422\u0418\u041c"  \u0421\u041f\u0431')
        self.assertTrue(all(not line.strip() for line in lines[2:]), lines)
        self.assertEqual([line for line in self.printer.paper() if line.strip()], [])
        # пустая лента всё равно держится внизу
        self.assertGreaterEqual(self.receipt.text.yview()[1], 0.9)

    def test_clear_on_empty_receipt_twice_is_safe(self):
        self.receipt.clear_paper()
        self.receipt.clear_paper()
        self.assertEqual(self.printer.cleared, 2)
        lines = self.receipt.get_text().split("\n")
        self.assertTrue(all(not line.strip() for line in lines[2:]), lines)
        self.assertGreaterEqual(self.receipt.text.yview()[1], 0.9)

    # -- длинный чек -------------------------------------------------------

    def test_long_receipt_is_scrolled_to_bottom(self):
        self._fill(120)
        self.assertEqual(len(self.printer.paper()), 120)
        text = self.receipt.get_text()
        self.assertIn("ТОВАР 000 10.00", text)
        self.assertIn("ТОВАР 119 10.00", text)
        self.assertGreaterEqual(self.receipt.text.yview()[1], 0.9)

    def test_user_scroll_up_is_not_yanked_by_new_lines(self):
        self._fill(120)
        self.receipt.text.yview_moveto(0.0)
        self.root.update()
        self.assertFalse(
            self.receipt._autoscroll,
            "кассир увёл ленту — автопрокрутка должна выключиться",
        )
        self.printer.type_line("НОВАЯ СТРОКА")
        self.receipt.update_from_printer()
        self.assertFalse(self.receipt._autoscroll)
        self.assertLess(self.receipt.text.yview()[0], 0.1, "прокрутку вырвало из рук")
        # довели ленту до конца — автопрокрутка включается снова
        self.receipt.text.yview_moveto(1.0)
        self.root.update()
        self.assertTrue(self.receipt._autoscroll)
        self.printer.type_line("ПОСЛЕДНЯЯ")
        self.receipt.update_from_printer()
        self.assertGreaterEqual(self.receipt.text.yview()[1], 0.9)

    def test_scrollbar_is_wired_to_the_text(self):
        self._fill(120)
        self.assertNotEqual(str(self.receipt.text.cget("yscrollcommand")), "")
        self.assertNotEqual(str(self.receipt._scroll.cget("command")), "")
        self.receipt.text.yview_moveto(0.0)
        self.root.update()
        self.assertLess(self.receipt.text.yview()[1], 0.9)

    # -- неверный ввод -----------------------------------------------------

    def test_paper_of_wrong_type_keeps_previous_receipt(self):
        self.printer.type_line("ХЛЕБ 12.50")
        self.receipt.update_from_printer()
        before = self.receipt.get_text()
        self.assertIn("ХЛЕБ 12.50", before)
        for bad in (42, 3.14, object(), {"строка": 1}):
            self.receipt.set_lines(bad)  # не должно бросить
            self.assertEqual(self.receipt.get_text(), before, repr(bad))
        # paper(), отдавший не список, уводит на запасной text()
        self.printer.paper = lambda: 42
        self.receipt.update_from_printer()
        self.assertEqual(self.receipt.get_text(), before)

    def test_paper_as_bytes_is_decoded(self):
        class BytesPrinter:
            def paper(self):
                return "ХЛЕБ 12.50\nЧАЙ 7.00".encode("utf-8")

            def is_busy(self):
                return False

        self.receipt.update_from_printer(BytesPrinter())
        text = self.receipt.get_text()
        self.assertIn("ХЛЕБ 12.50", text)
        self.assertIn("ЧАЙ 7.00", text)

    def test_printer_without_paper_and_text_is_tolerated(self):
        class EmptyPrinter:
            def paper(self):
                return None

            def is_busy(self):
                return False

        self.receipt.update_from_printer(EmptyPrinter())
        lines = self.receipt.get_text().split("\n")
        self.assertTrue(all(not line.strip() for line in lines[2:]), lines)

    def test_broken_printer_never_raises(self):
        class BrokenPrinter:
            def paper(self):
                raise RuntimeError("paper упал")

            def text(self):
                raise RuntimeError("text упал")

            def is_busy(self):
                raise RuntimeError("is_busy упал")

            def feed(self, lines=1):
                raise RuntimeError("feed упал")

            def clear(self):
                raise RuntimeError("clear упал")

        broken = BrokenPrinter()
        self.receipt.update_from_printer(broken)
        self.receipt.printer = broken
        self.receipt.feed()
        self.receipt.clear_paper()
        self.receipt.update_from_printer()
        self.assertTrue(self.receipt.get_text())


@unittest.skipUnless(TK_OK, TK_REASON)
class TestScreenEightCells(_TkFixture):
    """Индикатор 8x1 (реальная плата): 8 знакомест и канва без мёртвых полос."""

    TEXT = "000    0"

    def setUp(self):
        super().setUp()
        self.screen = ui_screen.ScreenWidget(self.root, columns=8, lines=1)
        self.screen.pack(side="top", fill="x", padx=4, pady=4)
        self.root.update_idletasks()
        self.root.update()

    def test_matrix_is_exactly_eight_cells(self):
        self.screen.set_text(self.TEXT)
        matrix = self.screen._matrix()
        self.assertEqual(len(matrix), ui_screen.CELL_H)
        for index, char in enumerate(self.TEXT):
            want = ui_screen.render_segments(char)
            for y in range(ui_screen.CELL_H):
                got = matrix[y][index * ui_screen.CELL_W:(index + 1) * ui_screen.CELL_W]
                self.assertEqual(got, want[y], "ячейка %d, строка %d" % (index, y))

    def test_canvas_matches_drawn_matrix(self):
        self.screen.set_geometry(columns=8, lines=1, max_width=760, max_height=200)
        self.root.update_idletasks()
        self.root.update()
        width, height = self.screen._canvas_size()
        self.assertEqual(self.screen.canvas.winfo_reqwidth(), width)
        self.assertEqual(self.screen.canvas.winfo_reqheight(), height)
        # канва не растянута на всю панель: видимый размер = нарисованная матрица
        self.assertLessEqual(abs(self.screen.canvas.winfo_width() - width), 2)
        self.assertLessEqual(abs(self.screen.canvas.winfo_height() - height), 2)

    def test_screen_draws_lit_and_dim_pixels(self):
        self.screen.set_text("88888888")
        self.root.update()
        items = self.screen.canvas.find_all()
        self.assertGreater(len(items), 0)
        fills = {}
        for item in items:
            key = str(self.screen.canvas.itemcget(item, "fill")).lower()
            fills[key] = fills.get(key, 0) + 1
        self.assertGreater(fills.get(ui_theme.COLORS["screen_on"].lower(), 0), 0,
                           "нет зажжённых точек")
        self.assertGreater(fills.get(ui_theme.COLORS["screen_dim"].lower(), 0), 0,
                           "нет погашенной сетки")

    def test_matrix_fills_canvas_without_dead_strip(self):
        """Точки занимают всю канву: иначе справа остаётся мёртвая полоса.

        ``_canvas_size()`` закладывает пустой столбец между знакоместами —
        рисование обязано использовать тот же зазор, что и расчёт габаритов.
        """
        self.screen.set_text("88888888")
        canvas = self.screen.canvas
        widths = {
            ui_theme.COLORS["screen_on"].lower(),
            ui_theme.COLORS["screen_dim"].lower(),
        }
        boxes = [
            canvas.bbox(item)
            for item in canvas.find_all()
            if str(canvas.itemcget(item, "fill")).lower() in widths
        ]
        boxes = [box for box in boxes if box]
        self.assertTrue(boxes, "канва пуста")
        width, _height = self.screen._canvas_size()
        cell = self.screen.cell_w
        left = min(box[0] for box in boxes)
        right = max(box[2] for box in boxes)
        self.assertLessEqual(abs(left - cell), cell, "матрица прижата к левому краю")
        self.assertLessEqual(width - right, cell * 2 + 2,
                             "мёртвая полоса справа: %d px" % (width - right))

    def test_rows_with_wrong_shape_are_clamped(self):
        self.screen.set_rows(["#" * 500] * 100)
        matrix = self.screen._matrix()
        self.assertEqual(len(matrix), ui_screen.CELL_H * self.screen.lines)
        for row in matrix:
            self.assertEqual(len(row), 8 * ui_screen.CELL_W)
        # слишком короткие строки достраиваются пробелами
        self.screen.set_rows(["#"])
        matrix = self.screen._matrix()
        self.assertEqual(len(matrix), ui_screen.CELL_H)
        self.assertEqual(matrix[0], "#" + " " * (8 * ui_screen.CELL_W - 1))
        # пустая лента -> пустая матрица нужной формы
        self.screen.set_rows([])
        self.assertEqual(
            self.screen._matrix(),
            [" " * (8 * ui_screen.CELL_W)] * ui_screen.CELL_H,
        )


@unittest.skipUnless(TK_OK, TK_REASON)
class TestKeypadInvalidInput(_TkFixture):
    """Крайние состояния клавиатуры: нет платы, нет раскладки, битая плата."""

    def test_keypad_without_keyboard_builds_no_buttons(self):
        keypad = ui_keypad.KeypadFrame(self.root, keyboard=None)
        keypad.pack(side="top", anchor="w")
        self.root.update()
        self.assertEqual(keypad.buttons, {})
        keypad.tap("5")
        keypad.press("5")
        keypad.release("5")  # не должны бросить
        keypad.bind_physical(self.root)
        self.assertEqual(keypad._bindings, [])
        keypad.destroy()

    def test_broken_keyboard_and_unknown_key_are_tolerated(self):
        events = []
        keypad = ui_keypad.KeypadFrame(
            self.root,
            keyboard=BrokenKeyboard(),
            on_key=lambda name, action: events.append((name, action)),
        )
        keypad.pack(side="top", anchor="w")
        self.root.update()
        for action in (keypad.tap, keypad.press, keypad.release):
            action("НЕТ_ТАКОЙ")  # плата кидает исключение — гасим сами
        self.assertEqual(
            events,
            [
                ("НЕТ_ТАКОЙ", "tap"),
                ("НЕТ_ТАКОЙ", "press"),
                ("НЕТ_ТАКОЙ", "release"),
            ],
        )
        self.assertNotIn("НЕТ_ТАКОЙ", keypad.buttons)
        keypad.reset_visuals()
        keypad.destroy()


@unittest.skipUnless(TK_OK, TK_REASON)
class TestModeSwitchingAndFunctionKeys(unittest.TestCase):
    """Переключение режимов индикатора, мусор в геометрии, F5/F8."""

    def setUp(self):
        self.board = MockBoard()
        # реальная плата ЭТИМ: индикатор 8x1
        self.board.display.columns = 8
        self.board.display.lines = 1
        self.board.display.set_text("000    0")
        self.app = ui_app.CashRegisterApp(self.board)
        self.app.root.deiconify()
        self.app.root.update()
        self.app.root.focus_force()
        self.app.root.update()

    def tearDown(self):
        try:
            self.app.quit()
        except Exception:
            pass

    def test_board_is_followed_to_eight_cells(self):
        self.app.refresh()
        self.assertEqual((self.app.screen.columns, self.app.screen.lines), (8, 1))
        self.assertEqual(len(self.app.screen._matrix()[0]), 8 * ui_screen.CELL_W)
        self.assertFalse(self.app._manual_mode, "режим должен следовать за платой")

    def test_every_display_mode_fits_the_matrix(self):
        for label, columns, lines in ui_app.DISPLAY_MODES:
            self.app.mode_var.set(label)
            self.app.root.update()
            self.app.refresh()
            self.assertEqual(
                (self.app.screen.columns, self.app.screen.lines),
                (columns, lines),
                label,
            )
            matrix = self.app.screen._matrix()
            self.assertEqual(len(matrix), lines * ui_screen.CELL_H, label)
            for row in matrix:
                self.assertEqual(len(row), columns * ui_screen.CELL_W, label)

    def test_unknown_mode_value_keeps_geometry(self):
        before = (self.app.screen.columns, self.app.screen.lines)
        self.app.mode_var.set("нет такого режима")
        self.app.root.update()
        self.app.refresh()
        self.assertEqual((self.app.screen.columns, self.app.screen.lines), before)

    def test_manual_mode_survives_board_geometry_change(self):
        self.app.mode_var.set("16 x 1  (ценник)")
        self.app.root.update()
        self.app.refresh()
        self.assertTrue(self.app._manual_mode)
        # плата «сменила» геометрию, но выбранный вручную режим главнее
        self.board.display.columns = 20
        self.board.display.lines = 2
        self.app.refresh()
        self.assertEqual((self.app.screen.columns, self.app.screen.lines), (16, 1))

    def test_display_geometry_garbage_is_clamped(self):
        self.board.display.columns = "нет"
        self.board.display.lines = -7
        self.app.refresh()  # не должен бросить
        self.assertEqual((self.app.screen.columns, self.app.screen.lines), (20, 1))
        self.board.display.columns = 0
        self.board.display.lines = 99
        self.app.refresh()
        self.assertEqual((self.app.screen.columns, self.app.screen.lines), (20, 1))

    def test_f5_is_refresh_and_f8_is_ks_report(self):
        keyboard = self.board.keyboard
        keyboard.log.clear()
        self.app.root.event_generate("<KeyPress-F5>", when="now")
        self.app.root.update()
        self.assertFalse(
            [entry for entry in keyboard.log if entry[1] == "КС"],
            "F5 не должна нажимать КС (X-отчёт): %r" % (keyboard.log,),
        )
        self.app.root.event_generate("<KeyRelease-F5>", when="now")
        self.app.root.update()
        bound = {sequence for sequence, _name in self.app.keypad._bindings}
        self.assertNotIn("<F5>", bound, "F5 не должна уходить в клавиатуру платы")
        self.assertIn("<F8>", bound)
        self.app.root.event_generate("<KeyPress-F8>", when="now")
        self.app.root.update()
        self.assertTrue(keyboard.is_pressed("КС"))
        self.app.root.event_generate("<KeyRelease-F8>", when="now")
        self.app.root.update()
        self.assertFalse(keyboard.is_pressed("КС"))

    def test_digit_buttons_are_square_and_large(self):
        self.app.root.update()
        for name in list("0123456789") + ["00", "."]:
            button = self.app.keypad.buttons[name]
            width, height = button.winfo_width(), button.winfo_height()
            self.assertGreaterEqual(width, 40, name)
            self.assertGreaterEqual(height, 30, name)
            self.assertLessEqual(
                abs(width - height),
                max(width, height) * 0.35,
                "%s не квадратная: %dx%d" % (name, width, height),
            )


@unittest.skipUnless(TK_OK, TK_REASON)
class TestKeypadFits4x3(unittest.TestCase):
    """Перекомпонованный блок клавиатуры влезает в окно с экраном 4:3.

    Заказчик: «экран 4 на 3, блок клавиатуры не помещается». Раньше одна
    вертикальная колонка из 7 клавиш действий задавала высоту блока 625 px,
    и на 1024x768 низ (ОТМЕНА, служебный ряд, навигация) уезжал за край окна
    — 15 кнопок были вообще не видны. Теперь ряды разрезаны на 2 столбика.
    """

    #: Геометрии экранов 4:3, на которых проверяем влезание.
    GEOMETRIES = ("1024x768+0+0", "1280x960+0+0")

    def setUp(self):
        self.board = MockBoard()
        self.app = ui_app.CashRegisterApp(self.board)
        self.root = self.app.root

    def tearDown(self):
        try:
            self.app.quit()
        except Exception:
            pass

    def _place(self, geometry: str) -> None:
        self.root.geometry(geometry)
        self.root.deiconify()
        self.root.update_idletasks()
        self.root.update()
        self.root.focus_force()
        self.root.update()

    def test_keypad_reqheight_fits_available_height(self):
        for geometry in self.GEOMETRIES:
            self._place(geometry)
            keypad = self.app.keypad
            lower = keypad.master.master  # строка «клавиатура + чек»
            self.assertLessEqual(
                keypad.winfo_reqheight(),
                lower.winfo_height(),
                "%s: блок клавиатуры (%d px) выше своей строки (%d px)"
                % (geometry, keypad.winfo_reqheight(), lower.winfo_height()),
            )

    def test_every_key_visible_inside_window(self):
        for geometry in self.GEOMETRIES:
            self._place(geometry)
            root_h = self.root.winfo_height()
            root_w = self.root.winfo_width()
            top = self.root.winfo_rooty()
            left = self.root.winfo_rootx()
            self.assertEqual(len(self.app.keypad.buttons), 33)
            for name, button in self.app.keypad.buttons.items():
                self.assertTrue(button.winfo_ismapped(), "%s: %s не видна" % (geometry, name))
                bottom = button.winfo_rooty() + button.winfo_height() - top
                right = button.winfo_rootx() + button.winfo_width() - left
                self.assertLessEqual(bottom, root_h, "%s: %s обрезана снизу" % (geometry, name))
                self.assertLessEqual(right, root_w, "%s: %s обрезана справа" % (geometry, name))

    def test_keypad_block_height_budget(self):
        # до перекомпоновки было 625 px — на 4:3 не влезало
        self.assertLessEqual(self.app.keypad.winfo_reqheight(), 340)
        self.assertLessEqual(self.root.winfo_reqheight(), 700)

    def test_auto_sized_window_covers_whole_content(self):
        # те же формулы, что в ui/app.py::_fit_window_to_content
        reqh = self.root.winfo_reqheight()
        for screen_h in (768, 960):
            window_h = max(660, min(reqh + 8, screen_h - 80))
            self.assertLessEqual(
                reqh, window_h, "экран %d: содержимое (%d) выше окна (%d)" % (screen_h, reqh, window_h)
            )

    def test_actions_are_split_into_two_columns(self):
        self._place("1024x768+0+0")
        keypad = self.app.keypad
        self.assertGreaterEqual(len(keypad.layout["actions"]), 3)
        columns = {}
        for name in keypad.layout["actions"]:
            button = keypad.buttons[name]
            columns.setdefault(id(button.master), []).append(name)
        self.assertEqual(len(columns), 2, "действия должны стоять в 2 столбиках")
        self.assertLessEqual(max(len(names) for names in columns.values()), 4)

    def test_service_row_moved_into_the_main_block(self):
        """Служебный ряд поднят в основной блок — низким остался только хвост."""
        self._place("1024x768+0+0")
        keypad = self.app.keypad
        body = keypad.winfo_children()[0]
        main = body.winfo_children()[0]  # body -> main
        inside_main = set()
        for block in main.winfo_children():
            inside_main.add(id(block))
            for child in block.winfo_children():
                inside_main.add(id(child))
        for name in keypad.layout["service"]:
            self.assertIn(
                id(keypad.buttons[name].master),
                inside_main,
                "%s должен быть внутри основного блока" % name,
            )
        tail = list(keypad.layout["nav"]) + list(keypad.layout["extra"])
        self.assertTrue(tail, "хвостовой ряд должен существовать")
        for name in tail:
            self.assertNotIn(
                id(keypad.buttons[name].master),
                inside_main,
                "%s должен остаться в отдельном нижнем ряду" % name,
            )


class TestSegmentRendererEdgeCases(unittest.TestCase):
    """Знакогенератор 5x7: строчные, неизвестные и пустой символ (без Tk)."""

    def test_lowercase_falls_back_to_upper_glyph(self):
        self.assertEqual(ui_screen.render_segments("a"), ui_screen.render_segments("A"))
        self.assertEqual(ui_screen.render_segments("щ"), ui_screen.render_segments("Щ"))

    def test_unknown_symbols_render_blank(self):
        for char in ("", "€", "\u2603", "\x07", "\t"):
            rows = ui_screen.render_segments(char)
            self.assertEqual(len(rows), ui_screen.CELL_H, repr(char))
            self.assertTrue(all(len(r) == ui_screen.CELL_W for r in rows), repr(char))
            self.assertTrue(all(ch == " " for r in rows for ch in r), repr(char))


class BrokenRowsDisplay:
    """``render_rows()`` отдаёт мусор -> экран обязан уйти на ``text()``."""

    def __init__(self, columns=20, lines=1):
        self.columns = columns
        self.lines = lines
        self.rows_calls = 0

    def text(self) -> str:
        return "ОШИБКА".ljust(self.columns * self.lines)[: self.columns * self.lines]

    def render_rows(self, scale: int = 1) -> list:
        self.rows_calls += 1
        if self.rows_calls % 2:
            return ["мусор"]  # неправильная форма
        raise RuntimeError("плата сломалась")


class HostileBoard:
    """Плата, у которой всё падает: ``refresh()`` не имеет права бросить."""

    class _Display:
        columns = "нет"
        lines = None

        def text(self):
            raise RuntimeError("display.text() упал")

        def render_rows(self, scale=1):
            raise RuntimeError("display.render_rows() упал")

    class _Keyboard:
        keys = None

        def press(self, name):
            raise RuntimeError("press упал")

        def release(self, name):
            raise RuntimeError("release упал")

        def tap(self, name):
            raise RuntimeError("tap упал")

    class _Printer:
        def paper(self):
            raise RuntimeError("paper упал")

        def text(self):
            raise RuntimeError("text упал")

        def clear(self):
            raise RuntimeError("clear упал")

        def feed(self, lines=1):
            raise RuntimeError("feed упал")

        def is_busy(self):
            raise RuntimeError("is_busy упал")

    def __init__(self):
        self.display = self._Display()
        self.keyboard = self._Keyboard()
        self.printer = self._Printer()

    def status_text(self):
        raise RuntimeError("status_text упал")


if __name__ == "__main__":  # pragma: no cover
    print("DISPLAY OK" if TK_OK else "SKIP: %s" % TK_REASON)
    print("DISPLAY=%s" % os.environ.get("DISPLAY", "<none>"))
    unittest.main(verbosity=2)
