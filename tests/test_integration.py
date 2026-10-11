# -*- coding: utf-8 -*-
"""Сквозные тесты: прошивка -> эмулятор ``m8051`` -> плата ``board/`` -> UI-модель.

Что проверяется (без единого Tkinter-окна, только headless- API):

1. **Загрузка настоящего дампа.**  ``firmware/nm27c512n.hex`` читается,
   записи rebased на нижние 32 КиБ CPU (смещения программатора 0x8000 ->
   адреса 0x0000, см. ``m8051/firmware_profile``), происхождение байтов
   совпадает с документацией, а разумный бюджет исполнения отрабатывает
   **без исключений**: настоящий вектор сброса ``LJMP 0x0A06`` внутри
   картинки.  Верхняя половина ``0x8000..0xFFFF`` в дамп не попала -- обращение
   туда честно останавливает CPU (``FirmwareProfile.provenance``), а не падение.
2. **Полная продажа на демо-прошивке.**  Тот же API, что в
   ``tests/test_demo_firmware.py`` (``build_demo`` + ``ROM`` + ``CPU8051`` +
   ``keyboard.press/release`` + ``run_steps``), но уже на настоящей плате
   ``board/cashboard.py``: ввод суммы -> регистрация позиции -> подытог ->
   итог -> оплата -> чек.
3. **``python main.py --selftest``** (без окна) завершается с кодом 0.
4. **Smoke восстановленного бэкенда** (``recover/``) через ``main.make_backend``.
5. **Состояние UI-модели без Tk**: раскладка клавиатуры (``ui/keypad``),
   рендер индикатора (``ui/screen``), строка состояния и лента чека -- ровно
   те данные, которые ``ui/app.py`` читает в ``refresh()``.

Запуск::

    python -m unittest tests.test_integration -v
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import main as m  # noqa: E402
from board.cashboard import CashRegisterBoard  # noqa: E402
from board.keyboard import ALIASES  # noqa: E402
from firmware.demo import DEMO_BASE, build_demo  # noqa: E402
from m8051 import CPU8051, ROM  # noqa: E402
from m8051.firmware_profile import (  # noqa: E402
    ETIM_IMAGE,
    available_images,
    load_firmware,
)
from ui.keypad import build_layout  # noqa: E402
from ui.screen import CELL_H, CELL_W, render_segments  # noqa: E402

#: Дамп, с которым работает эмулятор (единственный используемый проектом).
ETIM_DUMP = "nm27c512n.hex"

#: Сколько машинных циклов считаем «разумным бюджетом» для одной прокрутки.
RUN_BUDGET = 100_000

_CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def _args(**overrides) -> argparse.Namespace:
    """Аргументы, которые ``main.make_backend`` ждёт от argparse-парсера."""
    ns = argparse.Namespace(dump=None, self_test=False)
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def _receipt_variants(printer) -> set:
    """Все читаемые формы ленты (в нижнем регистре).

    Кодировка чека прямо сейчас в работе (зона demo-fix/board-hal): демо-шапка
    либо печатается транслитерацией прошивки (её ``decode_text`` превращает в
    кириллицу), либо сырым KOI8-R (тогда ``paper()`` даёт «кракозябру»).
    Поэтому слово считается присутствующим, если оно есть в **любой** из
    читаемых форм.  Все ветки детерминированы.
    """
    raw = "\n".join(printer.raw_paper())
    variants = {printer.text().lower(), raw.lower()}
    try:
        variants.add(raw.encode("latin-1").decode("koi8-r", "replace").lower())
    except UnicodeEncodeError:                     # pragma: no cover
        pass
    return variants


def _receipt_has(printer, word: str) -> bool:
    needle = word.lower()
    return any(needle in variant for variant in _receipt_variants(printer))


def _readable_receipt(printer) -> str:
    """Лучший читаемый вид чека -- только для сообщений об ошибках."""
    text = printer.text()
    if _CYRILLIC.search(text):
        return text
    raw = "\n".join(printer.raw_paper())
    return raw.encode("latin-1").decode("koi8-r", "replace")


# ---------------------------------------------------------------------------
# Полная продажа: та же механика, что DemoRig в tests/test_demo_firmware.py
# ---------------------------------------------------------------------------
class SaleScenario:
    """Демо-прошивка + настоящая плата кассы, прогнанная через полную продажу.

    Строится и выполняется **один раз** на модуль (см. :func:`sale_scenario`):
    каждый тест читает своё наблюдение, ничего не перезапуская.
    """

    #: шаги инициализации: самопроверка + первый кадр индикатора
    BOOT_STEPS = 4_000
    #: лимиты антидребезга -- ровно те, что у DemoRig
    PRESS_STEPS = 4_000
    SETTLE_STEPS = 1_500

    def __init__(self) -> None:
        image, self.symbols = build_demo()
        self.rom = ROM("demo-integration")
        self.rom.load_block(DEMO_BASE, image)
        self.board = CashRegisterBoard()
        self.cpu = CPU8051(self.rom, self.board)

    # -- управление -------------------------------------------------------
    def run(self, steps: int) -> int:
        done = self.cpu.run_steps(steps)
        if self.cpu.halted:
            raise AssertionError(
                "CPU остановлен: %s (PC=0x%04X)" % (self.cpu.error, self.cpu.pc))
        if self.cpu.error:
            raise AssertionError("ошибка ядра: %s" % self.cpu.error)
        return done

    def until(self, predicate, limit: int, chunk: int = 200) -> bool:
        total = 0
        while total < limit:
            self.run(chunk)
            total += chunk
            if predicate():
                return True
        return False

    def press(self, name: str) -> None:
        """Нажать клавишу, дождаться антидребезга, отпустить."""
        self.board.keyboard.press(name)
        if not self.until(
            lambda: self.cpu.ram[self.symbols["KEY_STABLE"]] != 0xFF,
            self.PRESS_STEPS * 4,
        ):
            raise AssertionError("клавиша %r не прошла антидребезг" % name)
        self.board.keyboard.release(name)
        if not self.until(
            lambda: self.cpu.ram[self.symbols["KEY_STABLE"]] == 0xFF,
            self.SETTLE_STEPS * 4,
        ):
            raise AssertionError("клавиша %r не отпустила" % name)

    # -- наблюдение -------------------------------------------------------
    def ram(self, name: str, offset: int = 0) -> int:
        return self.cpu.ram[self.symbols[name] + offset]

    def entry_value(self) -> int:
        """Введённая сумма в копейках (BCD -> int), как в DemoRig."""
        addr = self.symbols["ENTRY"]
        value = 0
        for byte in reversed([self.cpu.ram[addr + i] for i in range(4)]):
            value = value * 100 + (byte >> 4) * 10 + (byte & 0x0F)
        return value

    @property
    def display_text(self) -> str:
        return self.board.display.text()

    @property
    def display_digits(self) -> str:
        return "".join(ch for ch in self.display_text if ch.isdigit())

    @property
    def receipt(self) -> str:
        return _readable_receipt(self.board.printer)

    @property
    def paper(self) -> str:
        """Сырой ``printer.text()``: ASCII-часть чека не зависит от кодировки."""
        return self.board.printer.text()

    def receipt_has(self, word: str) -> bool:
        """Слово есть в чеке в любой из читаемых форм ленты (см. варианты)."""
        return _receipt_has(self.board.printer, word)

    # -- сам сценарий ------------------------------------------------------
    def execute(self) -> "SaleScenario":
        # 1. boot: самопроверка и вход в режим ввода
        self.run(self.BOOT_STEPS)
        self.boot_display = self.display_text

        # 2. ввод суммы 12.50
        for key in "1250":
            self.press(key)
        self.entry_after_digits = self.entry_value()
        self.display_after_entry = self.display_text

        # 3. регистрация первой позиции
        self.press("СУММА")
        self.entry_after_sum = self.entry_value()
        self.total_first = (self.ram("TOTAL"), self.ram("TOTAL", 1))
        self.display_after_sum = self.display_text
        self.paper_after_first = self.paper

        # 4. вторая позиция 3.00 -> итог 15.50
        for key in "300":
            self.press(key)
        self.press("СУММА")
        self.total_second = (self.ram("TOTAL"), self.ram("TOTAL", 1))

        # 5. итог: подытог (текущий итог на индикаторе) и ИТОГ
        self.press("ПОДЫТОГ")
        self.mode_subtotal = self.ram("MODE")
        self.display_subtotal = self.display_text
        self.press("ИТОГ")
        self.mode_total = self.ram("MODE")
        self.display_total = self.display_text

        # 6. оплата наличными 20.00 -> сдача 4.50 + печать чека
        for key in "2000":
            self.press(key)
        self.press("ОПЛ")
        self.mode_paid = self.ram("MODE")
        self.item_count_after_pay = self.ram("ITEM_N")
        self.display_paid = self.display_text
        self.paper_paid = self.paper
        self.receipt_paid = self.receipt
        self.paper_lines = list(self.board.printer.paper())
        return self


_SALE_CACHE = {}


def sale_scenario() -> SaleScenario:
    if "scenario" not in _SALE_CACHE:
        _SALE_CACHE["scenario"] = SaleScenario().execute()
    return _SALE_CACHE["scenario"]


# ===========================================================================
# 1. Настоящие дампы прошивок: загрузка + бюджет исполнения
# ===========================================================================
class TestFirmwareImagesLoad(unittest.TestCase):
    """``nm27c512n.hex`` грузится и крутится; проект использует только его."""

    def test_etim_dump_is_listed(self):
        """Единственный используемый проектом дамп виден в firmware/."""
        images = available_images()
        self.assertIn(ETIM_DUMP, images)
        self.assertEqual(ETIM_IMAGE, ETIM_DUMP)

    def test_etim_dump_records_carry_programmer_offsets(self):
        """Сырой hex: записи записаны по смещениям программатора 0x8000..0xFFFF.

        Сама картинка -- нижние 32 КиБ CPU (0x0000..0x7FFF): ``load_firmware``
        делает rebasing, см. m8051/firmware_profile (запись 0x8000 -- это
        настоящий вектор сброса ``LJMP 0x0A06``).
        """
        rom = ROM(ETIM_DUMP).load_file(os.path.join(ROOT, "firmware", ETIM_DUMP))
        low, high = rom.coverage()
        self.assertEqual((low, high), (0x8000, 0xFFFF))
        self.assertEqual(len(rom._mem), 0x8000)  # noqa: SLF001

    def test_etim_profile_marks_flash_and_missing_honestly(self):
        profile = load_firmware(primary=ETIM_DUMP, secondary=None)
        self.assertEqual(profile.reset_pc, 0x0000)
        # после rebasing (-0x8000) картинка занимает нижние 32 КиБ:
        # вектор сброса и цель 0x0A06 -- настоящий флеш
        self.assertEqual(profile.provenance(0x0000), "flash")
        self.assertEqual(profile.provenance(0x0A06), "flash",
                         "после rebasing цель сброса 0x0A06 внутри картинки")
        # а верхняя половина в этот дамп не попала
        self.assertEqual(profile.provenance(0x8000), "missing",
                         "верхняя половина 0x8000..0xFFFF не в дампе")
        self.assertEqual(profile.provenance(0xFFFF), "missing")
        # вектор сброса -- настоящие байты картинки: LJMP 0x0A06
        self.assertEqual(profile.rom.byte(0x0000), 0x02)
        self.assertEqual(profile.rom.word(0x0001), 0x0A06)
        self.assertGreater(profile.missing_count(), 0)
        self.assertTrue(profile.notes, "происхождение байтов обязано описываться")

    def _run_budget_without_exceptions(self, backend_name: str) -> dict:
        backend = m.make_backend(backend_name, _args())
        try:
            # бюджет не должен бросить ни на первом, ни на повторном вызове
            backend.run_budget(RUN_BUDGET)
            backend.run_budget(RUN_BUDGET)
        except Exception as exc:  # noqa: BLE001
            self.fail("%s: run_budget(%d) бросил %r"
                      % (backend_name, RUN_BUDGET, exc))
        status = backend.status()
        self.assertIsInstance(status, dict)
        self.assertGreater(status["cycles"], 0, "прошивка не выполнила циклов")
        self.assertIsInstance(status["halted"], bool)
        if status["halted"]:
            reason = status["reason"]
            self.assertTrue(reason, "остановка обязана назвать причину")
            self.assertRegex(reason, r"missing|unmapped",
                             "причина обязана честно говорить о дырке в дампе")
        return status

    def test_etim_backend_runs_the_budget_without_exceptions(self):
        status = self._run_budget_without_exceptions("etim")
        self.assertEqual(status["source"], "etim")
        # после rebasing прошивка целиком лежит в нижних 32 КиБ: бюджет она
        # должна отработать, а не упереться в недампленную верхнюю половину
        self.assertFalse(status["halted"],
                         "прошивка остановилась: %s" % status.get("reason"))
        self.assertIsNone(status["missing_pc"],
                          "не должно быть обращения к непокрытому адресу: %s"
                          % status.get("reason"))

    def test_emulator_backends_expose_the_ui_contract(self):
        """То, что ``ui/app.py`` и ``main.py`` ждут от бэкенда (headless)."""
        for name in ("etim",):
            with self.subTest(backend=name):
                backend = m.make_backend(name, _args())
                self.assertIsInstance(backend.display.text(), str)
                self.assertTrue(1 <= int(backend.display.columns) <= 80)
                self.assertTrue(1 <= int(backend.display.lines) <= 4)
                self.assertTrue(callable(backend.keyboard.press))
                self.assertTrue(callable(backend.keyboard.release))
                self.assertTrue(backend.keyboard.keys)
                paper = backend.printer.paper()
                self.assertIsInstance(paper, list)
                self.assertTrue(all(isinstance(line, str) for line in paper))
                # строка состояния: ui/app читает либо dict c source, либо строку
                self.assertEqual(backend.status()["source"], name)
                self.assertIsInstance(backend.board.status_text(), str)


# ===========================================================================
# 2. Полная продажа на демо-прошивке (настоящая плата)
# ===========================================================================
class TestDemoSaleScenario(unittest.TestCase):
    """Ввод -> позиция -> итог -> оплата -> чек, через API демо-тестов."""

    @classmethod
    def setUpClass(cls):
        cls.sale = sale_scenario()

    # -- boot --------------------------------------------------------------
    def test_boot_shows_the_entry_mode(self):
        self.assertNotEqual(self.sale.boot_display.strip(), "",
                            "после boot индикатор обязан что-то показывать")

    # -- ввод суммы --------------------------------------------------------
    def test_entering_the_sum_is_visible_everywhere(self):
        self.assertEqual(self.sale.entry_after_digits, 1250,
                         "введено 12.50 -> BCD-ввод 1250 копеек")
        self.assertIn("1250", self.sale.display_after_entry,
                      "введённая сумма не доехала до индикатора: %r"
                      % self.sale.display_after_entry)

    # -- регистрация позиции ------------------------------------------------
    def test_sum_registers_the_position(self):
        self.assertEqual(self.sale.entry_after_sum, 0, "после СУММА ввод чист")
        self.assertEqual(self.sale.total_first, (0x50, 0x12),
                         "итог должен стать 12.50 (BCD 0x12, 0x50)")
        self.assertIn("12.50", self.sale.paper_after_first,
                      "позиция не напечаталась на принтере")

    def test_running_total_accumulates(self):
        # 12.50 + 3.00 = 15.50: BCD-байты TOTAL = (копейки 0x50, рубли 0x15)
        self.assertEqual(self.sale.total_second, (0x50, 0x15),
                         "12.50 + 3.00 = 15.50 (BCD 0x15, 0x50)")

    # -- итог ---------------------------------------------------------------
    def test_subtotal_shows_the_running_total_on_the_display(self):
        self.assertEqual(self.sale.mode_subtotal, 1, "ПОДЫТОГ -> режим 1")
        self.assertIn("1550", self.sale.display_subtotal,
                      "текущий итог 15.50 не на индикаторе: %r"
                      % self.sale.display_subtotal)

    def test_total_switches_to_the_total_mode(self):
        self.assertEqual(self.sale.mode_total, 2, "ИТОГ -> режим 2")
        self.assertIn("1550", self.sale.display_total)

    # -- оплата и чек -------------------------------------------------------
    def test_payment_prints_the_receipt(self):
        self.assertEqual(self.sale.mode_paid, 3, "после оплаты -- режим сдачи")
        self.assertEqual(self.sale.item_count_after_pay, 0,
                         "чек закрыт: позиции обнулены")
        # ASCII-часть чека не зависит от кодировки ленты
        for amount in ("12.50", "3.00", "15.50", "20.00", "4.50"):
            self.assertIn(amount, self.sale.paper_paid,
                          "на ленте нет суммы %s" % amount)
        # кириллица -- в любой читаемой форме ленты, без учёта регистра
        for word in ("ДЕМО-ПРОГРАММА", "ИТОГ", "НАЛИЧНЫМИ", "СДАЧА", "СПАСИБО"):
            self.assertTrue(
                self.sale.receipt_has(word),
                "в чеке нет %r:\n%s" % (word, self.sale.receipt))

    def test_change_is_shown_on_the_display(self):
        self.assertIn("450", "".join(ch for ch in self.sale.display_paid
                                     if ch.isdigit()),
                      "сдача 4.50 не на индикаторе: %r" % self.sale.display_paid)

    def test_receipt_has_a_plausible_shape(self):
        lines = self.sale.paper_lines
        self.assertGreater(len(lines), 8, "чек слишком короткий: %r" % lines)
        self.assertTrue(all(isinstance(line, str) for line in lines))


# ===========================================================================
# 3. UI-модель: то, что читает ui/app.py, -- без Tk
# ===========================================================================
class TestUiModelState(unittest.TestCase):
    """Состояние индикатора/клавиатуры/чека/статуса в терминах UI."""

    @classmethod
    def setUpClass(cls):
        cls.sale = sale_scenario()
        cls.board = cls.sale.board

    def test_keypad_layout_covers_every_board_key(self):
        layout = build_layout(self.board.keyboard.keys)
        for group in ("digits", "actions", "service", "nav", "extra", "all"):
            self.assertIn(group, layout, "нет группы %r" % group)
        self.assertEqual(set(layout["all"]), set(self.board.keyboard.keys),
                         "раскладка UI потеряла или добавила клавиши")
        digits = [k for row in layout["digits"] for k in row]
        for name in list("0123456789") + ["00", "."]:
            self.assertIn(name, digits, "нет клавиши %r" % name)
        actions = layout["actions"]
        for name in ("СУММА", "ОПЛ", "ITOG", "ВВОД", "СБРОС", "ОТМЕНА"):
            self.assertIn(name, actions, "нет клавиши %r" % name)

    def test_every_key_used_by_the_sale_reaches_the_layout(self):
        """Клавиши сценария продажи есть в модели UI (в т.ч. через алиасы)."""
        layout = set(build_layout(self.board.keyboard.keys)["all"])
        for name in ("СУММА", "ОПЛ", "ПОДЫТОГ", "ИТОГ"):
            resolved = ALIASES.get(name, name)
            self.assertIn(resolved, layout,
                          "клавиша %r не попадает в раскладку UI" % name)

    def test_screen_renderer_handles_every_display_character(self):
        text = self.sale.display_text
        self.assertEqual(len(text),
                         int(self.board.display.columns)
                         * int(self.board.display.lines),
                         "длина текста индикатора != columns*lines")
        for index, char in enumerate(text):
            rows = render_segments(char)
            self.assertEqual(len(rows), CELL_H, "знакоместо %d: высота" % index)
            for row in rows:
                self.assertEqual(len(row), CELL_W, "знакоместо %d: ширина" % index)
                self.assertLessEqual(set(row), {"#", " "},
                                     "знакоместо %d: мусор %r" % (index, row))
        # «8» обязана рисоваться непустым знакоместом (индикатор не врёт)
        self.assertTrue(any("#" in row for row in render_segments("8")))

    def test_status_bar_contract(self):
        """``ui/app.py::_read_board_status``: либо dict с source, либо строка."""
        status = self.board.status()
        self.assertIsInstance(status, dict)
        self.assertTrue(status.get("source"), "нет source в статусе платы")
        self.assertIn("text", status, "статус обязан нести текст индикатора")
        self.assertIsInstance(status["printer_lines"], int)
        text = self.board.status_text()
        self.assertIsInstance(text, str)
        self.assertTrue(text.strip())

    def test_receipt_state_feeds_the_ui_receipt_view(self):
        """``ReceiptView.update_from_printer`` читает paper()/text()."""
        printer = self.board.printer
        lines = printer.paper()
        self.assertIsInstance(lines, list)
        self.assertTrue(all(isinstance(line, str) for line in lines))
        self.assertIsInstance(printer.text(), str)
        self.assertFalse(printer.is_busy(), "принтер не должен висеть")
        for amount in ("12.50", "15.50", "20.00", "4.50"):
            self.assertIn(amount, printer.text(),
                          "лента не содержит сумму %s" % amount)

    def test_display_geometry_is_within_the_ui_clamps(self):
        """``ui/app.py::_display_geometry`` принимает 1..80 x 1..4."""
        columns = int(self.board.display.columns)
        lines = int(self.board.display.lines)
        self.assertTrue(1 <= columns <= 80, columns)
        self.assertTrue(1 <= lines <= 4, lines)


# ===========================================================================
# 4. main.py без окна: --selftest и headless-прогон
# ===========================================================================
class TestMainHeadless(unittest.TestCase):
    """Точка входа ``main.py`` в режимах, которым не нужно окно."""

    def _run_main(self, *argv: str, timeout: int = 300):
        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [sys.executable, "main.py", *argv],
            cwd=ROOT, env=env, capture_output=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        return proc

    def test_selftest_exits_with_zero(self):
        """``python main.py --selftest``: все модули грузятся, код 0."""
        proc = self._run_main("--selftest")
        output = (proc.stdout or "") + (proc.stderr or "")
        self.assertEqual(proc.returncode, 0,
                         "selftest вернул %d:\n%s" % (proc.returncode, output))
        self.assertIn("ok    m8051", proc.stdout)
        self.assertIn("ok    board.cashboard", proc.stdout)
        self.assertNotIn("FAIL", proc.stdout, proc.stdout)

    def test_list_exits_with_zero_and_names_the_backends(self):
        proc = self._run_main("--list")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in m.BACKENDS:
            self.assertIn(name, proc.stdout)

    def test_run_headless_reports_no_thread_errors(self):
        """``main.run_headless`` -- headless-прогон эмуляции в фоне."""
        backend = m.make_backend("demo51", _args())
        result = m.run_headless(backend, 0.25, verbose=False)
        self.assertEqual(result["errors"], [],
                         "фоновый поток эмуляции ловил исключения: %r"
                         % result["errors"])
        status = result["status"]
        self.assertIsInstance(status, dict)
        self.assertGreater(status["cycles"], 0)
        self.assertIsInstance(backend.display.text(), str)

    def test_demo51_backend_boots_and_reacts_to_a_key(self):
        """Сквозной путь: main -> Demo51Backend -> m8051 -> board -> UI."""
        backend = m.make_backend("demo51", _args())
        digits = ""
        for _ in range(100):
            backend.run_budget(20_000)
            digits = "".join(ch for ch in backend.display.text() if ch.isdigit())
            if digits:
                break
        self.assertTrue(digits, "демо-прошивка не вывела индикатор: %r"
                        % backend.display.text())

        before = backend.display.text()
        backend.keyboard.press("7")
        backend.run_budget(40_000)
        backend.keyboard.release("7")
        backend.run_budget(20_000)
        after = backend.display.text()
        self.assertNotEqual(before, after, "нажатие не изменило индикатор")
        self.assertIn("7", after, "нажатая 7 не доехала до индикатора: %r" % after)

        status = backend.status()
        self.assertEqual(status["source"], "demo")
        self.assertFalse(status["halted"], status.get("reason"))
        self.assertGreater(status["ops"], 0)


# ===========================================================================
# 5. Smoke восстановленного бэкенда (recover/)
# ===========================================================================
class TestRecoveredBackendSmoke(unittest.TestCase):
    """``main.py --backend recovered`` поднимается, крутится и перезапускается."""

    def test_recovered_backend_boots_cleanly(self):
        backend = m.make_backend("recovered", _args())
        status = backend.status()
        self.assertEqual(status["boot_error"], "",
                         "boot восстановленного кода упал: %s"
                         % status.get("reason"))
        self.assertIn(status["source"], ("demo", "recovered"))
        self.assertTrue(status["reason"], "причина старта обязана быть названа")
        self.assertGreaterEqual(status["functions_loaded"], 100,
                                "дамп не загрузился")
        self.assertEqual(status["functions_failed"], 0)
        self.assertTrue(status["entry_covered"],
                        "после rebasing вектор сброса 0x0A06 покрыт дампом")

    def test_recovered_backend_runs_a_budget_without_exceptions(self):
        backend = m.make_backend("recovered", _args())
        before = backend.status()["steps"]
        try:
            for _ in range(20):
                backend.run_budget(10_000)
        except Exception as exc:  # noqa: BLE001
            self.fail("run_budget восстановленного бэкенда бросил %r" % (exc,))
        after = backend.status()
        self.assertGreaterEqual(after["steps"], before,
                                "восстановленный код не сделал ни шага")
        self.assertEqual(after["boot_error"], "")
        # консистентность на стороне сессии: фасады сессии == то, что в статусе
        session = backend.session
        self.assertEqual(session.display.text(), after["display"])
        self.assertEqual(len(session.printer.paper()), after["receipt_lines"])

    def test_recovered_backend_reset_reboots(self):
        backend = m.make_backend("recovered", _args())
        backend.run_budget(5_000)
        backend.reset()
        status = backend.status()
        self.assertEqual(status["boot_error"], "")
        self.assertGreaterEqual(status["functions_loaded"], 100)
        self.assertIn(status["source"], ("demo", "recovered"))

    # -- регрессия: фасады обязаны быть живыми (property, а не копии) --------
    def test_facades_are_the_live_session_objects(self):
        """``backend.display/keyboard/printer is session.*``.

        Был баг: ``RecoveredBackend.__init__`` копировал фасады **до**
        ``session.boot()``, а boot внутри ``_refresh_facades()`` подменяет их
        на новые.  Бэкенд навсегда держал пустые заглушки: экран и чек в GUI
        были пустыми, а нажатия клавиш пропадали (``is_pressed`` -> False).
        """
        backend = m.make_backend("recovered", _args())
        session = backend.session
        self.assertIs(backend.display, session.display,
                      "display бэкенда -- не фасад сессии (пустая копия?)")
        self.assertIs(backend.keyboard, session.keyboard)
        self.assertIs(backend.printer, session.printer)
        # property, а не одноразовая копия: повторное чтение -- тот же объект
        self.assertIs(backend.display, backend.display)
        self.assertIs(backend.keyboard, backend.keyboard)
        self.assertIs(backend.printer, backend.printer)

    def test_display_changes_after_run_budget(self):
        """Экран живой: ``run_budget`` двигает индикатор бэкенда."""
        backend = m.make_backend("recovered", _args())
        before = backend.display.text()
        self.assertIsInstance(before, str, "фасад display не отдаёт строку")
        changed_at = None
        for attempt in range(20):
            backend.run_budget(20_000)
            if backend.display.text() != before:
                changed_at = attempt
                break
        self.assertIsNotNone(
            changed_at,
            "run_budget не изменил индикатор: %r (20 x 20000 циклов)" % before)
        self.assertEqual(backend.status()["display"], backend.display.text(),
                         "статус-бар врёт про экран")

    def test_key_press_reaches_the_session_keyboard(self):
        """Нажатие через бэкенд доходит до платы (а не в пустую заглушку)."""
        backend = m.make_backend("recovered", _args())
        keyboard = backend.keyboard
        self.assertTrue(keyboard.keys, "у сессии нет клавиш")
        keyboard.press("5")
        try:
            self.assertTrue(keyboard.is_pressed("5"),
                            "нажатие не дошло до платы: is_pressed -> False")
        finally:
            keyboard.release("5")
        self.assertFalse(keyboard.is_pressed("5"),
                         "клавиша не отпустилась")

    def test_status_never_lies_about_the_screen(self):
        """Бут без ошибок + статус говорит ровно то, что показывает экран."""
        backend = m.make_backend("recovered", _args())
        # Настоящая прошивка проходит детерминированные delay-петли инициации
        # (~285k циклов) до первого непустого экрана: 20 x 20k = 400k с запасом.
        for _ in range(20):
            backend.run_budget(20_000)
        status = backend.status()
        self.assertEqual(status["boot_error"], "",
                         "boot упал: %s" % status.get("reason"))
        self.assertEqual(status["display"], backend.display.text(),
                         "status()['display'] != display.text()")
        self.assertEqual(status["receipt_lines"],
                         len(backend.printer.paper()),
                         "status()['receipt_lines'] != len(printer.paper())")
        # и сам экран за это время обязан был ожить
        self.assertTrue(backend.display.text().strip(),
                        "восстановленный бэкенд оставил экран пустым")

    def test_ui_reads_never_wait_for_the_whole_budget(self):
        """Новое гарантия скорости: срезы ``session.run()`` под нагрузкой.

        Пока фон крутит ``run_budget(100_000)``, чтения из «Tk-потока»
        (``display.text()``/``status()``) обязаны ждать максимум один срез
        (``recover.session.LOCK_SLICE_CYCLES`` ~250 циклов), а не весь
        бюджет.  До фикса один такой бюджет удерживал замок ~0.8-1.6 с -
        это и есть «подвисание» окна.  Порог 60 мс >> измеряемых ~0.1 мс,
        но << времени удержания замка старым кодом.
        """
        import threading
        import time

        def p95(xs):
            xs = sorted(xs)
            return xs[min(len(xs) - 1, int(len(xs) * 0.95))]

        backend = m.make_backend("recovered", _args())
        stop = threading.Event()
        writer_errors = []

        def writer():
            try:
                while not stop.is_set():
                    backend.run_budget(100_000)
            except Exception as exc:  # noqa: BLE001
                writer_errors.append(repr(exc))

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        lat_text, lat_status = [], []
        try:
            for _ in range(40):
                t0 = time.perf_counter()
                backend.display.text()
                lat_text.append(time.perf_counter() - t0)
                t0 = time.perf_counter()
                backend.status()
                lat_status.append(time.perf_counter() - t0)
                time.sleep(0.005)
        finally:
            stop.set()
            thread.join(timeout=10.0)
        self.assertEqual(writer_errors, [],
                         "фоновый run_budget упал: %r" % writer_errors)
        self.assertLess(
            p95(lat_text), 0.060,
            "display.text() ждёт весь бюджет сессии: p95=%.1f мс"
            % (p95(lat_text) * 1000))
        self.assertLess(
            p95(lat_status), 0.060,
            "status() ждёт весь бюджет сессии: p95=%.1f мс"
            % (p95(lat_status) * 1000))
        # после остановки фона контракт статуса остаётся точным
        status = backend.status()
        self.assertEqual(status["display"], backend.display.text(),
                         "status()['display'] != display.text() после нагрузки")
        self.assertEqual(status["receipt_lines"],
                         len(backend.printer.paper()),
                         "status()['receipt_lines'] != len(printer.paper())")


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
