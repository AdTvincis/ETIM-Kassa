# -*- coding: utf-8 -*-
"""Производительность эмулятора и длина полного прогона тестов.

Три вещи, которые не должны деградировать незаметно:

1. **Скорость ядра.**  ``m8051.CPU8051`` обязан выполнять разумное число
   машинных циклов в секунду -- и на голом шине (``NullBus``), и на полной
   плате кассы (``board/cashboard.py``), и на живой демо-прошивке.
   Пороги консервативные: замерено ~230..270 тыс. циклов/с, порог
   50 тыс. циклов/с даёт ~5-кратный запас, чтобы тест не флейкал на
   загруженной машине, но всё ещё ловил пятикратную регрессию.
2. **Время boot'а демо-прошивки** ограничено: ``--backend demo51`` обязан
   вывести индикатор практически мгновенно, а не «когда-нибудь».
3. **Полный прогон тестов не раздувается**: ``python -m unittest discover``
   обязан укладываться в бюджет (иначе регрессия по времени -- это тоже
   регрессия).  Прогон выполняется в подпроцессе с защитой от рекурсии
   (``DSH_SKIP_SUITE_TIME_TEST=1``).

Никаких окон, только headless- API.

Запуск::

    python -m unittest tests.test_perf -v
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import main as m  # noqa: E402
from board.cashboard import CashRegisterBoard  # noqa: E402
from firmware.demo import DEMO_BASE, build_demo  # noqa: E402
from m8051 import CPU8051, NullBus, ROM  # noqa: E402

#: Минимальная скорость ядра, машинных циклов в секунду (консервативно:
#: замерено ~230..270 тыс./с, порог -- пятая часть от замера).
MIN_CYCLES_PER_SECOND = 50_000

#: Сколько циклов крутим в одном замере (≈1.2 с на замер при ~250 к/с).
THROUGHPUT_CYCLES = 300_000

#: Сколько секунд отводится на boot демо-прошивки (замерено ~0.05 с).
DEMO_BOOT_SECONDS = 3.0

#: Бюджет полного прогона тестов, секунд (текущий -- ~70 с + подмодули).
FULL_SUITE_SECONDS = 600

#: Защита от рекурсии: во вложенном прогоне тест времени выключает себя.
SUITE_GUARD_ENV = "DSH_SKIP_SUITE_TIME_TEST"

#: ``SJMP $`` -- бесконечный цикл, две машинных такта на итерацию.
#: Код не трогает шину, но ``_advance`` всё равно вызывается.
TIGHT_LOOP = bytes((0x80, 0xFE))


def _make_args() -> argparse.Namespace:
    return argparse.Namespace(dump=None, self_test=False)


def _measure_rate(bus, program: bytes, cycles: int = THROUGHPUT_CYCLES,
                  warmup: int = 20_000) -> tuple:
    """(циклов/с, cpu) для ``program`` на ``bus``; замер детерминирован."""
    rom = ROM("perf")
    rom.load_block(0x0000, program)
    cpu = CPU8051(rom, bus)
    if warmup:
        cpu.run(warmup)               # прогрев: локальные кэши интерпретатора
    start = time.perf_counter()
    cpu.run(cycles)
    elapsed = time.perf_counter() - start
    if elapsed <= 0:
        elapsed = 1e-9
    return cycles / elapsed, cpu


# ===========================================================================
# 1. Скорость эмулятора
# ===========================================================================
class TestEmulatorThroughput(unittest.TestCase):
    """``m8051`` обязан оставаться быстрым: >= MIN_CYCLES_PER_SECOND."""

    def test_core_throughput_on_null_bus(self):
        rate, cpu = _measure_rate(NullBus(), TIGHT_LOOP)
        self.assertFalse(cpu.halted, cpu.error)
        self.assertGreaterEqual(
            int(rate), MIN_CYCLES_PER_SECOND,
            "ядро на NullBus: %.0f циклов/с < %d (замер ~250 тыс./с)"
            % (rate, MIN_CYCLES_PER_SECOND))

    def test_throughput_with_the_cash_register_board(self):
        rate, cpu = _measure_rate(CashRegisterBoard(), TIGHT_LOOP)
        self.assertFalse(cpu.halted, cpu.error)
        self.assertGreaterEqual(
            int(rate), MIN_CYCLES_PER_SECOND,
            "ядро с платой кассы: %.0f циклов/с < %d" % (rate, MIN_CYCLES_PER_SECOND))

    def test_demo_firmware_loop_throughput(self):
        """Живая демо-прошивка на полной плате: сколько циклов в секунду."""
        image, _symbols = build_demo()
        rom = ROM("perf-demo")
        rom.load_block(DEMO_BASE, image)
        board = CashRegisterBoard()
        cpu = CPU8051(rom, board)
        cpu.run_steps(4_000)                    # boot до входа в режим ввода
        self.assertFalse(cpu.halted, cpu.error)
        start = time.perf_counter()
        cpu.run(THROUGHPUT_CYCLES)
        elapsed = time.perf_counter() - start
        rate = THROUGHPUT_CYCLES / max(elapsed, 1e-9)
        self.assertFalse(cpu.halted, cpu.error)
        self.assertGreaterEqual(
            int(rate), MIN_CYCLES_PER_SECOND,
            "демо-прошивка: %.0f циклов/с < %d" % (rate, MIN_CYCLES_PER_SECOND))

    def test_throughput_survives_a_key_press(self):
        """Нажатие клавиши не должно ронять скорость в двигатель."""
        image, _symbols = build_demo()
        rom = ROM("perf-key")
        rom.load_block(DEMO_BASE, image)
        board = CashRegisterBoard()
        cpu = CPU8051(rom, board)
        cpu.run_steps(4_000)
        board.keyboard.press("5")
        start = time.perf_counter()
        cpu.run(100_000)
        elapsed = time.perf_counter() - start
        board.keyboard.release("5")
        rate = 100_000 / max(elapsed, 1e-9)
        self.assertFalse(cpu.halted, cpu.error)
        self.assertGreaterEqual(
            int(rate), MIN_CYCLES_PER_SECOND,
            "нажатие клавиши убило скорость: %.0f циклов/с" % rate)


# ===========================================================================
# 2. Время boot'а демо-прошивки
# ===========================================================================
class TestDemoBootTime(unittest.TestCase):
    """``--backend demo51`` обязан проснуться быстро и предсказуемо."""

    def test_demo_backend_builds_quickly(self):
        start = time.perf_counter()
        backend = m.make_backend("demo51", _make_args())
        build_time = time.perf_counter() - start
        self.assertLess(build_time, 2.0,
                        "сборка demo51 заняла %.2f с" % build_time)

    def test_demo_display_appears_within_the_budget(self):
        start = time.perf_counter()
        backend = m.make_backend("demo51", _make_args())
        build_time = time.perf_counter() - start

        shown = ""
        for _ in range(200):                 # не больше 2 млн циклов по бюджету
            backend.run_budget(10_000)
            shown = "".join(ch for ch in backend.display.text() if ch.isdigit())
            if shown:
                break
        boot_time = time.perf_counter() - start

        self.assertTrue(shown,
                        "демо-прошивка не вывела индикатор за %.2f с: %r"
                        % (boot_time, backend.display.text()))
        self.assertLess(boot_time, DEMO_BOOT_SECONDS,
                        "boot демо-прошивки %.2f с > %.1f с"
                        % (boot_time, DEMO_BOOT_SECONDS))
        self.assertLess(build_time, DEMO_BOOT_SECONDS)

    def test_boot_is_repeatable(self):
        """Повторный бэкенд -- тот же результат (никакой глобальной магии)."""
        digits = []
        for _ in range(2):
            backend = m.make_backend("demo51", _make_args())
            for _ in range(50):
                backend.run_budget(10_000)
                text = "".join(ch for ch in backend.display.text()
                               if ch.isdigit())
                if text:
                    break
            digits.append(text)
        self.assertTrue(digits[0], digits)
        self.assertTrue(digits[1], digits)


# ===========================================================================
# 3. Полный прогон тестов не раздувается
# ===========================================================================
class TestSuiteRuntime(unittest.TestCase):
    """Полный ``unittest discover`` обязан укладываться в бюджет секунд."""

    @unittest.skipIf(os.environ.get(SUITE_GUARD_ENV) == "1",
                     "вложенный прогон: время уже меряется снаружи")
    def test_full_suite_finishes_within_budget(self):
        env = dict(os.environ)
        env[SUITE_GUARD_ENV] = "1"           # анти-рекурсия
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        start = time.perf_counter()
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "unittest", "discover",
                 "-s", "tests", "-q"],
                cwd=ROOT, env=env, capture_output=True,
                encoding="utf-8", errors="replace",
                timeout=FULL_SUITE_SECONDS + 60,
            )
        except subprocess.TimeoutExpired:
            self.fail("полный прогон тестов не уложился в %d с"
                      % (FULL_SUITE_SECONDS + 60))
        elapsed = time.perf_counter() - start

        output = (proc.stdout or "") + (proc.stderr or "")
        self.assertLess(
            elapsed, FULL_SUITE_SECONDS,
            "полный прогон занял %.1f с (бюджет %d с):\n%s"
            % (elapsed, FULL_SUITE_SECONDS, output[-2000:]))

        found = re.search(r"Ran (\d+) tests?", output)
        self.assertIsNotNone(found, "прогон не отчитался о числе тестов:\n%s"
                             % output[-2000:])
        ran = int(found.group(1))
        self.assertGreaterEqual(
            ran, 200, "прогон упал раньше времени: только %d тестов:\n%s"
            % (ran, output[-2000:]))
        # 0 -- всё зелёное, 1 -- есть упавшие тесты; 2 и выше -- поломка запуска
        self.assertIn(proc.returncode, (0, 1),
                      "неожиданный код возврата %d:\n%s"
                      % (proc.returncode, output[-2000:]))

    @unittest.skipIf(os.environ.get(SUITE_GUARD_ENV) == "1",
                     "вложенный прогон")
    def test_this_module_is_cheap(self):
        """Сами perf-тесты не раздувают прогон (кроме проверки прогона)."""
        start = time.perf_counter()
        _measure_rate(NullBus(), TIGHT_LOOP, cycles=50_000, warmup=10_000)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 10.0,
                        "замер скорости занял %.2f с -- что-то не так" % elapsed)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
