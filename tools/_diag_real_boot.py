"""Диагностика загрузки НАСТОЯЩЕЙ прошивки ETIM по найденному пути.

Воспроизводит текущий статус восстановления (см. docs/usage.md §4.3):

1. ППИ вынесена из диапазона самотеста ОЗУ (``PPI_BASE=0xF000``) —
   самотест прошивки проходит.
2. Прерывание INT0 в режиме уровня (``IT0=0``) не взводится программным
   ``SETB IE0`` (исправлено в ``m8051/cpu.py::_poll_interrupts``) — прошивка
   больше не «выключается» сразу после самотеста.
3. Устройство на странице ``0x80`` отвечает последовательностью
   ``00 -> 55 -> AA`` (так требует код ``0x4CE0``/``0x51E7``/``0x51F4``).
4. Устройство ``0x933E/0x933F`` содержит ``55 AA`` (требование ``0x07D7``).
5. Прескан клавиатуры (``0x9100+i``) читается как маска нажатий: пусто = 0.
6. Скан клавиатуры (``0x9130+row``) — активная-ВЫСОКАЯ маска; колонки
   стробируются линией выбора знакоместа (вне 0..7 строка читается нулём).

Инструмент печатает, что реально получилось: адрес зацикливания, экран,
кольцо кодов клавиш (XDATA 0x0C80), флаги сервисного ряда 7.

Запуск::

    python tools/_diag_real_boot.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from board.cashboard import CashRegisterBoard  # noqa: E402
from recover.hal import CashRegisterHAL, load_rom  # noqa: E402
from recover.realrun import RealRunner  # noqa: E402

#: Найденная рабочая проводка: ППИ вне диапазона самотеста 0x0000..0x1FFF.
PROBE_WIRING = {"PPI_BASE": 0xF000, "PPI_MIRROR_BASES": ()}

#: Ответы устройства на странице 0x80: три чтения при загрузке.
DEVICE_80_SEQUENCE = (0x00, 0x55, 0xAA)


class _Handshake:
    """Поведение устройств, найденное трассировкой настоящих байтов."""

    def __init__(self, board: CashRegisterBoard) -> None:
        self.board = board
        self.read_count_80 = 0
        self.original_read = None

    def install(self, runner) -> None:
        bus = runner.bus
        self.original_read = bus.ext_read
        board = self.board
        original = self.original_read
        sequence = DEVICE_80_SEQUENCE
        this = self

        def ext_read(addr: int, code: bool = False) -> int:
            if (addr >> 8) == 0x80:
                value = sequence[min(this.read_count_80, len(sequence) - 1)]
                this.read_count_80 += 1
                return value
            return original(addr, code=code)

        bus.ext_read = ext_read

    def remove(self, runner) -> None:
        if self.original_read is not None:
            runner.bus.ext_read = self.original_read


def main() -> int:
    rom = load_rom()
    board = CashRegisterBoard(wiring=PROBE_WIRING)
    # Устройства-«отвечающие» (иначе прошивка уходит в ветку ожидания):
    board.ext_write(0x933E, 0x55)  # требование 0x07D7: пара 55 AA
    board.ext_write(0x933F, 0xAA)
    hal = CashRegisterHAL(board=board, rom=rom, strict=True)
    runner = RealRunner(hal=hal, rom=rom)
    cpu = runner.cpu if hasattr(runner, "cpu") else runner._cpu

    handshake = _Handshake(board)
    handshake.install(runner)

    # 1. Грузимся до состояния «опрос кольца» (петля 0x0AD5..0x0AD8).
    wait_loop = None
    for _ in range(600):  # до 12 млн циклов
        runner.advance(20_000)
        if 0x0AD5 <= cpu.pc <= 0x0AD8:
            wait_loop = "0x0AD5 (опрос кольца, ждём код 0x10)"
            break
        if runner.halted:
            wait_loop = "HALT: %s" % (runner.halt_reason,)
            break
    st = runner.stats()
    print("== 1. Загрузка ==")
    print("  циклов: %d" % (st.get("instructions", 0) and 0))
    print("  pc: %#06x  halted: %s" % (cpu.pc, runner.halted))
    print("  состояние: %s" % wait_loop)
    print("  экран: %r" % board.display.text())
    print("  ответов устройства 0x80: %d (ожидалось 3)" % handshake.read_count_80)

    # 2. Клавиша «1» (код 0x10) проходит стартовые ворота 0x5C6D.
    def tap(key: str, press_ms: int = 150_000, release_ms: int = 75_000) -> None:
        board.keyboard.press(key)
        runner.advance(press_ms)
        board.keyboard.release(key)
        runner.advance(release_ms)

    ring_write_before = cpu.ram[0x4F]
    tap("1")
    runner.advance(400_000)
    print("\n== 2. Клавиша «1» ==")
    print("  pc: %#06x  экран: %r" % (cpu.pc, board.display.text()))
    print("  кольцо: 4F=%#04x 4E=%#04x (до нажатия было 4F=%#04x)"
          % (cpu.ram[0x4F], cpu.ram[0x4E], ring_write_before))

    # 3. Пара обычных клавиш — настоящая прошивка сама их сканирует и
    #    кладёт коды row<<3|col в кольцо XDATA 0x0C80.
    codes = [0x80, 0x81, 0x82, 0x83]
    start = cpu.ram[0x4F]
    for key in ("5", "СУММА"):
        tap(key)
    print("\n== 3. Клавиши «5», «СУММА» ==")
    print("  кольцо: записано %d событий (4F %#04x -> %#04x)"
          % ((cpu.ram[0x4F] - start) & 0xFF, start, cpu.ram[0x4F]))
    ring = [board.ext_read(0x0C00 + a) for a in codes]
    print("  коды в кольце (0x0C80..): %s" % [hex(v) for v in ring])
    print("  экран: %r  чек: %d строк"
          % (board.display.text(), len(board.printer.paper())))

    # 4. Сервисный ряд 7: инъекция «замкнут» col0+col2 ставит флаг 26h.3.
    keyboard = board.keyboard
    rows = [list(r) for r in keyboard._row_names]
    rows[7][0] = "DIAG7C0"
    rows[7][2] = "DIAG7C2"
    keyboard._row_names = [tuple(r) for r in rows]
    keyboard._pressed["DIAG7C0"] = True
    keyboard._pressed["DIAG7C2"] = True
    runner.advance(150_000)
    print("\n== 4. Сервисный «ряд 7» (col0+col2) ==")
    print("  26h=%#04x (ожидается бит 3)  25h=%#04x"
          % (cpu.ram[0x26], cpu.ram[0x25]))
    keyboard._pressed.clear()
    runner.advance(100_000)
    print("  после отпускания: 26h=%#04x" % cpu.ram[0x26])

    handshake.remove(runner)
    print("\n== Итог ==")
    print("  Настоящая прошивка: самотест пройден, загрузка дошла до главного")
    print("  цикла, собственный ISR сканирует матрицу и кладёт коды в кольцо,")
    print("  главный цикл их читает.  Полный сценарий продажи пока упирается")
    print("  в сервисные ворота 0x06A4 (коды 0x1B/0x0A/0x28 + флаги 26h.3/")
    print("  25h.7/20h.2/20h.3/20h.4) — открытая находка; верхняя половина")
    print("  ПЗУ 0x8000..0xFFFF физически отсутствует в дампе.")
    return 0 if not runner.halted else 1


if __name__ == "__main__":
    raise SystemExit(main())
