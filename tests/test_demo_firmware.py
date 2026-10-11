# -*- coding: utf-8 -*-
"""Тесты демонстрационной (stand-in) программы кассы и сборщика asm51.

Программа ``firmware/demo/cashier.asm`` -- **не** оригинальная прошивка: это
замена, написанная машинным кодом MCS-51 и собранная ``tools/asm51.py``.
Тесты проверяют три вещи:

1. ``tools/asm51.py`` кодирует каждую поддерживаемую инструкцию так, что
   ``tools/disasm.py`` читает её обратно эквивалентно (``selftest``).
2. Собранный образ действительно работает на ядре ``m8051``: настраивает ППИ,
   циклически обновляет индикатор, сканирует клавиатуру, реагирует на нажатие
   и печатает чек.
3. Если готова плата ``board/cashboard.py`` (владелец hal-ppi), то тот же образ
   проверяется на ней; иначе тест помечается ``SkipTest``.

Запуск::

    python -m unittest tests.test_demo_firmware -v
"""

from __future__ import annotations

import importlib
import unittest

from m8051 import CPU8051, ROM, NullBus
from tools import asm51
from firmware.demo import (
    DEMO_BASE,
    DEMO_LABEL,
    DISPLAY,
    KEY_CODES,
    KEY_LAYOUT,
    PORT_MAP,
    SEGMENTS,
    build_demo,
    build_result,
    load_demo_image,
)

SEG_BY_MASK = {mask: ch for ch, mask in SEGMENTS.items()}

#: Однобайтовая кодировка русского текста настоящей прошивки:
#: немецко-подобная транслитерация (см. «Character encoding» в
#: board/printer.py и строки из ROM в docs/rom_strings.txt:
#: "nali~nymi", "sda~a", "spasibo", "kassir", "teku}ij itog").
#: Ниже -- ЗЕРКАЛО board.printer.ENCODE_TABLE, чтобы мок-плата читала
#: бумагу и там, где board/ не установлен; test_mock_decoder_matches_the_board
#: сверяет его с плитой байт в байт, чтобы зеркало не разошлось.
_FW_LAT2CYR = {
    "a": "а", "b": "б", "w": "в", "g": "г", "d": "д", "e": "е", "z": "з",
    "i": "и", "j": "й", "k": "к", "l": "л", "m": "м", "n": "н", "o": "о",
    "p": "п", "r": "р", "s": "с", "t": "т", "u": "у", "f": "ф", "h": "х",
    "c": "ц", "y": "ы", "x": "ь", "q": "я", "~": "ч", "}": "щ",
    "v": "ж", "{": "ш", '"': "ъ", "'": "э", "|": "ю",
}
_FW_DECODE = {}
for _lat, _cyr in _FW_LAT2CYR.items():
    _FW_DECODE[ord(_lat)] = _cyr
    if _lat.upper() != _lat:
        _FW_DECODE[ord(_lat.upper())] = _cyr.upper()


def decode_fw(data) -> str:
    """Байты чека -> читаемый текст; ровно то, что делает board.printer."""
    return "".join(_FW_DECODE.get(b & 0xFF, chr(b & 0xFF)) for b in data)


#: Mnemonics the stand-in program's assembler must support (задание).
REQUIRED_MNEMONICS = (
    "MOV", "MOVX", "MOVC", "ADD", "ADDC", "SUBB", "INC", "DEC",
    "ANL", "ORL", "XRL", "CLR", "CPL", "SETB", "JB", "JNB", "JBC",
    "JC", "JNC", "JZ", "JNZ", "CJNE", "DJNZ", "SJMP", "AJMP", "LJMP",
    "ACALL", "LCALL", "RET", "RETI", "PUSH", "POP", "NOP", "RL", "RR",
    "SWAP", "XCH", "MUL", "DIV", "DA",
)


# ---------------------------------------------------------------------------
# Mock-плата: ровно контракт docs/board_contract.md + карта ППИ от hal-ppi
# ---------------------------------------------------------------------------
class MockBus:
    """Мини-ППИ 8255 + клавиатура + принтер, достаточные для образа демо.

    Поведение повторяет согласованную карту:

    * ``0x0000`` PA -- выход: маска сегментов (режим 0x89) или байт принтеру
      (режим 0xA9);
    * ``0x0001`` PB -- выход: единица в разряде знакоместа (и строки матрицы);
    * ``0x0002`` PC -- вход: столбцы клавиатуры, 0 = нажато;
    * ``0x0003``    -- регистр управления 8255.
    """

    COLUMNS = 8
    ROWS = 8

    def __init__(self) -> None:
        self.control = None
        self.pa = 0x00
        self.pb = 0x00
        self.cells = [0x00] * self.COLUMNS
        self.pressed = set()
        self.ext_writes = []          # (addr, value)
        self.ext_reads = []           # addr
        self.port_writes = []         # (port, value)
        self.port_reads = []          # port
        self.printer = bytearray()
        self.cell_history = []        # кортежи cells после каждой защёлки
        self.ticks = 0

    # -- HardwareBus ------------------------------------------------------
    def tick(self, cycles: int) -> None:
        self.ticks += cycles

    def ext_read(self, addr: int, code: bool = False) -> int:
        addr &= 0xFFFF
        self.ext_reads.append(addr)
        if addr in (0x0002, 0x000A):
            return self._columns()
        if addr in (0x0000, 0x0008):
            return self.pa
        if addr in (0x0001, 0x0009):
            return self.pb
        return 0xFF

    def ext_write(self, addr: int, value: int) -> None:
        addr &= 0xFFFF
        value &= 0xFF
        self.ext_writes.append((addr, value))
        if addr in (0x0000, 0x0008):
            self.pa = value
            if self._printer_mode():
                self.printer.append(value)
        elif addr in (0x0001, 0x0009):
            self.pb = value
            self._commit()
        elif addr in (0x0003, 0x000B):
            self.control = value
        else:
            self.pa = value

    def port_read(self, port: int) -> int:
        self.port_reads.append(port)
        return 0xFF

    def port_write(self, port: int, value: int) -> None:
        self.port_writes.append((port, value))

    def serial_write(self, byte: int) -> None:
        self.printer.append(byte & 0xFF)

    def irq_requested(self) -> int:
        return 0

    # -- 8255 semantics ---------------------------------------------------
    def _printer_mode(self) -> bool:
        """True when group A is in mode 1 (0xA9): PA writes feed the printer."""
        return self.control is not None and (self.control & 0x80) and \
            ((self.control >> 5) & 0x03) == 0x01

    def _commit(self) -> None:
        """PB selects a digit: latch PA into it (one-hot, active high)."""
        if self.pb:
            index = self.pb.bit_length() - 1
            if 0 <= index < self.COLUMNS:
                self.cells[index] = self.pa
        self.cell_history.append(tuple(self.cells))

    def _columns(self) -> int:
        """Column bits of the row selected by PB: 0 = pressed."""
        value = 0xFF
        if self.pb:
            row = self.pb.bit_length() - 1
            for col in range(self.COLUMNS):
                if (row, col) in self.pressed:
                    value &= ~(1 << col) & 0xFF
        return value

    # -- test helpers -----------------------------------------------------
    def press(self, name: str) -> None:
        self.pressed.add(self._position(name))

    def release(self, name: str) -> None:
        self.pressed.discard(self._position(name))

    @staticmethod
    def _position(name: str):
        for row, cells in enumerate(KEY_LAYOUT):
            for col, key in enumerate(cells):
                if key == name:
                    return (row, col)
        raise KeyError(f"{name!r} не найдена в KEY_LAYOUT")

    # -- наблюдение -------------------------------------------------------
    def display_chars(self) -> str:
        out = []
        for mask in self.cells:
            base = mask & 0x7F
            ch = SEG_BY_MASK.get(base, "?")
            out.append(ch + ("." if mask & 0x80 else ""))
        return "".join(out)

    def display_digits(self) -> str:
        return "".join(ch for ch in self.display_chars() if ch.isdigit())

    def printer_text(self) -> str:
        """Бумага в читаемом виде -- как board.printer.text()."""
        raw = bytes(b for b in self.printer if b not in (0x0D,))
        return decode_fw(raw)

    def printer_lines(self) -> list:
        return [line for line in self.printer_text().split("\n")]

    def writes_to(self, addr: int) -> list:
        return [v for a, v in self.ext_writes if a == addr]

    def reads_of(self, addr: int) -> int:
        return self.ext_reads.count(addr)


class DemoRig:
    """Образ демо + ядро 8051 + mock-плата, с удобным прогоном."""

    def __init__(self) -> None:
        self.image, self.symbols = build_demo()
        self.rom = ROM("demo-stand-in")
        self.rom.load_block(DEMO_BASE, self.image)
        self.bus = MockBus()
        self.cpu = CPU8051(self.rom, self.bus)

    def run(self, steps: int) -> int:
        done = self.cpu.run_steps(steps)
        if self.cpu.halted:
            raise AssertionError(
                f"программа остановлена: {self.cpu.error} "
                f"(PC=0x{self.cpu.pc:04X})")
        if self.cpu.error:
            raise AssertionError(
                f"ошибка ядра: {self.cpu.error} (PC=0x{self.cpu.pc:04X})")
        return done

    def run_until(self, predicate, limit: int = 400_000, chunk: int = 500) -> bool:
        total = 0
        while total < limit:
            self.run(chunk)
            total += chunk
            if predicate():
                return True
        return False

    def press(self, name: str, steps: int = 4000, settle: int = 1500) -> None:
        """Нажать клавишу, дать антидребезгу сработать и отпустить."""
        self.bus.press(name)
        self.run_until(
            lambda: self.cpu.ram[self.symbols["KEY_STABLE"]] != 0xFF,
            limit=steps * 4, chunk=200)
        self.bus.release(name)
        self.run_until(
            lambda: self.cpu.ram[self.symbols["KEY_STABLE"]] == 0xFF,
            limit=settle * 4, chunk=200)

    def entry_bcd(self) -> int:
        addr = self.symbols["ENTRY"]
        digits = [self.cpu.ram[addr + i] for i in range(4)]
        return sum(d << (8 * i) for i, d in enumerate(digits))

    def entry_value(self) -> int:
        """Введённая сумма в копейках (BCD -> int)."""
        addr = self.symbols["ENTRY"]
        value = 0
        for byte in reversed([self.cpu.ram[addr + i] for i in range(4)]):
            value = value * 100 + (byte >> 4) * 10 + (byte & 0x0F)
        return value


# ---------------------------------------------------------------------------
# 0. Мок-принтер декодирует так же, как плата
# ---------------------------------------------------------------------------
class TestMockPrinterDecoding(unittest.TestCase):
    def test_mock_decoder_matches_the_board(self):
        """Зеркало ENCODE_TABLE в тесте не разошлось с board/printer.py."""
        try:
            from board.printer import decode_text as board_decode
        except Exception as exc:                # pragma: no cover - без board
            raise unittest.SkipTest(f"board.printer недоступен: {exc!r}")
        for value in range(256):
            self.assertEqual(decode_fw([value]), board_decode([value]),
                             f"байт 0x{value:02X} декодируется иначе, "
                             f"чем на плите")


# ---------------------------------------------------------------------------
# 1. Сборщик
# ---------------------------------------------------------------------------
class TestAssembler(unittest.TestCase):
    def test_selftest_round_trips_every_encoding(self):
        """Каждая инструкция asm51 читается disasm.py обратно эквивалентно."""
        self.assertEqual(asm51.selftest(verbose=False), 0)

    def test_supports_every_required_mnemonic(self):
        for mnemonic in REQUIRED_MNEMONICS:
            self.assertIn(mnemonic, asm51.ENC,
                          f"нет мнемоники {mnemonic}")

    def test_labels_immediates_and_two_pass(self):
        result = asm51.assemble(
            """
            VAL    EQU 0x1234
                    ORG 0x0000
                    LJMP START
            START:  MOV  DPTR,#VAL
                    MOV  A,#LOW(START)
                    MOV  A,#HIGH(START)
                    SJMP START
                    END
            """)
        self.assertEqual(result.symbols["VAL"], 0x1234)
        start = result.symbols["START"]
        self.assertEqual(result.image[0:3], bytes((0x02, 0x00, start)))
        self.assertEqual(result.image[start:start + 3], bytes((0x90, 0x12, 0x34)))
        self.assertEqual(result.image[start + 3:start + 5],
                         bytes((0x74, start & 0xFF)))
        self.assertEqual(result.image[start + 5:start + 7],
                         bytes((0x74, (start >> 8) & 0xFF)))

    def test_intel_hex_output_is_loadable(self):
        result = build_result()
        text = result.intel_hex()
        lines = text.strip().splitlines()
        # Первая запись -- данные по адресу 0x0000 (вектор сброса). ЕЁ ДЛИНА
        # не зафиксирована: векторные ORG (0x0003, 0x000B, ...) оставляют
        # 0xFF-просветы, asm51 пишет каждый непрерывный кусок отдельной
        # записью, поэтому первая запись может быть короче 16 байт.
        head = lines[0]
        self.assertTrue(head.startswith(":"), head)
        size = int(head[1:3], 16)
        self.assertGreater(size, 0, head)
        self.assertEqual(head[3:7], "0000", "первая запись не на адресе 0x0000")
        self.assertEqual(head[7:9], "00", "первая запись не типа DATA")
        # у каждой записи сходится контрольная сумма (иначе load_hex_text её
        # отвергнет)
        for line in lines:
            self.assertTrue(line.startswith(":"), line)
            raw = bytes.fromhex(line[1:])
            self.assertEqual(sum(raw) & 0xFF, 0,
                             f"плохая контрольная сумма: {line}")
        self.assertEqual(lines[-1], ":00000001FF")           # конец файла
        # round-trip: записанный образ читается байт в байт
        rom = ROM("hex").load_hex_text(text)
        for addr in range(result.base, result.end):
            self.assertEqual(rom.byte(addr), result.image[addr - result.base],
                             f"байт 0x{addr:04X} не пережил round-trip")

    def test_immediate_overflow_is_reported(self):
        result = asm51.assemble("        ORG 0\n        MOV A,#300\n")
        self.assertTrue(any("truncated" in w for w in result.warnings))

    def test_unknown_mnemonic_raises(self):
        with self.assertRaises(asm51.AsmError):
            asm51.assemble("        ORG 0\n        FROB A,#1\n")

    def test_relative_jump_out_of_range_raises(self):
        source = "        ORG 0\nL:      NOP\n" + "        NOP\n" * 200 + \
                 "        SJMP L\n"
        with self.assertRaises(asm51.AsmError):
            asm51.assemble(source)

    def test_bit_addresses_use_the_mcs51_convention(self):
        # 20h.3 -- это бит 0x03 (байт 0x20, третий бит), ACC.3 -- бит 0xE3.
        result = asm51.assemble(
            "        ORG 0\n"
            "        SETB 20h.3\n"
            "        SETB ACC.3\n"
            "        CLR  C\n"
            "        END\n")
        self.assertEqual(result.image[:5], bytes((0xD2, 0x03, 0xD2, 0xE3, 0xC3)))


# ---------------------------------------------------------------------------
# 2. Сборка демо-программы
# ---------------------------------------------------------------------------
class TestDemoImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = build_result()
        cls.image = cls.result.image
        cls.symbols = cls.result.symbols

    def test_reset_vector_starts_at_zero(self):
        self.assertEqual(DEMO_BASE, 0x0000)
        self.assertEqual(self.image[0], 0x02)          # LJMP
        target = (self.image[1] << 8) | self.image[2]
        self.assertEqual(target, self.symbols["START"])

    def test_image_is_labelled_a_stand_in(self):
        self.assertIn("ДЕМО", DEMO_LABEL)
        self.assertIn("НЕ ОРИГИНАЛЬНАЯ", DEMO_LABEL)

    def test_receipt_text_is_transliterated_and_mentions_the_demo(self):
        """Чек пишется 7-битным транслитом -- как настоящая прошивка.

        KOI8-R здесь был бы ошибкой: плата (board/printer.py) читает байты
        через ENCODE_TABLE, и кириллические байты превратились бы в мусор.
        """
        text = self.result.image
        start = self.symbols["S_DEMO"]
        blob = text[start - self.result.base:start - self.result.base + 40]
        raw = blob.split(b"\x00")[0]
        self.assertTrue(all(b < 0x80 for b in raw),
                        "текст чека должен быть 7-битным (транслитерация)")
        self.assertIn("ДЕМО-ПРОГРАММА", decode_fw(raw).upper())

    def test_keymap_table_matches_python_layout(self):
        addr = self.symbols["KEYMAP"] - self.result.base
        table = self.image[addr:addr + 64]
        expected = []
        for row in KEY_LAYOUT:
            for name in row:
                # клавиши, которые демо не разбирает, дают K_NONE (0xFF)
                expected.append(KEY_CODES.get(name, KEY_CODES[""]))
        self.assertEqual(list(table), expected,
                         "KEYMAP в cashier.asm разошлась с KEY_LAYOUT")

    def test_segment_table_matches_python_table(self):
        addr = self.symbols["DIGIT_SEG"] - self.result.base
        table = self.image[addr:addr + 10]
        self.assertEqual(list(table),
                         [SEGMENTS[str(d)] for d in range(10)])

    def test_load_demo_image_matches_build(self):
        self.assertEqual(load_demo_image(), self.image)

    def test_no_acall_in_the_demo(self):
        """ACALL (0x11/0x31/...) в собранном образе демо не встречается.

        ``tools/asm51.py`` ACALL поддерживает (задание), но сама
        демо-программа его не собирает: все вызовы в ``cashier.asm`` --
        ``LCALL``/``RET``.

        Проверка идёт ПО ЛИСТИНГУ (границы инструкций), а не по сырым байтам
        образа: эти же значения закономерно встречаются *внутри* инструкций
        (операнд ``CJNE A,#K_SUMM`` даёт 0x11, младшие байты адресов
        ``LJMP``/``LCALL`` дают 0x31/0x51/0x91/0xB1) и в таблицах данных
        (KEYMAP), поэтому сырая проверка по диапазону адресов даёт ложные
        срабатывания.  Полнота листинга проверяется отдельно, чтобы между
        записями не осталось необработанных байтов.
        """
        acall_ops = (0x11, 0x31, 0x51, 0x71, 0x91, 0xB1, 0xD1, 0xF1)
        start = self.symbols["START"]
        covered = set()
        for entry in self.result.listing:
            if entry.kind == "ins" and entry.data:
                self.assertNotIn(
                    entry.data[0], acall_ops,
                    f"ACALL по адресу 0x{entry.addr:04X} ({entry.source})")
            if entry.addr >= start and entry.data:
                covered.update(range(entry.addr, entry.addr + len(entry.data)))
        self.assertEqual(covered, set(range(start, self.result.end)),
                         "листинг не покрывает образ сплошным потоком")


# ---------------------------------------------------------------------------
# 3. Контракт ядра m8051, от которого зависит демо-программа
# ---------------------------------------------------------------------------
class TestCoreContract(unittest.TestCase):
    """Проверки ядра, без которых демо-программа не может работать.

    Демо-программа -- обычный машинный код: она вызывает подпрограммы
    (``LCALL``/``RET``) и сравнивает коды клавиш (``CJNE``).  Эти тесты
    фиксируют семантику ядра, чтобы ошибка в нём не выглядела как ошибка
    демо-программы (обе найденные здесь ошибки -- ``push_pc`` и условие
    перехода ``CJNE`` -- были именно такими).
    """

    def _run(self, source: str, steps: int = 10, watch=(0x30, 0x40)) -> CPU8051:
        result = asm51.assemble(source)
        rom = ROM("core-contract")
        rom.load_block(0, result.image)
        cpu = CPU8051(rom, NullBus())
        for _ in range(steps):
            cpu.step()
            if cpu.pc in watch:
                break
        return cpu

    _CJNE = (
        "        ORG 0\n"
        "{setup}\n"
        "        CJNE {ops},T\n"
        "        LJMP 0x0030\n"
        "        ORG 0x20\n"
        "T:      LJMP 0x0040\n"
    )

    def _cjne_jumps(self, setup: str, ops: str) -> bool:
        cpu = self._run(self._CJNE.format(setup=setup, ops=ops))
        self.assertIn(cpu.pc, (0x30, 0x40), "CJNE не дошёл до ветки")
        return cpu.pc == 0x40

    def test_cjne_a_immediate(self):
        self.assertTrue(self._cjne_jumps("        MOV A,#5", "A,#2"),
                        "CJNE A,#2 при A=5 обязан перейти (не равно)")
        self.assertTrue(self._cjne_jumps("        MOV A,#2", "A,#5"),
                        "CJNE A,#5 при A=2 обязан перейти (не равно)")
        self.assertFalse(self._cjne_jumps("        MOV A,#5", "A,#5"),
                         "CJNE A,#5 при A=5 не должен переходить (равно)")

    def test_cjne_a_direct_and_registers(self):
        self.assertTrue(self._cjne_jumps("        MOV A,#9\n"
                                         "        MOV 30h,#4", "A,30h"))
        self.assertFalse(self._cjne_jumps("        MOV A,#4\n"
                                          "        MOV 30h,#4", "A,30h"))
        self.assertTrue(self._cjne_jumps("        MOV R0,#5", "R0,#2"))
        self.assertFalse(self._cjne_jumps("        MOV R0,#5", "R0,#5"))
        self.assertTrue(self._cjne_jumps("        MOV R0,#31h\n"
                                         "        MOV @R0,#7", "@R0,#3"))
        self.assertFalse(self._cjne_jumps("        MOV R0,#31h\n"
                                          "        MOV @R0,#7", "@R0,#7"))

    def test_cjne_sets_carry_for_unsigned_less_than(self):
        # A=2 < 5 -> CY=1 -> JC берёт ветку; A=9 > 5 -> CY=0.
        low = self._run("        ORG 0\n        MOV A,#2\n"
                        "        CJNE A,#5,T\n        LJMP 0x0030\n"
                        "        ORG 0x20\nT:      JC 0x0040\n"
                        "        LJMP 0x0030\n")
        self.assertEqual(low.pc, 0x40, "CJNE должен ставить CY при A<#imm")

    def test_lcall_ret_returns_to_the_right_address(self):
        cpu = self._run(
            "        ORG 0\n"
            "        LCALL SUB\n"
            "        LJMP 0x0030\n"
            "        ORG 0x20\n"
            "SUB:    MOV A,#5Ah\n"
            "        RET\n", steps=8)
        self.assertEqual(cpu.pc, 0x30, "RET вернулся не по адресу вызова")
        self.assertEqual(cpu.acc, 0x5A)
        self.assertEqual(cpu.sp, 0x07, "SP не восстановился после RET")

    def test_push_pop_round_trip(self):
        cpu = self._run(
            "        ORG 0\n"
            "        MOV A,#11h\n"
            "        PUSH ACC\n"
            "        MOV A,#22h\n"
            "        POP ACC\n"
            "        LJMP 0x0030\n", steps=8)
        self.assertEqual(cpu.pc, 0x30)
        self.assertEqual(cpu.acc, 0x11)

    def test_conditional_jumps_used_by_the_demo(self):
        cases = (
            ("        MOV A,#0\n        JZ  T", True),
            ("        MOV A,#1\n        JZ  T", False),
            ("        MOV A,#1\n        JNZ T", True),
            ("        CLR C\n        JC  T", False),
            ("        SETB C\n        JC  T", True),
            ("        SETB C\n        JNC T", False),
            ("        MOV R2,#2\n        DJNZ R2,T", True),
            ("        MOV R2,#1\n        DJNZ R2,T", False),
        )
        for setup, expected in cases:
            with self.subTest(setup=setup.strip()):
                cpu = self._run(
                    "        ORG 0\n"
                    f"{setup}\n"
                    "        LJMP 0x0030\n"
                    "        ORG 0x20\n"
                    "T:      LJMP 0x0040\n")
                self.assertEqual(cpu.pc == 0x40, expected,
                                 f"{setup!r}: неверное поведение перехода")

    # -- флаги арифметики: на них держится вся BCD-арифметика демо ---------
    def _flags(self, body: str) -> CPU8051:
        return self._run(
            "        ORG 0\n"
            f"{body}\n"
            "L:      SJMP L\n", steps=40, watch=())

    def test_add_updates_auxiliary_carry_both_ways(self):
        cpu = self._flags(
            "        MOV A,#08h\n"
            "        ADD A,#08h          ; AC=1 (8+8)\n"
            "        MOV A,#10h\n"
            "        ADD A,#01h          ; переноса из младшей тетрады нет,\n"
            "        DA  A               ; поэтому AC сброшен и DA ничего не правит\n"
            "        MOV 30h,A")
        self.assertEqual(cpu.ram[0x30], 0x11,
                         "stale AC: DA A добавила 6 (получилось 0x%02X, "
                         "должно быть 0x11)" % cpu.ram[0x30])

    def test_add_updates_carry_both_ways(self):
        cpu = self._flags(
            "        MOV A,#0FFh\n"
            "        ADD A,#02h          ; CY=1\n"
            "        MOV A,#01h\n"
            "        ADD A,#01h          ; CY должен быть сброшен\n"
            "        CLR A\n"
            "        RLC A\n"
            "        MOV 30h,A")
        self.assertEqual(cpu.ram[0x30], 0,
                         "stale CY остался после ADD без переноса")

    def test_sub_updates_carry_both_ways(self):
        cpu = self._flags(
            "        CLR C\n"
            "        MOV A,#02h\n"
            "        SUBB A,#05h         ; заём -> CY=1\n"
            "        MOV A,#05h\n"
            "        SUBB A,#02h         ; CY должен быть сброшен\n"
            "        CLR A\n"
            "        RLC A\n"
            "        MOV 30h,A")
        self.assertEqual(cpu.ram[0x30], 0,
                         "stale CY остался после SUBB без заёма")

    def test_bcd_idiom_used_by_the_receipt(self):
        # ровно то, что делает BCD_ADD4: ADD + DA A поверх «грязных» флагов
        cpu = self._flags(
            "        MOV A,#08h\n"
            "        ADD A,#08h          ; выставить AC\n"
            "        MOV A,#50h\n"
            "        ADD A,#00h\n"
            "        DA  A               ; 0x50 + 0 -> 0x50\n"
            "        MOV 30h,A")
        self.assertEqual(cpu.ram[0x30], 0x50,
                         "BCD 0x50+0 дало 0x%02X" % cpu.ram[0x30])

    def test_add_preserves_register_bank_bits(self):
        cpu = self._flags(
            "        SETB PSW.3           ; RS0=1 -> банк 1\n"
            "        MOV A,#01h\n"
            "        ADD A,#01h\n"
            "        MOV 30h,PSW")
        self.assertTrue(cpu.ram[0x30] & 0x08,
                        "ADD сбросил PSW.RS0 (банк регистров)")

    # -- DA A: старшая тетрада проверяется ПОСЛЕ коррекции младшей ---------
    def _da(self, body: str):
        cpu = self._flags(
            f"{body}\n"
            "        MOV 30h,A\n"
            "        CLR A\n"
            "        RLC A\n"
            "        MOV 31h,A")
        return cpu.ram[0x30], cpu.ram[0x31]

    def test_da_adjusts_high_nibble_after_low_nibble(self):
        acc, carry = self._da("        MOV A,#9Ah\n        DA  A")
        self.assertEqual((acc, carry), (0x00, 1),
                         "DA A(9Ah) -> %02X/CY=%d, должно быть 00/CY=1"
                         % (acc, carry))

    def test_da_on_a_full_bcd_addition(self):
        for left, right, expect in ((0x45, 0x55, (0x00, 1)),
                                    (0x99, 0x01, (0x00, 1)),
                                    (0x12, 0x34, (0x46, 0)),
                                    (0x50, 0x50, (0x00, 1))):
            with self.subTest(left=hex(left), right=hex(right)):
                acc, carry = self._da(
                    "        MOV A,#%02Xh\n"
                    "        ADD A,#%02Xh\n"
                    "        DA  A" % (left, right))
                self.assertEqual((acc, carry), expect,
                                 "BCD %02X+%02X -> %02X/CY=%d"
                                 % (left, right, acc, carry))


# ---------------------------------------------------------------------------
# 4. Работа образа на ядре m8051 с mock-платой
# ---------------------------------------------------------------------------
class TestDemoOnMockBus(unittest.TestCase):
    def setUp(self):
        self.rig = DemoRig()

    # -- инициализация ----------------------------------------------------
    def test_program_runs_and_initialises_the_ppi(self):
        self.rig.run(3000)
        self.assertIn(PORT_MAP["MODE_DISPLAY"],
                      self.rig.bus.writes_to(PORT_MAP["PPI_CTRL"]),
                      "программа не записала управляющее слово 0x89")

    def test_power_on_selftest_lights_every_segment(self):
        all_segments = SEGMENTS["8"] | 0x80
        self.rig.run(4000)
        pattern = tuple([all_segments] * DISPLAY["columns"])
        self.assertIn(pattern, self.rig.bus.cell_history,
                      "нет самопроверки 'test tpu' (все сегменты)")

    def test_display_is_refreshed_repeatedly(self):
        self.rig.run(3000)
        pa_writes = self.rig.bus.writes_to(PORT_MAP["PPI_PA"])
        pb_writes = self.rig.bus.writes_to(PORT_MAP["PPI_PB"])
        self.assertGreater(len(pa_writes), 3 * DISPLAY["columns"])
        self.assertGreater(len(pb_writes), 3 * DISPLAY["columns"])
        # каждая запись в PB -- либо "знакоместо не выбрано" (0x00, перед
        # печатью/в начале), либо единица ровно в одном разряде
        one_hot = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
        for value in pb_writes:
            self.assertIn(value, [0x00] + one_hot)
        self.assertGreater(len([v for v in pb_writes if v in one_hot]),
                           3 * DISPLAY["columns"])

    def test_keyboard_port_is_scanned(self):
        self.rig.run(3000)
        self.assertGreater(self.rig.bus.reads_of(PORT_MAP["PPI_PC"]), 8)

    def test_key_press_changes_the_display(self):
        self.rig.run(4000)                        # инициализация + самопроверка
        before = tuple(self.rig.bus.cells)
        self.rig.press("5")
        after = tuple(self.rig.bus.cells)
        self.assertNotEqual(before, after,
                            "нажатие клавиши не изменило буфер индикатора")
        self.assertEqual(self.rig.entry_value(), 5)
        # разряд копеек -- крайнее правое знакоместо
        self.assertEqual(after[7], SEGMENTS["5"])
        # знакоместо 0 -- индикатор режима ("0" = ввод)
        self.assertEqual(after[0], SEGMENTS["0"])

    def test_clear_entry_and_zero_keys(self):
        self.rig.run(4000)
        self.rig.press("5")
        self.assertEqual(self.rig.entry_value(), 5)
        self.rig.press("СБРОС")
        self.assertEqual(self.rig.entry_value(), 0)
        self.rig.press("00")
        self.assertEqual(self.rig.entry_value(), 0)
        self.rig.press("1")
        self.rig.press("2")
        self.rig.press(".")
        self.assertEqual(self.rig.entry_value(), 1200,
                         '". " и "00" достраивают копейки')

    def test_sum_registers_an_item_and_prints_a_line(self):
        self.rig.run(4000)
        self.rig.press("1")
        self.rig.press("2")
        self.rig.press("5")
        self.rig.press("0")                       # 12.50
        self.rig.press("СУММА")
        self.assertEqual(self.rig.entry_value(), 0, "ввод должен очищаться")
        total_addr = self.rig.symbols["TOTAL"]
        self.assertEqual(self.rig.cpu.ram[total_addr], 0x50)   # 12.50 младший
        self.assertEqual(self.rig.cpu.ram[total_addr + 1], 0x12)
        text = self.rig.bus.printer_text()
        self.assertIn("12.50", text)
        # регистр не сверяем: однобайтовый транслит не различает верхний
        # регистр у ч/ш/щ/ъ/э/ю (board/printer.py, test_transliteration_round_trip)
        self.assertIn("ДЕМО-ПРОГРАММА", text.upper())   # шапка помечена как замена

    def test_subtotal_and_total_keys_show_the_running_total(self):
        self.rig.run(4000)
        for key in "100":
            self.rig.press(key)
        self.rig.press("СУММА")                   # итог 1.00
        self.rig.press("ПОДЫТОГ")
        self.assertEqual(self.rig.cpu.ram[self.rig.symbols["MODE"]], 1)
        digits = self.rig.bus.display_digits()
        self.assertTrue(digits.endswith("100"),
                        f"на индикаторе нет итога: {digits!r}")
        self.rig.press("ИТОГ")
        self.assertEqual(self.rig.cpu.ram[self.rig.symbols["MODE"]], 2)

    def test_full_sale_prints_receipt_with_change(self):
        self.rig.run(4000)
        # 12.50
        for key in "1250":
            self.rig.press(key)
        self.rig.press("СУММА")
        # 3.00
        for key in "300":
            self.rig.press(key)
        self.rig.press("СУММА")
        # наличными 20.00
        for key in "2000":
            self.rig.press(key)
        self.rig.press("ОПЛ")

        text = self.rig.bus.printer_text()
        # содержимое сверяем без учёта регистра (см. комментарий выше)
        self.assertIn("ИТОГ", text.upper())
        self.assertIn("НАЛИЧНЫМИ", text.upper())
        self.assertIn("СДАЧА", text.upper())
        self.assertIn("СПАСИБО", text.upper())
        self.assertIn("15.50", text)              # итог
        self.assertIn("20.00", text)              # внесено
        self.assertIn("4.50", text)               # сдача 20.00 - 15.50
        self.assertIn("12.50", text)
        self.assertIn("3.00", text)
        # чек закрыт
        self.assertEqual(self.rig.cpu.ram[self.rig.symbols["ITEM_N"]], 0)
        # режим "сдача" -- на индикаторе 4.50
        self.assertEqual(self.rig.cpu.ram[self.rig.symbols["MODE"]], 3)
        self.assertTrue(self.rig.bus.display_digits().endswith("450"),
                        self.rig.bus.display_chars())

    def test_cancel_voids_the_last_item(self):
        self.rig.run(4000)
        for key in "500":
            self.rig.press(key)
        self.rig.press("СУММА")                   # 5.00
        for key in "250":
            self.rig.press(key)
        self.rig.press("СУММА")                   # +2.50 = 7.50
        self.rig.press("ОТМЕНА")                  # -2.50 = 5.00
        total_addr = self.rig.symbols["TOTAL"]
        self.assertEqual(self.rig.cpu.ram[total_addr], 0x00)
        self.assertEqual(self.rig.cpu.ram[total_addr + 1], 0x05)
        self.assertIn("ОТМЕНА", self.rig.bus.printer_text().upper())

    def test_not_enough_cash_does_not_print_change(self):
        self.rig.run(4000)
        for key in "1000":
            self.rig.press(key)
        self.rig.press("СУММА")                   # 10.00
        for key in "500":
            self.rig.press(key)
        self.rig.press("ОПЛ")                     # внесено 5.00 < 10.00
        self.assertIn("НЕДОСТАТОЧНО",
                      self.rig.bus.printer_text().upper())

    def test_main_loop_stays_responsive(self):
        """Главный цикл -- опросный: индикатор и клавиатура работают всегда."""
        self.rig.run(50_000)
        bus = self.rig.bus
        # за 50k инструкций должно быть много полных рефрешей
        self.assertGreater(len(bus.writes_to(PORT_MAP["PPI_PB"])), 100)
        self.assertGreater(bus.reads_of(PORT_MAP["PPI_PC"]), 100)
        self.assertIsNone(self.rig.cpu.error)


# ---------------------------------------------------------------------------
# 4. Тот же образ на настоящей плате (если board/cashboard.py уже есть)
# ---------------------------------------------------------------------------
def _board_available():
    try:
        module = importlib.import_module("board.cashboard")
    except Exception as exc:                  # pragma: no cover - зависит от hal-ppi
        return False, f"board/cashboard.py недоступен: {exc!r}"
    if not hasattr(module, "CashRegisterBoard"):
        return False, "в board/cashboard.py нет CashRegisterBoard"
    return True, ""


BOARD_OK, BOARD_REASON = _board_available()


@unittest.skipUnless(BOARD_OK, BOARD_REASON)
class TestDemoOnRealBoard(unittest.TestCase):
    """Демо-образ на плате hal-ppi: индикатор показывает цифры после клавиш."""

    def setUp(self):
        from board.cashboard import CashRegisterBoard
        self.board = CashRegisterBoard()
        image, self.symbols = build_demo()
        self.rom = ROM("demo-stand-in")
        self.rom.load_block(DEMO_BASE, image)
        self.cpu = CPU8051(self.rom, self.board)

    def _run(self, steps: int) -> None:
        self.cpu.run_steps(steps)
        self.assertFalse(self.cpu.halted,
                         f"CPU остановлен: {self.cpu.error}")
        self.assertIsNone(self.cpu.error)

    def test_display_shows_digits_after_key_presses(self):
        self._run(5000)
        before = self.board.display.text()
        if hasattr(self.board.keyboard, "press"):
            self.board.keyboard.press("5")
            self._run(20000)
            self.board.keyboard.release("5")
            self._run(5000)
        else:                                   # pragma: no cover
            self.board.keyboard.tap("5")
            self._run(20000)
        after = self.board.display.text()
        self.assertNotEqual(before, after,
                            "индикатор платы не изменился после нажатия '5'")
        self.assertIn("5", after)

    def test_receipt_reaches_the_board_printer(self):
        self._run(5000)
        for key in "500":
            self.board.keyboard.press(key)
            self._run(4000)
            self.board.keyboard.release(key)
            self._run(1500)
        self.board.keyboard.press("СУММА")
        self._run(20000)
        self.board.keyboard.release("СУММА")
        self._run(4000)
        text = self.board.printer.text()
        self.assertIn("5.00", text)
        self.assertIn("ДЕМО-ПРОГРАММА", text.upper())

    # -- сценарий: полная продажа на настоящей плате ----------------------
    def _tap(self, key: str, hold: int = 4000, settle: int = 1500) -> None:
        self.board.keyboard.press(key)
        self._run(hold)
        self.board.keyboard.release(key)
        self._run(settle)

    def test_full_sale_scenario_on_the_board(self):
        """Полная продажа 5.00: индикатор и чек на настоящей плате.

        Ровно эту регрессию ловит сценарий: плата запоминает порядок
        записи «данные -> знакоместо» по САМОМУ ПЕРВОМУ обращению к
        индикатору (board/cashboard.py, ``_ppi_order``), а демо пишет
        именно так -- PA, затем PB -- во всём REFRESH/SCAN_KEY.  Если
        первым событием оказывается только PB (как в старой
        инициализации: PB = 0 до первой записи в PA), плата трактует все
        последующие пары как «знакоместо -> данные» и индикатор съезжает
        на одну позицию: индикатор режима уходит в крайнее правое
        знакоместо, сумма стоит левее, чем должна.
        """
        self._run(4000)
        for key in "500":                       # 5.00
            self._tap(key)
        self.assertEqual(self.board.display.text(), "0    500",
                         "индикатор: режим слева, сумма по правому краю")
        self._tap("СУММА")                      # позиция в чеке, ввод чист
        for key in "1000":                      # 10.00 наличными
            self._tap(key)
        self._tap("ОПЛ")

        display = self.board.display.text()
        self.assertEqual(display[0], "3",
                         "индикатор режима (сдача) не в нулевом знакоместе: "
                         f"{display!r}")
        self.assertTrue(display.endswith("500"),
                        f"сдача 5.00 не по правому краю индикатора: {display!r}")
        self.assertEqual(self.cpu.ram[self.symbols["MODE"]], 3)
        self.assertEqual(self.cpu.ram[self.symbols["ITEM_N"]], 0,
                         "чек не закрыт")

        text = self.board.printer.text().upper()
        for word in ("ДЕМО-ПРОГРАММА", "ИТОГ", "НАЛИЧНЫМИ", "СДАЧА", "СПАСИБО"):
            self.assertIn(word, text, f"в чеке нет {word!r}:\n{text}")
        for amount in ("5.00", "10.00"):
            self.assertIn(amount, text)
        raw = "\n".join(self.board.printer.raw_paper())
        self.assertTrue(all(ord(ch) < 0x80 for ch in raw),
                        "лента должна оставаться 7-битным транслитом")


if __name__ == "__main__":                    # pragma: no cover
    unittest.main(verbosity=2)
