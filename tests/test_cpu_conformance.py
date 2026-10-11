# -*- coding: utf-8 -*-
"""Конформанс-тесты ядра MCS-51: все 256 опкодов ``m8051/cpu.py``.

Что здесь проверяется
---------------------
1. **Таблицы групп.**  ``GROUPS`` разбивает пространство из 256 опкодов на
   осмысленные группы (арифметика, логика, перемещение данных, переходы,
   битовые операции, стек, вызовы, прочее) - по опкоду сразу видно,
   реализован ли он и в какой он группе.
2. **Прогон по всем опкодам.**  Каждый опкод исполняется одним шагом;
   ни один, кроме ``0xA5`` (зарезервирован Intel), не должен давать
   ``unimplemented opcode``.  Такой прогон ловит случайно потерянную
   ветку в ``_execute`` (в том числе после рефакторинга горячего пути).
3. **Минимальные исполняемые проверки каждой группы** - по нескольку
   инструкций с проверкой регистров/флагов.
4. **Регрессии мест, где раньше были баги.**  Ниже перечислено то, что
   когда-то падало; всё это исправлено в ``m8051/cpu.py``, и тесты
   теперь проверяют правильное поведение напрямую, без skip-guard'ов:
   * ``CJNE`` прыгает по признаку «операнды различаются», а **не** по CY;
   * ``DA A`` для ``0x9A..0x9F`` (коррекция старшей тетрады по значению
     **после** коррекции младшей) - иначе ломается вся BCD-арифметика денег;
   * флаги CY/AC/OV у ``ADD``/``ADDC``/``SUBB`` обязаны обновляться
     (не «залипать») - залипший флаг ломает ``DA A``;
   * ``0x73`` ``JMP @A+DPTR``: PC = (DPTR + A) & 0xFFFF, 2 цикла;
   * ``MUL AB``/``DIV AB`` сбрасывают ранее взведённый OV;
   * ``PSW.P`` отражает ACC после **любой** записи в него (сеттер ``acc``);
   * ``XCHD A,@Ri`` действительно меняет младшие тетрады местами;
   * ``AJMP``/``ACALL`` на границе 2 КБ страницы берут страницу по PC+2.

Запуск::

    python -m unittest tests.test_cpu_conformance -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from m8051 import CPU8051, NullBus, ROM  # noqa: E402

SFR_SP = 0x81
SFR_PSW = 0xD0
SFR_ACC = 0xE0
SFR_B = 0xF0
SFR_IE = 0xA8
SFR_TCON = 0x88

CY = 0x80          # PSW.7
AC = 0x40          # PSW.6
OV = 0x04          # PSW.2
PARITY = 0x01      # PSW.0


# --------------------------------------------------------------------------- #
# вспомогательные построители программ
# --------------------------------------------------------------------------- #
def make(program, base: int = 0x0000) -> CPU8051:
    """Свежий процессор с ``program`` по адресу ``base``."""
    rom = ROM("conformance")
    rom.load_block(base, bytes(program))
    return CPU8051(rom, NullBus())


def build_cond(setup: bytes, cond: bytes):
    """Собрать ``<setup> ; <cond>+rel ; LJMP NO ; LJMP YES ; NO: SJMP $ ; YES: SJMP $``.

    ``cond`` - опкод и операнды инструкции **без** байта смещения.
    Смещение считается по общему для всех относительных инструкций правилу
    ``target = адрес_инструкции + размер + rel``, поэтому хелпер работает и
    для ``SJMP``, и для ``JB``, и для ``CJNE``, и для ``DJNZ``.

    Возвращает ``(program, addr_cond, addr_no, addr_yes)``.
    """
    prog = bytearray(setup)
    cond_at = len(prog)
    prog += bytes(cond) + b"\x00"                   # место под rel
    no_ljmp = len(prog)
    prog += bytes([0x02, 0x00, 0x00])               # LJMP NO  (адрес впишем)
    yes_ljmp = len(prog)
    prog += bytes([0x02, 0x00, 0x00])               # LJMP YES
    no_at = len(prog)
    prog += b"\x80\xfe"                             # NO:  SJMP $
    yes_at = len(prog)
    prog += b"\x80\xfe"                             # YES: SJMP $

    prog[no_ljmp + 1] = (no_at >> 8) & 0xFF
    prog[no_ljmp + 2] = no_at & 0xFF
    prog[yes_ljmp + 1] = (yes_at >> 8) & 0xFF
    prog[yes_ljmp + 2] = yes_at & 0xFF

    size = len(cond) + 1                            # opcode + operands + rel
    prog[cond_at + size - 1] = (yes_at - (cond_at + size)) & 0xFF
    return bytes(prog), cond_at, no_at, yes_at


def _rng(first: int, last: int) -> tuple:
    """Включительный диапазон опкодов."""
    return tuple(range(first, last + 1))


# --------------------------------------------------------------------------- #
# таблицы: какой опкод к какой группе относится
# --------------------------------------------------------------------------- #
GROUPS = {
    "перемещение данных": (
        _rng(0x74, 0x7F)                       # MOV A/Rn/@Ri/direct,#imm
        + (0x83, 0x85) + _rng(0x86, 0x8F)      # MOVC @A+PC, MOV direct,*
        + (0x90, 0x93)                         # MOV DPTR,# / MOVC @A+DPTR
        + (0xA6, 0xA7) + _rng(0xA8, 0xAF)      # MOV @Ri/direct
        + (0xC5, 0xC6, 0xC7) + _rng(0xC8, 0xCF)  # XCH A,direct/@Ri/Rn
        + (0xD6, 0xD7)                         # XCHD A,@Ri
        + (0xE0, 0xE2, 0xE3, 0xE5, 0xE6, 0xE7) + _rng(0xE8, 0xEF)
        + (0xF0, 0xF2, 0xF3, 0xF5, 0xF6, 0xF7) + _rng(0xF8, 0xFF)
    ),
    "арифметика": (
        _rng(0x04, 0x0F)                       # INC
        + _rng(0x14, 0x1F)                     # DEC
        + _rng(0x24, 0x2F)                     # ADD
        + _rng(0x34, 0x3F)                     # ADDC
        + (0x84,)                              # DIV AB
        + _rng(0x94, 0x9F)                     # SUBB
        + (0xA3, 0xA4)                         # INC DPTR, MUL AB
        + (0xD4,)                              # DA A
    ),
    "логика": (
        (0x03, 0x13, 0x23, 0x33)               # RR/RRC/RL/RLC
        + (0x42, 0x43) + _rng(0x44, 0x4F)      # ORL
        + (0x52, 0x53) + _rng(0x54, 0x5F)      # ANL
        + (0x62, 0x63) + _rng(0x64, 0x6F)      # XRL
        + (0xC4, 0xE4, 0xF4)                   # SWAP/CLR A/CPL A
    ),
    "переходы": (
        (0x01, 0x02, 0x10, 0x20, 0x21, 0x30, 0x40, 0x41, 0x50, 0x60,
         0x61, 0x70, 0x73, 0x80, 0x81, 0xA1, 0xC1, 0xE1)
        + _rng(0xB4, 0xBF)                     # CJNE
        + (0xD5,) + _rng(0xD8, 0xDF)           # DJNZ
    ),
    "битовые операции": (
        0x72, 0x82, 0x92, 0xA0, 0xA2, 0xB0, 0xB2, 0xB3,
        0xC2, 0xC3, 0xD2, 0xD3,
    ),
    "стек": (0xC0, 0xD0),
    "вызовы": (0x11, 0x12, 0x22, 0x31, 0x32, 0x51, 0x71, 0x91, 0xB1, 0xD1, 0xF1),
    "прочее": (0x00, 0xA5),
}

#: Опкоды, которые ядро сегодня НЕ исполняет.  Пусто: ``0x73``
#: (``JMP @A+DPTR``) реализован, поэтому прогон идёт по всем 256 опкодам.
#: Новый пробел сюда не «прячут» - его сначала чинят, потом пишут тест.
KNOWN_GAPS = frozenset()

#: Зарезервирован Intel: ядро обязано сообщить об этом, а не молчать.
RESERVED = {0xA5}


# =========================================================================== #
class TestOpcodeTable(unittest.TestCase):
    """Таблицы групп и прогон по всем 256 опкодам."""

    def test_group_tables_partition_all_256_opcodes(self):
        """Группы разбивают ровно всё пространство опкодов, без дублей."""
        seen = []
        for name, opcodes in GROUPS.items():
            self.assertTrue(opcodes, f"группа {name!r} пуста")
            seen.extend(opcodes)
        self.assertEqual(len(seen), len(set(seen)),
                         "какой-то опкод попал сразу в две группы")
        self.assertEqual(sorted(seen), list(range(256)),
                         "таблицы групп не покрывают все 256 опкодов")

    def test_no_known_gaps_and_reserved_is_listed(self):
        """Пробелов нет; зарезервированный опкод обязан состоять в группах."""
        self.assertEqual(set(KNOWN_GAPS), set(),
                         "неисполняемых опкодов быть не должно - почините ядро")
        self.assertTrue(RESERVED <= set(GROUPS["прочее"]))

    def test_every_opcode_executes_without_unimplemented_error(self):
        """Ни один опкод не должен падать в «unimplemented».

        Программа - 512 нулевых байт: операнды нулевые, адреса нулевые,
        поэтому ни одна инструкция не может «уйти» за пределы образа.
        """
        for op in range(256):
            if op in KNOWN_GAPS:
                continue
            prog = bytearray(0x200)
            prog[0] = op
            cpu = make(bytes(prog))
            cpu.step()
            if op in RESERVED:
                self.assertIsNotNone(
                    cpu.error,
                    f"зарезервированный опкод 0x{op:02X} обязан быть отмечен")
                self.assertIn("a5", cpu.error.lower(),
                              f"сообщение об 0xA5: {cpu.error!r}")
                continue
            self.assertIsNone(
                cpu.error,
                f"опкод 0x{op:02X} (группа "
                f"{next(n for n, s in GROUPS.items() if op in s)}): {cpu.error}")

    def test_opcode_0x73_jmp_a_dptr(self):
        """``JMP @A+DPTR``: PC = (DPTR + A) & 0xFFFF, 2 машинных цикла.

        Раньше опкода не было вовсе (и в ядре, и в дизассемблере) - это был
        единственный неисполняемый опкод из 256.
        """
        cpu = make(b"\x90\x01\x00\x74\x05\x73\x80\xfe" + bytes(0x110) + b"\x80\xfe")
        cpu.run_steps(2)                       # MOV DPTR,#0100h ; MOV A,#05h
        cycles = cpu.step()                    # JMP @A+DPTR
        self.assertIsNone(cpu.error, "0x73 обязан исполняться без ошибки")
        self.assertEqual(cpu.pc, 0x0105, "PC <- DPTR + A")
        self.assertEqual(cycles, 2,
                         "JMP @A+DPTR - 2 машинных цикла (Keil is51_jmp)")

        # перенос за 0xFFFF маскируется: FFFFh + 1 -> 0000h
        cpu = make(b"\x90\xff\xff\x74\x01\x73\x80\xfe" + bytes(0x20))
        cpu.run_steps(3)
        self.assertIsNone(cpu.error)
        self.assertEqual(cpu.pc, 0x0000, "(DPTR + A) & 0xFFFF")


# =========================================================================== #
class TestArithmetic(unittest.TestCase):
    """ADD/ADDC/SUBB: CY, AC и OV обязаны ОБНОВЛЯТЬСЯ, а не «залипать».

    «Залипший» флаг ломает ``DA A``, то есть всю десятичную арифметику денег.
    """

    @staticmethod
    def _after(program, steps: int) -> CPU8051:
        cpu = make(bytes(program) + b"\x80\xfe")
        cpu.run_steps(steps)
        return cpu

    def test_add_sets_carry_auxiliary_and_overflow(self):
        # 08h + 08h = 10h
        cpu = self._after([0x74, 0x08, 0x24, 0x08], 2)
        self.assertEqual(cpu.acc, 0x10)
        self.assertTrue(cpu.psw & AC, "перенос из младшей тетрады -> AC=1")
        self.assertFalse(cpu.psw & CY, "битового переноса нет -> CY=0")
        self.assertFalse(cpu.psw & OV, "знаковый переноса нет -> OV=0")

        # 7Fh + 01h = 80h: только знаковый перенос
        cpu = self._after([0x74, 0x7F, 0x24, 0x01], 2)
        self.assertEqual(cpu.acc, 0x80)
        self.assertTrue(cpu.psw & OV, "OV=1 при 7Fh+1")
        self.assertFalse(cpu.psw & CY, "CY=0 при 7Fh+1")
        self.assertTrue(cpu.psw & AC, "AC=1 при 7Fh+1")

        # 80h + 80h = 00h: и битовый, и знаковый перенос
        cpu = self._after([0x74, 0x80, 0x24, 0x80], 2)
        self.assertEqual(cpu.acc, 0x00)
        self.assertTrue(cpu.psw & CY, "CY=1 при 80h+80h")
        self.assertTrue(cpu.psw & OV, "OV=1 при 80h+80h")
        self.assertFalse(cpu.psw & AC, "AC=0 при 80h+80h")

        # FFh + 01h = 00h: только битовый перенос
        cpu = self._after([0x74, 0xFF, 0x24, 0x01], 2)
        self.assertEqual(cpu.acc, 0x00)
        self.assertTrue(cpu.psw & CY, "CY=1 при FFh+1")
        self.assertTrue(cpu.psw & AC, "AC=1 при FFh+1")
        self.assertFalse(cpu.psw & OV, "OV=0 при FFh+1")

    def test_add_flags_are_not_sticky(self):
        # Взводим все три флага, затем складываем 01h+01h: всё обязано сброситься.
        cpu = self._after([0x74, 0xFF, 0x24, 0x01,      # CY=1, AC=1
                           0x74, 0x7F, 0x24, 0x01,      # OV=1, AC=1
                           0x74, 0x01, 0x24, 0x01], 6)  # ни одного переноса
        self.assertEqual(cpu.acc, 0x02)
        self.assertFalse(cpu.psw & CY, "CY залип от предыдущего ADD")
        self.assertFalse(cpu.psw & AC, "AC залип от предыдущего ADD")
        self.assertFalse(cpu.psw & OV, "OV залип от предыдущего ADD")

    def test_addc_consumes_then_clears_the_carry(self):
        # SETB C ; MOV A,#00h ; ADDC A,#00h -> 01h, CY сброшен
        cpu = self._after([0xD3, 0x74, 0x00, 0x34, 0x00], 3)
        self.assertEqual(cpu.acc, 0x01, "заемный бит вошёл в сумму")
        self.assertFalse(cpu.psw & CY, "ADDC обязан сбросить CY после работы")

        # цепочка: FFh+01h -> CY=1; FFh+00h+CY -> 00h, CY снова 1
        cpu = self._after([0x74, 0xFF, 0x24, 0x01, 0x74, 0xFF, 0x34, 0x00], 4)
        self.assertEqual(cpu.acc, 0x00)
        self.assertTrue(cpu.psw & CY)

        # и снова без переноса: 00h+00h+CY(1) = 01h, CY=0
        cpu = self._after([0x74, 0xFF, 0x24, 0x01, 0x74, 0x00, 0x34, 0x00], 4)
        self.assertEqual(cpu.acc, 0x01)
        self.assertFalse(cpu.psw & CY)

    def test_subb_flags(self):
        # 10h - 20h = F0h: заём из старшего байта есть, из тетрады - нет
        cpu = self._after([0xC3, 0x74, 0x10, 0x94, 0x20], 3)
        self.assertEqual(cpu.acc, 0xF0)
        self.assertTrue(cpu.psw & CY, "CY=1 (заём)")
        self.assertFalse(cpu.psw & AC, "AC=0: младшие тетрады не занимали")
        self.assertFalse(cpu.psw & OV, "OV=0")

        # 05h - 06h = FFh: занимают обе половины
        cpu = self._after([0xC3, 0x74, 0x05, 0x94, 0x06], 3)
        self.assertEqual(cpu.acc, 0xFF)
        self.assertTrue(cpu.psw & CY)
        self.assertTrue(cpu.psw & AC, "AC=1: младшая тетрада занимала")
        self.assertFalse(cpu.psw & OV)

        # 80h - 01h = 7Fh: без заёма, но знаковый перенос
        cpu = self._after([0xC3, 0x74, 0x80, 0x94, 0x01], 3)
        self.assertEqual(cpu.acc, 0x7F)
        self.assertFalse(cpu.psw & CY)
        self.assertTrue(cpu.psw & AC, "AC=1: 00h-01h занимает")
        self.assertTrue(cpu.psw & OV, "отрицательное - положительное -> OV=1")

        # 7Fh - FFh = 80h: заём есть, знаковый перенос есть
        cpu = self._after([0xC3, 0x74, 0x7F, 0x94, 0xFF], 3)
        self.assertEqual(cpu.acc, 0x80)
        self.assertTrue(cpu.psw & CY)
        self.assertFalse(cpu.psw & AC)
        self.assertTrue(cpu.psw & OV)

    def test_subb_flags_are_not_sticky(self):
        # 10h-20h (CY=1), затем CLR C и 20h-10h без заёма:
        # все три флага обязаны сброситься
        cpu = self._after([0xC3, 0x74, 0x10, 0x94, 0x20, 0xC3,
                           0x74, 0x20, 0x94, 0x10], 6)
        self.assertEqual(cpu.acc, 0x10)
        self.assertFalse(cpu.psw & CY, "второй SUBB прошёл без заёма")
        self.assertFalse(cpu.psw & AC, "AC сброшен")
        self.assertFalse(cpu.psw & OV, "OV сброшен")

    def test_mul_ab_and_div_ab(self):
        # 12h * 10h = 120h -> A=20h, B=01h, CY всегда сброшен
        cpu = self._after([0x74, 0x12, 0x75, 0xF0, 0x10, 0xA4], 3)
        self.assertEqual(cpu.acc, 0x20)
        self.assertEqual(cpu.sfr[SFR_B], 0x01)
        self.assertFalse(cpu.psw & CY, "MUL обязан сбросить CY")

        # 0Ah / 03h -> A=3, B=1
        cpu = self._after([0x74, 0x0A, 0x75, 0xF0, 0x03, 0x84], 3)
        self.assertEqual(cpu.acc, 3)
        self.assertEqual(cpu.sfr[SFR_B], 1)
        self.assertFalse(cpu.psw & CY, "DIV обязан сбросить CY")

        # деление на ноль: регистры не трогаются, OV=1
        cpu = self._after([0x74, 0x0A, 0x75, 0xF0, 0x00, 0x84], 3)
        self.assertEqual(cpu.acc, 0x0A, "при делении на 0 A не меняется")
        self.assertTrue(cpu.psw & OV, "деление на 0 -> OV=1")

    def test_inc_dec_wrap_around(self):
        # MOV A,#0FFh ; INC A -> 00h ; MOV A,#00h ; DEC A -> FFh
        cpu = self._after([0x74, 0xFF, 0x04, 0x74, 0x00, 0x14], 4)
        self.assertEqual(cpu.acc, 0xFF)

    def test_inc_dec_on_direct_and_register(self):
        # INC 30h (00h -> 01h), DEC 30h (01h -> 00h);
        # R4: 10h --INC--> 11h --DEC--> 10h (возврат к исходному)
        cpu = self._after([0x75, 0x30, 0x00, 0x05, 0x30, 0x15, 0x30,
                           0x7C, 0x10, 0x0C, 0x1C], 6)
        self.assertEqual(cpu.ram[0x30], 0x00)
        self.assertEqual(cpu.ram[0x04], 0x10, "INC R4; DEC R4 вернули 10h")


# =========================================================================== #
class TestDecimalAdjust(unittest.TestCase):
    """``DA A`` - регрессия для диапазона 0x9A..0x9F."""

    def test_da_a_corrects_0x9a_to_0x9f(self):
        """Старшая тетрада проверяется ПОСЛЕ коррекции младшей.

        Для 0x9A..0x9F коррекция младшей тетрады даёт 0xA0..0xA5, и только
        **этот** результат должен проверяться на «больше 9».  Иначе 0x9A
        превращается в 0xA0 без переноса, и многобайтовый BCD-итог (то есть
        любая сумма денег) разъезжается на границе разрядов.
        """
        expected = {0x9A: 0x00, 0x9B: 0x01, 0x9C: 0x02,
                    0x9D: 0x03, 0x9E: 0x04, 0x9F: 0x05}
        for value, want in expected.items():
            with self.subTest(acc=f"0x{value:02X}"):
                cpu = make(bytes([0x74, value, 0xD4, 0x80, 0xFE]))
                cpu.run_steps(2)                  # MOV A,#val ; DA A
                self.assertEqual(cpu.acc, want,
                                 f"DA A(0x{value:02X}) должна дать 0x{want:02X}")
                self.assertTrue(cpu.psw & CY, "перенос в старший разряд")
                self.assertFalse(cpu.psw & AC, "DA A не трогает AC")

    def test_da_a_after_a_real_bcd_addition(self):
        # 99h + 01h -> 00h с переносом
        cpu = make(b"\x74\x99\x24\x01\xd4\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x00)
        self.assertTrue(cpu.psw & CY)

        # 50h + 50h -> 00h с переносом (AC не взводился!)
        cpu = make(b"\x74\x50\x24\x50\xd4\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x00)
        self.assertTrue(cpu.psw & CY)

        # 19h + 01h -> 20h, переноса нет
        cpu = make(b"\x74\x19\x24\x01\xd4\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x20)
        self.assertFalse(cpu.psw & CY)

    def test_da_a_honours_auxiliary_carry(self):
        # AC взведён -> поправка +6 даже если младшая тетрада <= 9
        cpu = make(b"\xd4\x80\xfe")
        cpu.sfr[SFR_PSW] = AC
        cpu.acc = 0x14
        cpu.step()
        self.assertEqual(cpu.acc, 0x1A, "AC вынуждает коррекцию младшей тетрады")
        self.assertTrue(cpu.psw & AC, "DA A не сбрасывает AC")
        self.assertFalse(cpu.psw & CY)

    def test_da_a_honours_an_incoming_carry(self):
        # CY взведён -> +60h к старшей тетраде, CY остаётся
        cpu = make(b"\xd4\x80\xfe")
        cpu.sfr[SFR_PSW] = CY
        cpu.acc = 0x45
        cpu.step()
        self.assertEqual(cpu.acc, 0xA5, "45h + 60h при CY=1")
        self.assertTrue(cpu.psw & CY, "CY обязан пережить DA A")
        self.assertFalse(cpu.psw & AC, "AC из ничего не появляется")


# =========================================================================== #
class TestCJNE(unittest.TestCase):
    """``CJNE`` прыгает при **неравенстве**, а не по флагу CY."""

    @staticmethod
    def _run(setup: bytes, cond: bytes, steps: int, ram=None):
        prog, cond_at, no_at, yes_at = build_cond(setup, cond)
        cpu = make(prog)
        if ram:
            for addr, value in ram.items():
                cpu.ram[addr] = value
        cpu.run_steps(steps)
        cpu.step()                                # сама CJNE
        if cpu.pc != yes_at and cpu.pc != no_at:
            # переход не взялся: PC остановился на LJMP NO - доводим его,
            # чтобы адреса NO/YES были сравнимы
            cpu.step()
        return cpu, no_at, yes_at

    def test_branches_on_difference_even_when_carry_is_clear(self):
        # A=5 > 2 -> CY=0, но переход ОБЯЗАН быть
        cpu, _, yes_at = self._run(b"\x74\x05", (0xB4, 0x02), 1)
        self.assertEqual(cpu.pc, yes_at, "5 != 2 -> переход, несмотря на CY=0")
        self.assertFalse(cpu.psw & CY, "5 > 2 -> CY=0")

    def test_branches_with_carry_set(self):
        cpu, _, yes_at = self._run(b"\x74\x02", (0xB4, 0x05), 1)
        self.assertEqual(cpu.pc, yes_at, "2 != 5 -> переход")
        self.assertTrue(cpu.psw & CY, "2 < 5 -> CY=1")

    def test_does_not_branch_when_equal(self):
        cpu, no_at, _ = self._run(b"\x74\x05", (0xB4, 0x05), 1)
        self.assertEqual(cpu.pc, no_at, "5 == 5 -> перехода быть не должно")
        self.assertFalse(cpu.psw & CY, "равные операнды -> CY=0")

    def test_does_not_branch_when_equal_even_with_carry_set_before(self):
        """Условие перехода и флаг CY - независимые вещи."""
        cpu, no_at, _ = self._run(b"\xd3\x74\x05", (0xB4, 0x05), 2)
        self.assertEqual(cpu.pc, no_at,
                         "равные операнды -> перехода нет, даже при CY=1")
        self.assertFalse(cpu.psw & CY, "CJNE пересчитывает CY при каждом исполнении")

    def test_direct_form(self):
        cpu, _, yes_at = self._run(b"\x74\x09", (0xB5, 0x30), 1, ram={0x30: 0x02})
        self.assertEqual(cpu.pc, yes_at, "A=9 != 30h=2 -> переход")
        self.assertFalse(cpu.psw & CY, "9 > 2 -> CY=0")

        cpu, no_at, _ = self._run(b"\x74\x09", (0xB5, 0x30), 1, ram={0x30: 0x09})
        self.assertEqual(cpu.pc, no_at, "A=9 == 30h=9 -> без перехода")

    def test_register_form(self):
        cpu, _, yes_at = self._run(b"\x78\x05", (0xB8, 0x02), 1)
        self.assertEqual(cpu.pc, yes_at, "R0=5 != 2 -> переход")
        cpu, no_at, _ = self._run(b"\x78\x05", (0xB8, 0x05), 1)
        self.assertEqual(cpu.pc, no_at, "R0=5 == 5 -> без перехода")

    def test_indirect_form(self):
        # MOV R0,#40h ; MOV @R0,#07h
        cpu, _, yes_at = self._run(b"\x78\x40\x76\x07", (0xB6, 0x03), 2)
        self.assertEqual(cpu.pc, yes_at, "@R0=7 != 3 -> переход")
        cpu, no_at, _ = self._run(b"\x78\x40\x76\x07", (0xB6, 0x07), 2)
        self.assertEqual(cpu.pc, no_at, "@R0=7 == 7 -> без перехода")

    def test_every_cjne_form_is_covered_by_the_group_table(self):
        for op in (0xB4, 0xB5, 0xB6, 0xB7) + tuple(range(0xB8, 0xC0)):
            self.assertIn(op, GROUPS["переходы"], f"CJNE 0x{op:02X} не в таблице")


# =========================================================================== #
class TestLogicAndRotate(unittest.TestCase):

    def test_anl_orl_xrl_on_the_accumulator(self):
        # 0F0h OR 0Fh = 0FFh ; AND 3Ch = 03Ch ; XOR 0FFh = 0C3h
        cpu = make(b"\x74\xf0\x44\x0f\x54\x3c\x64\xff\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.acc, 0xC3)

    def test_anl_orl_xrl_on_direct_memory(self):
        # 0F0h | 0C3h = 0F3h ; 0F3h & 0C3h = 0C3h ; 0C3h ^ 0C3h = 00h
        cpu = make(b"\x75\x30\xf0\x74\xc3\x42\x30\x52\x30\x62\x30\x80\xfe")
        cpu.run_steps(5)
        self.assertEqual(cpu.ram[0x30], 0x00)

    def test_anl_orl_xrl_on_direct_with_immediate(self):
        # 0Fh | 0F0h = 0FFh ; 0FFh & 3Ch = 03Ch ; 3Ch ^ 0FFh = 0C3h
        cpu = make(b"\x75\x30\x0f\x43\x30\xf0\x53\x30\x3c\x63\x30\xff\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.ram[0x30], 0xC3)

    def test_anl_orl_xrl_with_registers(self):
        # 0C3h | 0F0h = 0F3h ; 0F3h & 0F0h = 0F0h ; 0F0h ^ 0F0h = 00h
        cpu = make(b"\x7b\xf0\x74\xc3\x4b\x5b\x6b\x80\xfe")
        cpu.run_steps(5)
        self.assertEqual(cpu.acc, 0x00)

    def test_anl_orl_xrl_with_indirect(self):
        # MOV R0,#40h ; MOV @R0,#0Fh ; MOV A,#0C3h ; ORL A,@R0 ; ANL A,@R0
        # 0C3h | 0Fh = 0CFh, затем 0CFh & 0Fh = 0Fh
        cpu = make(b"\x78\x40\x76\x0f\x74\xc3\x46\x56\x80\xfe")
        cpu.run_steps(5)
        self.assertEqual(cpu.acc, 0x0F)

    def test_rotates(self):
        # 81h RR -> 0C0h ; 0C0h RL -> 81h
        cpu = make(b"\x74\x81\x03\x23\x80\xfe")
        cpu.run_steps(2)
        self.assertEqual(cpu.acc, 0xC0, "RR A")
        cpu.step()
        self.assertEqual(cpu.acc, 0x81, "RL A")

    def test_rotate_through_carry(self):
        # 01h, CY=1 -> RRC даёт A=80h, а бит0 уходит в CY
        cpu = make(b"\x74\x01\xd3\x13\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x80)
        self.assertTrue(cpu.psw & CY, "бит0 ACC обязан уйти в CY")

        # 80h, CY=0 -> RLC даёт A=00h, а бит7 уходит в CY
        cpu = make(b"\x74\x80\xc3\x33\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x00)
        self.assertTrue(cpu.psw & CY, "бит7 ACC обязан уйти в CY")

    def test_swap_and_clear_cpl(self):
        # 0A5h SWAP -> 5Ah
        cpu = make(b"\x74\xa5\xc4\x80\xfe")
        cpu.run_steps(2)
        self.assertEqual(cpu.acc, 0x5A)

        # 0Fh CLR A -> 00h ; CPL A -> FFh
        cpu = make(b"\x74\x0f\xe4\xf4\x80\xfe")
        cpu.run_steps(2)
        self.assertEqual(cpu.acc, 0x00, "CLR A")
        cpu.step()
        self.assertEqual(cpu.acc, 0xFF, "CPL A")


# =========================================================================== #
class TestMove(unittest.TestCase):

    def test_immediate_and_direct_forms(self):
        # MOV A,#5Ah ; MOV 30h,A ; MOV 31h,#0C3h ; MOV 32h,31h ; MOV A,32h
        cpu = make(b"\x74\x5a\xf5\x30\x75\x31\xc3\x85\x31\x32\xe5\x32\x80\xfe")
        cpu.run_steps(5)
        self.assertEqual(cpu.ram[0x30], 0x5A, "MOV direct,A")
        self.assertEqual(cpu.ram[0x31], 0xC3, "MOV direct,#imm")
        self.assertEqual(cpu.ram[0x32], 0xC3, "MOV direct,direct")
        self.assertEqual(cpu.acc, 0xC3, "MOV A,direct")

    def test_register_and_indirect_forms(self):
        # MOV R0,#40h ; MOV @R0,#5Ah ; MOV A,@R0 ; MOV 30h,R0 ; MOV R1,30h
        cpu = make(b"\x78\x40\x76\x5a\xe6\xf8\x88\x30\xa9\x30\x80\xfe")
        cpu.run_steps(6)
        self.assertEqual(cpu.ram[0x40], 0x5A, "MOV @Ri,#imm")
        self.assertEqual(cpu.acc, 0x5A, "MOV A,@Ri")
        self.assertEqual(cpu.ram[0x30], 0x5A, "MOV direct,Rn")
        self.assertEqual(cpu.ram[0x01], 0x5A, "MOV Rn,direct")

    def test_dptr_and_movx(self):
        bus = NullBus()
        rom = ROM("movx")
        rom.load_block(0, b"\x90\x12\x34\x74\x5a\xf0\xe0\x80\xfe")
        cpu = CPU8051(rom, bus)
        cpu.run_steps(4)
        self.assertEqual(bus.ext[0x1234], 0x5A, "MOVX @DPTR,A")
        self.assertEqual(cpu.acc, 0x5A, "MOVX A,@DPTR")
        self.assertEqual(cpu.dptr, 0x1234, "MOV DPTR,#imm16")

    def test_movx_through_ri_uses_p2_as_the_high_byte(self):
        # После сброса P2=FFh, поэтому адрес = 0FF40h
        bus = NullBus()
        rom = ROM("movx-ri")
        rom.load_block(0, b"\x78\x40\x74\x3c\xf2\xe2\x80\xfe")
        cpu = CPU8051(rom, bus)
        cpu.run_steps(4)
        self.assertEqual(bus.ext[0xFF40], 0x3C, "MOVX @Ri,A уходит в P2:Ri")
        self.assertEqual(cpu.acc, 0x3C, "MOVX A,@Ri читает тот же адрес")

    def test_movc_from_dptr(self):
        # MOV A,#06h ; MOV DPTR,#0000h ; MOVC A,@A+DPTR -> rom[0006h]
        prog = bytearray(b"\x74\x06\x90\x00\x00\x93\x00\x80\xfe")
        prog[6] = 0xAA
        cpu = make(bytes(prog))
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0xAA)

    def test_movc_from_pc(self):
        # MOV A,#02h ; MOVC A,@A+PC -> rom[0005h] (PC после инструкции + A)
        prog = bytearray(b"\x74\x02\x83\x00\x00\x00\x80\xfe")
        prog[5] = 0xDD
        cpu = make(bytes(prog))
        cpu.run_steps(2)
        self.assertEqual(cpu.acc, 0xDD)

    def test_xch_forms(self):
        # MOV A,#12h ; MOV R2,#34h ; XCH A,R2 (0xC8+n)
        cpu = make(b"\x74\x12\x7a\x34\xca\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x34)
        self.assertEqual(cpu.ram[0x02], 0x12)

        # MOV 30h,#5Ah ; MOV A,#11h ; XCH A,30h
        cpu = make(b"\x75\x30\x5a\x74\x11\xc5\x30\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x5A)
        self.assertEqual(cpu.ram[0x30], 0x11)

        # MOV A,#12h ; MOV @R0,#34h ; XCH A,@R0
        cpu = make(b"\x78\x40\x76\x34\x74\x12\xc6\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.acc, 0x34)
        self.assertEqual(cpu.ram[0x40], 0x12)

    def test_parity_flag_follows_a_direct_load(self):
        # MOV 30h,#01h (нечётное) ; MOV A,30h -> P=1
        cpu = make(b"\x75\x30\x01\xe5\x30\x80\xfe")
        cpu.run_steps(2)
        self.assertEqual(cpu.acc, 0x01)
        self.assertTrue(cpu.psw & PARITY, "нечётное число единиц -> P=1")


# =========================================================================== #
class TestBranches(unittest.TestCase):

    def _cond(self, setup: bytes, cond: bytes, steps: int):
        prog, _, no_at, yes_at = build_cond(setup, cond)
        cpu = make(prog)
        cpu.run_steps(steps)
        cpu.step()                          # сама условная инструкция
        if cpu.pc != yes_at and cpu.pc != no_at:
            # переход не взялся: PC остановился на LJMP NO - доводим его,
            # чтобы адреса NO/YES были сравнимы
            cpu.step()
        return cpu, no_at, yes_at

    def test_sjmp_forward_and_backward(self):
        # 80 05 -> +5 от конца инструкции = адрес 7
        cpu = make(bytes([0x80, 0x05]) + bytes(5) + b"\x80\xfe")
        cpu.step()
        self.assertEqual(cpu.pc, 7)
        # 80 FE -> в себя
        cpu = make(b"\x80\xfe")
        cpu.step()
        self.assertEqual(cpu.pc, 0)

    def test_ljmp(self):
        cpu = make(b"\x02\x12\x34\x80\xfe")
        cpu.step()
        self.assertEqual(cpu.pc, 0x1234)

    def test_ajmp_page_bits(self):
        # опкод 01h: биты 10..8 = 000 -> остаёмся в нулевой странице
        cpu = make(b"\x01\x50\x80\xfe")
        cpu.step()
        self.assertEqual(cpu.pc, 0x0050)

        # опкод 21h: биты 10..8 = 001 -> 0100h
        cpu = make(b"\x21\x00\x80\xfe" + bytes(0x110))
        cpu.step()
        self.assertEqual(cpu.pc, 0x0100)

        # из страницы 0800h: старшие биты берутся из адреса инструкции
        cpu = make(b"\x01\x10\x80\xfe", base=0x0800)
        cpu.pc = 0x0800
        cpu.step()
        self.assertEqual(cpu.pc, 0x0810)

    def test_conditional_jumps(self):
        cases = (
            (b"\x74\x00", (0x60,), "JZ при A=0", True),
            (b"\x74\x01", (0x60,), "JZ при A=1", False),
            (b"\x74\x00", (0x70,), "JNZ при A=0", False),
            (b"\x74\x01", (0x70,), "JNZ при A=1", True),
            (b"\xd3", (0x40,), "JC при CY=1", True),
            (b"\xc3", (0x40,), "JC при CY=0", False),
            (b"\xd3", (0x50,), "JNC при CY=1", False),
            (b"\xc3", (0x50,), "JNC при CY=0", True),
        )
        for setup, cond, name, taken in cases:
            with self.subTest(name):
                cpu, no_at, yes_at = self._cond(setup, cond, 1)
                self.assertEqual(cpu.pc, yes_at if taken else no_at, name)

    def test_bit_conditional_jumps(self):
        cases = (
            (b"\xd2\x00", (0x20, 0x00), "JB при бите=1", True),
            (b"\xc2\x00", (0x20, 0x00), "JB при бите=0", False),
            (b"\xd2\x00", (0x30, 0x00), "JNB при бите=1", False),
            (b"\xc2\x00", (0x30, 0x00), "JNB при бите=0", True),
            (b"\xd2\x00", (0x10, 0x00), "JBC при бите=1", True),
            (b"\xc2\x00", (0x10, 0x00), "JBC при бите=0", False),
        )
        for setup, cond, name, taken in cases:
            with self.subTest(name):
                cpu, no_at, yes_at = self._cond(setup, cond, 1)
                self.assertEqual(cpu.pc, yes_at if taken else no_at, name)

    def test_jbc_also_clears_the_bit(self):
        prog, _, no_at, yes_at = build_cond(b"\xd2\x00", (0x10, 0x00))
        cpu = make(prog)
        cpu.run_steps(1)
        cpu.step()
        self.assertEqual(cpu.pc, yes_at)
        self.assertEqual(cpu.ram[0x20] & 0x01, 0x00, "JBC обязан снять бит")

    def test_djnz_register_counts_down_and_leaves_the_loop(self):
        # MOV R2,#03h ; DJNZ R2,$ (0xD8+n: DAh = R2) ; LJMP 0040h
        prog = (b"\x7a\x03\xda\xfe\x02\x00\x40" + bytes(0x39) + b"\x80\xfe")
        cpu = make(prog)
        cpu.run_steps(5)
        self.assertEqual(cpu.ram[0x02], 0x00, "R2 досчитал до нуля")
        self.assertEqual(cpu.pc, 0x0040, "после обнуления выходим из цикла")

    def test_djnz_direct_counts_down_and_leaves_the_loop(self):
        # MOV 30h,#02h ; DJNZ 30h,$ ; LJMP 0040h
        prog = (b"\x75\x30\x02\xd5\x30\xfd\x02\x00\x40"
                + bytes(0x37) + b"\x80\xfe")
        cpu = make(prog)
        cpu.run_steps(4)
        self.assertEqual(cpu.ram[0x30], 0x00)
        self.assertEqual(cpu.pc, 0x0040)


# =========================================================================== #
class TestBitOperations(unittest.TestCase):

    def test_clr_setb_cpl_on_the_carry(self):
        cpu = make(b"\xd3\xc3\xd3\xb3\x80\xfe")
        cpu.step()
        self.assertTrue(cpu.psw & CY, "SETB C")
        cpu.step()
        self.assertFalse(cpu.psw & CY, "CLR C")
        cpu.step()
        self.assertTrue(cpu.psw & CY, "SETB C ещё раз")
        cpu.step()
        self.assertFalse(cpu.psw & CY, "CPL C")

    def test_clr_setb_cpl_on_a_ram_bit(self):
        # SETB 20h.0 ; SETB 20h.7 ; CPL 20h.0 ; CLR 20h.7
        cpu = make(b"\xd2\x00\xd2\x07\xb2\x00\xc2\x07\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.ram[0x20], 0x00, "биты 0 и 7 возвращены в 0")
        cpu = make(b"\xd2\x00\xd2\x07\x80\xfe")
        cpu.run_steps(2)
        self.assertEqual(cpu.ram[0x20], 0x81, "бит0 -> 20h.0, бит7 -> 20h.7")

    def test_clr_setb_on_an_sfr_bit(self):
        # SETB ACC.7 -> ACC бит7 ; SETB P1.0 -> латч P1 бит0
        cpu = make(b"\xd2\xe7\x80\xfe")
        cpu.step()
        self.assertEqual(cpu.sfr[SFR_ACC] & 0x80, 0x80, "бит 0xE7 -> ACC.7")
        cpu = make(b"\xd2\x90\x80\xfe")
        cpu.step()
        self.assertEqual(cpu._port_latch[1] & 0x01, 0x01, "бит 0x90 -> P1.0")

    def test_move_between_bit_and_carry(self):
        # SETB 20h.0 ; CLR C ; MOV C,20h.0 -> CY=1
        cpu = make(b"\xd2\x00\xc3\xa2\x00\x80\xfe")
        cpu.run_steps(3)
        self.assertTrue(cpu.psw & CY, "MOV C,bit читает установленный бит")

        # CLR 20h.0 ; SETB C ; MOV C,20h.0 -> CY=0
        cpu = make(b"\xc2\x00\xd3\xa2\x00\x80\xfe")
        cpu.run_steps(3)
        self.assertFalse(cpu.psw & CY, "MOV C,bit читает снятый бит")

        # SETB C ; MOV 20h.0,C -> бит установлен
        cpu = make(b"\xd3\x92\x00\x80\xfe")
        cpu.run_steps(2)
        self.assertEqual(cpu.ram[0x20] & 0x01, 0x01, "MOV bit,C пишет бит")

        # CLR C ; MOV 20h.0,C -> бит снят
        cpu = make(b"\xc3\x92\x00\x80\xfe")
        cpu.run_steps(2)
        self.assertEqual(cpu.ram[0x20] & 0x01, 0x00, "MOV bit,C пишет 0")

    def test_anl_and_orl_with_carry(self):
        # ORL C,bit: CY = CY OR bit
        cpu = make(b"\xd3\x72\x00\x80\xfe")          # SETB C ; бит 20h.0=0
        cpu.run_steps(2)
        self.assertTrue(cpu.psw & CY, "CY=1 OR 0 -> 1")
        cpu = make(b"\xc3\x72\x00\x80\xfe")
        cpu.run_steps(2)
        self.assertFalse(cpu.psw & CY, "CY=0 OR 0 -> 0")
        cpu = make(b"\xc3\xd2\x00\x72\x00\x80\xfe")  # бит установлен
        cpu.run_steps(3)
        self.assertTrue(cpu.psw & CY, "CY=0 OR 1 -> 1")

        # ORL C,/bit: CY = CY OR NOT bit
        cpu = make(b"\xc3\xd2\x00\xa0\x00\x80\xfe")  # бит=1 -> /bit=0
        cpu.run_steps(3)
        self.assertFalse(cpu.psw & CY, "CY=0 OR 0 -> 0")
        cpu = make(b"\xd3\xa0\x00\x80\xfe")          # бит=0 -> /bit=1
        cpu.run_steps(2)
        self.assertTrue(cpu.psw & CY, "CY=1 OR 1 -> 1")

        # ANL C,bit: CY = CY AND bit
        cpu = make(b"\xd3\x82\x00\x80\xfe")          # бит=0
        cpu.run_steps(2)
        self.assertFalse(cpu.psw & CY, "CY=1 AND 0 -> 0")
        cpu = make(b"\xd3\xd2\x00\x82\x00\x80\xfe")  # бит=1
        cpu.run_steps(3)
        self.assertTrue(cpu.psw & CY, "CY=1 AND 1 -> 1")
        cpu = make(b"\xc3\xd2\x00\x82\x00\x80\xfe")  # CY=0 AND 1
        cpu.run_steps(3)
        self.assertFalse(cpu.psw & CY, "CY=0 AND 1 -> 0")

        # ANL C,/bit: CY = CY AND NOT bit
        cpu = make(b"\xd3\xd2\x00\xb0\x00\x80\xfe")  # бит=1 -> /bit=0
        cpu.run_steps(3)
        self.assertFalse(cpu.psw & CY, "CY=1 AND 0 -> 0")
        cpu = make(b"\xd3\xb0\x00\x80\xfe")          # бит=0 -> /bit=1
        cpu.run_steps(2)
        self.assertTrue(cpu.psw & CY, "CY=1 AND 1 -> 1")

    def test_bit_address_maps_to_the_right_byte(self):
        # бит 0x00 -> 20h.0, бит 0x3F -> 27h.7, бит 0x7F -> 2Fh.7
        cpu = make(b"\xd2\x00\xd2\x3f\xd2\x7f\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.ram[0x20] & 0x01, 0x01, "бит 0x00 -> 20h.0")
        self.assertEqual(cpu.ram[0x27] & 0x80, 0x80, "бит 0x3F -> 27h.7")
        self.assertEqual(cpu.ram[0x2F] & 0x80, 0x80, "бит 0x7F -> 2Fh.7")
        self.assertEqual(cpu.ram[0x21], 0x00, "остальные байты не тронуты")


# =========================================================================== #
class TestStackAndCalls(unittest.TestCase):

    def test_push_pop_round_trip(self):
        # MOV 30h,#5Ah ; PUSH 30h ; MOV 30h,#00h ; POP 30h
        cpu = make(b"\x75\x30\x5a\xc0\x30\x75\x30\x00\xd0\x30\x80\xfe")
        self.assertEqual(cpu.sp, 0x07, "стек пуст после сброса")
        cpu.run_steps(4)
        self.assertEqual(cpu.ram[0x30], 0x5A, "POP вернул байт из стека")
        self.assertEqual(cpu.sp, 0x07, "SP восстановился")
        self.assertEqual(cpu.ram[0x08], 0x5A, "PUSH кладёт байт в SP+1")

    def test_lcall_and_ret(self):
        prog = bytearray(0x50)
        prog[0x00:0x03] = bytes((0x12, 0x00, 0x06))    # LCALL 0006h
        prog[0x03:0x06] = bytes((0x02, 0x00, 0x40))    # LJMP 0040h
        prog[0x06] = 0x74                               # MOV A,#5Ah
        prog[0x07] = 0x5A
        prog[0x08] = 0x22                               # RET
        prog[0x40:0x42] = b"\x80\xfe"
        cpu = make(bytes(prog))
        cpu.step()
        self.assertEqual(cpu.pc, 0x0006)
        self.assertEqual(cpu.sp, 0x09)
        self.assertEqual(cpu.ram[0x08], 0x03, "младший байт адреса возврата первым")
        self.assertEqual(cpu.ram[0x09], 0x00, "затем старший")
        cpu.step()
        self.assertEqual(cpu.acc, 0x5A)
        cpu.step()                                     # RET
        self.assertEqual(cpu.pc, 0x0003, "RET вернулся на адрес после LCALL")
        self.assertEqual(cpu.sp, 0x07)

    def test_acall_and_ret(self):
        prog = bytearray(0x50)
        prog[0x00] = 0x11                              # ACALL
        prog[0x01] = 0x10                              # -> 0010h
        prog[0x02:0x05] = bytes((0x02, 0x00, 0x40))    # LJMP 0040h
        prog[0x10] = 0x22                              # RET
        prog[0x40:0x42] = b"\x80\xfe"
        cpu = make(bytes(prog))
        cpu.step()
        self.assertEqual(cpu.pc, 0x0010, "ACALL 10h из страницы 0")
        self.assertEqual(cpu.ram[0x08], 0x02, "адрес возврата 0002h")
        self.assertEqual(cpu.ram[0x09], 0x00)
        cpu.step()                                     # RET
        self.assertEqual(cpu.pc, 0x0002)
        self.assertEqual(cpu.sp, 0x07)

    def test_acall_page_bits(self):
        # опкод 31h -> биты 10..8 = 001 -> страница 0100h
        prog = bytearray(0x200)
        prog[0x00] = 0x31
        prog[0x01] = 0x20                              # -> 0120h
        prog[0x02:0x05] = bytes((0x02, 0x00, 0x40))
        prog[0x120] = 0x22                             # RET
        prog[0x40:0x42] = b"\x80\xfe"
        cpu = make(bytes(prog))
        cpu.step()
        self.assertEqual(cpu.pc, 0x0120)

    def test_reti_returns_and_clears_the_interrupt_level(self):
        prog = bytearray(0x50)
        prog[0x00:0x03] = bytes((0x12, 0x00, 0x06))    # LCALL 0006h
        prog[0x03:0x06] = bytes((0x02, 0x00, 0x40))    # LJMP 0040h
        prog[0x06] = 0x32                              # RETI
        prog[0x40:0x42] = b"\x80\xfe"
        cpu = make(bytes(prog))
        cpu.step()
        cpu.step()                                     # RETI
        self.assertEqual(cpu.pc, 0x0003)
        self.assertEqual(cpu.sp, 0x07, "стек чист")
        self.assertEqual(cpu.in_isr, 0)
        self.assertEqual(cpu.irq_level, 0, "RETI снимает уровень прерывания")

    def test_interrupt_dispatch_and_reti(self):
        rom = ROM("irq")
        rom.load_block(0x0000, b"\x80\xfe")            # SJMP $
        rom.load_block(0x0003, b"\x02\x00\x10")        # LJMP 0010h (вектор EXT0)
        rom.load_block(0x0010, b"\x32")                # RETI
        cpu = CPU8051(rom, NullBus())
        cpu.sfr[SFR_IE] = 0x81                         # EA | EX0
        cpu.sfr[SFR_TCON] = 0x02                       # IE0
        cpu.step()                                     # вход в обработчик + LJMP
        self.assertEqual(cpu.pc, 0x0010)
        self.assertEqual(cpu.sp, 0x09, "адрес возврата в стеке")
        self.assertEqual(cpu.ram[0x08], 0x00, "возвращаемся на 0000h")
        self.assertEqual(cpu.ram[0x09], 0x00)
        self.assertFalse(cpu.sfr[SFR_TCON] & 0x02, "IE0 снят при входе")
        cpu.step()                                     # RETI
        self.assertEqual(cpu.pc, 0x0000)
        self.assertEqual(cpu.sp, 0x07, "стек после RETI пуст")
        self.assertEqual(cpu.in_isr, 0)
        self.assertEqual(cpu.irq_level, 0)


# =========================================================================== #
class TestMisc(unittest.TestCase):

    def test_nop_advances_by_one_byte(self):
        cpu = make(b"\x00\x00\x80\xfe")
        cycles = cpu.step()
        self.assertEqual(cpu.pc, 0x0001)
        self.assertEqual(cycles, 1, "NOP - один машинный цикл")

    def test_reserved_opcode_a5_reports_an_error(self):
        cpu = make(b"\xa5\x80\xfe")
        cpu.step()
        self.assertIsNotNone(cpu.error, "0xA5 зарезервирован и должен быть отмечен")
        self.assertIn("a5", cpu.error.lower())


# =========================================================================== #
class TestCoreRegressions(unittest.TestCase):
    """Регрессии дефектов, найденных этим конформанс-прогоном и исправленных.

    Все они когда-то падали.  Skip-guard'ы сняты: ядро обязано вести себя
    правильно всегда, а не «пока не починят».
    """

    def test_mul_ab_clears_a_stale_overflow(self):
        # SETB OV ; MOV A,#3 ; MOV B,#5 ; MUL AB -> 15, OV обязан сброситься
        cpu = make(b"\xd2\xd2\x74\x03\x75\xf0\x05\xa4\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.acc, 15)
        self.assertEqual(cpu.sfr[SFR_B], 0)
        self.assertFalse(cpu.psw & OV,
                         "MUL AB: OV=0, если результат помещается в 8 бит")
        self.assertFalse(cpu.psw & CY, "MUL AB всегда сбрасывает CY")

    def test_div_ab_clears_a_stale_overflow(self):
        # SETB OV ; MOV A,#0Ah ; MOV B,#03h ; DIV AB -> A=3, B=1, OV=0
        cpu = make(b"\xd2\xd2\x74\x0a\x75\xf0\x03\x84\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.acc, 3)
        self.assertEqual(cpu.sfr[SFR_B], 1)
        self.assertFalse(cpu.psw & OV, "DIV AB: OV=0 при ненулевом делителе")
        self.assertFalse(cpu.psw & CY, "DIV AB всегда сбрасывает CY")

    def test_parity_flag_follows_the_accumulator(self):
        """PSW.P - комбинаторная функция ACC: она верна после ЛЮБОЙ записи.

        ``CLR A``/``MOV A,#imm`` не вызывают ``set_p()`` явно - паритет
        обновляет сеттер ``acc``, поэтому вся семья (CLR/CPL A, MOV A,#imm,
        ротации, ANL/ORL/XRL A,..., XCH/XCHD, MOVC) верна «по построению».
        """
        # MOV 30h,#01h ; MOV A,30h (P=1) ; CLR A -> P обязан стать 0
        cpu = make(b"\x75\x30\x01\xe5\x30\xe4\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x00, "CLR A обнуляет ACC")
        self.assertFalse(cpu.psw & PARITY, "чётный ACC -> P=0")

        # и обратный случай: MOV A,#07h (три единицы) -> P=1
        cpu = make(b"\x74\x07\x80\xfe")
        cpu.run_steps(1)
        self.assertEqual(cpu.acc, 0x07)
        self.assertTrue(cpu.psw & PARITY, "нечётное число единиц -> P=1")

    def test_xchd_swaps_the_low_nibble_into_the_accumulator(self):
        # A=0A3h, @R0=05Ch -> A=0ACh, @R0=053h
        cpu = make(b"\x78\x40\x76\x5c\x74\xa3\xd6\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.ram[0x40], 0x53,
                         "XCHD меняет младшую тетраду в памяти")
        self.assertEqual(cpu.acc, 0xAC,
                         "и кладёт в ACC чужую младшую тетраду")

    def test_ajmp_takes_its_page_from_pc_plus_two(self):
        """AJMP на адресе 0x07FE: PC после инструкции уже 0x0800.

        Целевая страница берётся из ``(PC + 2) & 0xF800`` - как делают
        ``tools/disasm.py``, ``tools/asm51.py`` и (после исправления) ядро.
        """
        prog = bytearray(0x810)
        prog[0x07FE] = 0x01                           # AJMP, биты 10..8 = 000
        prog[0x07FF] = 0x00                           # -> 0800h
        prog[0x0800:0x0802] = b"\x80\xfe"
        cpu = make(bytes(prog))
        cpu.pc = 0x07FE
        cpu.step()
        self.assertEqual(cpu.pc, 0x0800,
                         "AJMP обязан брать страницу из PC+2, а не PC+1")

    def test_acall_takes_its_page_from_pc_plus_two(self):
        prog = bytearray(0x810)
        prog[0x07FE] = 0x11                           # ACALL, биты 10..8 = 000
        prog[0x07FF] = 0x00                           # -> 0800h
        prog[0x0800] = 0x22                           # RET
        cpu = make(bytes(prog))
        cpu.pc = 0x07FE
        cpu.step()
        self.assertEqual(cpu.pc, 0x0800,
                         "ACALL обязан брать страницу из PC+2, а не PC+1")
        self.assertEqual(cpu.sp, 0x09)
        self.assertEqual(cpu.ram[0x08], 0x00, "адрес возврата 0800h: младший байт")
        self.assertEqual(cpu.ram[0x09], 0x08, "адрес возврата 0800h: старший байт")

    def test_machine_cycle_counts_match_keil(self):
        """Число машинных циклов - по Keil 8051 Instruction Set Manual.

        ``is51_orl`` / ``is51_xch`` / ``is51_mov``: ``ORL/ANL/XRL direct,A``,
        ``XCH A,direct`` и ``MOV C,bit`` (0xA2) - **один** цикл.
        ``MOV bit,C`` (0x92) - две инструкции со сходной ролью, но это
        отдельная строка таблицы, и там **два** цикла.
        """
        cases = {
            0x42: (1, b"\x75\x30\xf0\x42\x30\x80\xfe", 2),          # ORL 30h,A
            0x52: (1, b"\x75\x30\xf0\x74\x0f\x52\x30\x80\xfe", 3),  # ANL 30h,A
            0x62: (1, b"\x75\x30\xf0\x74\x0f\x62\x30\x80\xfe", 3),  # XRL 30h,A
            0xC5: (1, b"\x75\x30\x5a\xc5\x30\x80\xfe", 2),          # XCH A,30h
            0xA2: (1, b"\xc3\xa2\x00\x80\xfe", 2),                  # MOV C,20h.0
            0x92: (2, b"\xc3\x92\x00\x80\xfe", 2),                  # MOV 20h.0,C
        }
        for op, (want, program, index) in cases.items():
            with self.subTest(op=f"0x{op:02X}"):
                cpu = make(program)
                cpu.run_steps(index - 1)           # довести до нужной инструкции
                self.assertEqual(cpu.step(), want,
                                 f"машинных циклов опкода 0x{op:02X}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
