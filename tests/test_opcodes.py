# -*- coding: utf-8 -*-
"""Round-trip тесты инструментов: ``tools/asm51.py`` <-> ``tools/disasm.py``.

Главная проверка: **ассемблирование -> дизассемблирование -> ассемблирование
обязано дать байт в байт тот же образ.**  Раньше такого теста не было -
встроенный ``asm51.selftest()`` сравнивает не байты, а *канонические формы*
текста (``canon``), поэтому пара дефектов проходила мимо него.

Что проверяется
---------------
1. Дизассембер декодирует все 256 опкодов и отчитывается о корректной длине.
2. Каждый из 256 опкодов (с нулевыми операндами) проходит
   ``дизассембляция -> ассембляция -> те же байты``.
3. Полный образ ``ROUNDTRIP_SOURCE`` переживает линейный проход
   ``ассембляция -> дизассемблирование -> ассембляция`` без единого
   расхождения по байтам.
4. Битовые операнды (``20h.n``, ``ACC.n``, ``P1.n``, ``CY``) отдельно.
5. Каждая инструкция из встроенного ``SELFTEST_SOURCE`` переживает
   round-trip при *реальных* (не нулевых) операндах.

Пробелы, найденные этим файлом и **исправленные** в ``tools/``:

* ``disasm`` печатал ``MOV DPTR,1234h`` без ``#`` -> теперь ``#1234h``;
* ``asm51`` не умел ``ANL/ORL C,bit`` и ``ANL/ORL C,/bit``
  (опкоды ``0x72``, ``0x82``, ``0xA0``, ``0xB0``) -> добавлены записи в ``ENC``;
* шестнадцатеричный литерал, начинающийся с ``A..F`` (``#FFh``, ``A9h``,
  ``C0h.0``), токенизировался как *имя символа* -> резолвер теперь понимает
  такие неизвестные имена как числа (метки, SFR и битовые имена по-прежнему
  в приоритете);
* ``disasm`` и ``asm51`` не знали опкод ``0x73`` ``JMP @A+DPTR``.

Поэтому ни один тест ниже больше не пропускается «из-за известного пробела»:
``KNOWN_ROUNDTRIP_GAPS`` пуст, и любой несобравшийся обратно опкод - падение.

Запуск::

    python -m unittest tests.test_opcodes -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.asm51 import AsmError, SELFTEST_SOURCE, assemble  # noqa: E402
from tools.disasm import disassemble, disassemble_one  # noqa: E402


class _MemView:
    """Байтовый вид образа для дизайнера: незанятые адреса читаются как 0xFF."""

    __slots__ = ("_mem",)

    def __init__(self, base: int, data: bytes) -> None:
        self._mem = {addr: value for addr, value in enumerate(data, base)}

    def __getitem__(self, addr: int) -> int:
        return self._mem.get(addr & 0xFFFF, 0xFF)


#: Опкоды, которые ``asm51`` не может собрать обратно.  Пусто: все пробелы
#: из docstring устранены, поэтому несобирающийся опкод - это падение.
KNOWN_ROUNDTRIP_GAPS = frozenset()


ROUNDTRIP_SOURCE = """
; ---------------------------------------------------------------------------
; Образ для round-trip: ассембляция -> дизассемблирование -> ассембляция.
; Сознательно содержит формы, которые когда-то НЕ переживали обратную сборку:
;   * MOV DPTR,#...   - disasm печатал без '#';
;   * ANL/ORL C,bit   - в ENC не было таких записей (0x72/0x82/0xA0/0xB0);
;   * FFh / 0A9h      - литерал, начинающийся с A..F, читался как имя символа;
;   * JMP @A+DPTR     - опкода 0x73 не было ни в disasm, ни в asm51.
; ---------------------------------------------------------------------------
        ORG   0x0000
START:  NOP
        MOV   A,#12h
        MOV   A,#0FFh
        MOV   A,30h
        MOV   A,@R0
        MOV   A,@R1
        MOV   A,R0
        MOV   A,R7
        MOV   R0,A
        MOV   R3,#7
        MOV   R2,30h
        MOV   30h,A
        MOV   30h,#5
        MOV   30h,R1
        MOV   31h,32h
        MOV   33h,@R0
        MOV   34h,@R1
        MOV   @R0,A
        MOV   @R1,A
        MOV   @R0,#9
        MOV   @R1,30h
        MOV   P1,A
        MOV   A,PSW
        MOV   A,B
        MOV   B,#3
        MOV   DPTR,#1234h
        MOV   0A9h,A
        ANL   C,20h.6
        ANL   C,/20h.7
        ORL   C,20h.6
        ORL   C,/20h.7
        JMP   @A+DPTR
        MOVX  A,@DPTR
        MOVX  A,@R0
        MOVX  A,@R1
        MOVX  @DPTR,A
        MOVX  @R0,A
        MOVX  @R1,A
        MOVC  A,@A+DPTR
        MOVC  A,@A+PC
        ADD   A,#1
        ADD   A,30h
        ADD   A,@R0
        ADD   A,R2
        ADDC  A,#1
        ADDC  A,30h
        ADDC  A,@R1
        ADDC  A,R3
        SUBB  A,#1
        SUBB  A,30h
        SUBB  A,@R0
        SUBB  A,R4
        INC   A
        INC   30h
        INC   @R0
        INC   R5
        DEC   A
        DEC   30h
        DEC   @R1
        DEC   R6
        ANL   A,#0Fh
        ANL   A,30h
        ANL   A,@R0
        ANL   A,R1
        ANL   30h,A
        ANL   30h,#0Fh
        ORL   A,#0Fh
        ORL   A,30h
        ORL   30h,A
        ORL   30h,#0Fh
        XRL   A,#0Fh
        XRL   A,30h
        XRL   30h,A
        XRL   30h,#0Fh
        CLR   A
        CLR   C
        CLR   20h.0
        CPL   A
        CPL   C
        CPL   20h.1
        SETB  C
        SETB  20h.2
        SETB  ACC.0
        MOV   C,ACC.0
        MOV   20h.3,C
        MOV   C,20h.4
        MOV   20h.5,C
        RL    A
        RR    A
        RLC   A
        RRC   A
        SWAP  A
        XCH   A,30h
        XCH   A,@R0
        XCH   A,R7
        XCHD  A,@R1
        MUL   AB
        DIV   AB
        DA    A
        PUSH  30h
        POP   30h
        PUSH  PSW
        POP   PSW
LOOP:   SJMP  LOOP
        JC    LOOP
        JNC   LOOP
        JZ    LOOP
        JNZ   LOOP
        JB    20h.0,LOOP
        JNB   20h.1,LOOP
        JBC   20h.2,LOOP
        CJNE  A,#5,LOOP
        CJNE  A,30h,LOOP
        CJNE  @R0,#5,LOOP
        CJNE  R0,#5,LOOP
        DJNZ  R2,LOOP
        DJNZ  30h,LOOP
        AJMP  PAGE2
        ACALL PAGE2
        LJMP  PAGE2
        LCALL PAGE2
        RET
        RETI
PAGE2:  MOV   A,#45h
        MOV   B,#3
        NOP
        END
"""

BIT_SOURCE = """
; Битовые операнды: адресация байта и разряда обязана совпасть на обоих
; концах round-trip.
        ORG   0x0000
        SETB  20h.0
        CLR   20h.7
        CPL   20h.3
        SETB  ACC.0
        CLR   ACC.7
        SETB  P1.0
        SETB  CY
        MOV   C,20h.5
        MOV   20h.6,C
        MOV   C,ACC.3
        MOV   ACC.2,C
L1:     JB    20h.4,L1
        END
"""


# =========================================================================== #
class TestDisassemblerCoverage(unittest.TestCase):
    """Дизассембер обязан знать всю таблицу опкодов."""

    def test_decodes_all_256_opcodes(self):
        for op in range(256):
            text, length = disassemble_one(bytes((op, 0x00, 0x00)), 0)
            self.assertTrue(text.strip(), f"опкод 0x{op:02X} не декодируется")
            self.assertIn(length, (1, 2, 3),
                          f"опкод 0x{op:02X}: подозрительная длина {length} ({text!r})")

    def test_disassemble_advances_by_the_reported_lengths(self):
        first = assemble(ROUNDTRIP_SOURCE)
        rows = disassemble(first.image, 0, 40, base=0)
        self.assertEqual(len(rows), 40)
        self.assertEqual(rows[0][0], 0)
        for (addr, _text, length), (next_addr, _t2, _l2) in zip(rows, rows[1:]):
            self.assertEqual(next_addr, (addr + length) & 0xFFFF,
                             f"после 0x{addr:04X} (+{length}) ожидается "
                             f"0x{(addr + length) & 0xFFFF:04X}")


# =========================================================================== #
class TestOpcodeRoundTrip(unittest.TestCase):
    """``дизассембляция -> ассембляция`` для каждого опкода и для образа."""

    def test_every_opcode_roundtrips_byte_identically(self):
        """Все 256 опкодов с нулевыми операндами.

        Нулевые операнды выбраны сознательно: при них любой дефект
        *позиции* операнда (например, перепутанные байты у
        ``MOV direct,direct``) не может маскироваться значением.
        """
        unexpected = []
        for op in range(256):
            raw = bytes((op, 0x00, 0x00))
            text, length = disassemble_one(raw, 0)
            self.assertIn(length, (1, 2, 3), f"0x{op:02X}: {text!r}")
            want = raw[:length]
            try:
                again = assemble("        ORG 0\n        %s\n        END\n" % text)
            except AsmError as exc:
                if op not in KNOWN_ROUNDTRIP_GAPS:
                    unexpected.append(f"0x{op:02X} {text!r}: {exc}")
                continue
            if again.image != want:
                unexpected.append(
                    f"0x{op:02X} {text!r}: {again.image.hex()} != {want.hex()}")
        self.assertEqual(unexpected, [],
                         "round-trip сломан на следующих опкодах")

    @staticmethod
    def _resweep(first) -> tuple:
        """Линейный проход дизассемблера по образу -> новый исходник.

        Возвращает ``(адрес_за_концом_образа, текст_исходника)``.
        """
        view = _MemView(first.base, first.image)
        lines = ["        ORG 0x%04X" % first.base]
        addr = first.base
        while addr < first.end:
            text, length = disassemble_one(view, addr)
            lines.append("        " + text)
            addr += length
        lines.append("        END")
        return addr, "\n".join(lines)

    @staticmethod
    def _first_diff(first, second):
        """``(адрес, ожидалось, получено)`` для первого расхождения либо None."""
        if len(second.image) != len(first.image):
            return (first.base, f"длина {len(first.image)} байт",
                    f"длина {len(second.image)} байт")
        for offset, (left, right) in enumerate(zip(first.image, second.image)):
            if left != right:
                return (first.base + offset, f"{left:02X}", f"{right:02X}")
        return None

    def test_full_image_roundtrip_is_byte_identical(self):
        """Линейный проход по всему образу: ни одного расхождения по байтам."""
        first = assemble(ROUNDTRIP_SOURCE)
        self.assertEqual(len(first.blocks), 1,
                         "образ должен быть непрерывным (без ORG-просветов)")
        end, source = self._resweep(first)
        self.assertEqual(end, first.end,
                         "линейный проход дизассемблера не совпал с концом образа")
        second = assemble(source)
        self.assertEqual(second.base, first.base)
        diff = self._first_diff(first, second)
        if diff is not None:
            addr, want, got = diff
            self.fail(f"round-trip разошёлся по адресу 0x{addr:04X}: "
                      f"ожидалось {want}, получено {got}")

    def test_bit_operands_roundtrip(self):
        """Битовые операнды: ``20h.n``, ``ACC.n``, ``P1.n``, ``CY``."""
        first = assemble(BIT_SOURCE)
        self.assertEqual(len(first.blocks), 1)
        end, source = self._resweep(first)
        self.assertEqual(end, first.end, "проход дизассемблера оборвался")
        second = assemble(source)
        diff = self._first_diff(first, second)
        if diff is not None:
            addr, want, got = diff
            self.fail(f"битовые операнды не пережили round-trip по адресу "
                      f"0x{addr:04X}: ожидалось {want}, получено {got}")

    def test_intel_hex_survives_a_round_trip_through_rom(self):
        from m8051 import ROM

        first = assemble(ROUNDTRIP_SOURCE)
        rom = ROM("roundtrip")
        rom.load_hex_text(first.intel_hex())
        for addr in range(first.base, first.end):
            self.assertEqual(rom.byte(addr), first.image[addr - first.base],
                             f"байт 0x{addr:04X} не пережил Intel HEX")


# =========================================================================== #
class TestSelftestSourceRoundTrip(unittest.TestCase):
    """Каждая инструкция встроенного ``SELFTEST_SOURCE`` собирается обратно.

    В отличие от ``asm51.selftest()`` здесь сравниваются именно **байты**,
    а не канонические формы текста.
    """

    def test_every_selftest_instruction_roundtrips(self):
        first = assemble(SELFTEST_SOURCE)
        view = _MemView(first.base, first.image)
        checked = 0
        for entry in first.listing:
            if entry.kind != "ins":
                continue
            text, length = disassemble_one(view, entry.addr)
            self.assertEqual(
                length, len(entry.data),
                f"0x{entry.addr:04X} {entry.source!r}: дизассембер дал {length} "
                f"байт(а), собрано {len(entry.data)} ({text!r})")
            try:
                again = assemble("        ORG 0x%04X\n        %s\n        END\n"
                                 % (entry.addr, text))
            except AsmError as exc:
                self.fail(f"0x{entry.addr:04X}: {entry.source!r} -> {text!r} "
                          f"не собирается обратно: {exc}")
            self.assertEqual(
                again.image, entry.data,
                f"0x{entry.addr:04X}: {entry.source!r} -> {text!r} даёт "
                f"{again.image.hex()}, ожидалось {entry.data.hex()}")
            checked += 1
        self.assertGreater(checked, 100,
                           f"проверено всего {checked} инструкций - слишком мало")


# =========================================================================== #
class TestFormerGaps(unittest.TestCase):
    """Пробелы, найденные этим файлом и исправленные в ``tools/``.

    Раньше каждый из этих тестов пропускался «пока не починят»; теперь они
    обязаны падать, если пробел вернётся.
    """

    def _assert_roundtrip(self, source: str, expected: bytes, addr: int = 0):
        """Собрать ``source``, разобрать и собрать обратно - те же байты."""
        first = assemble("        ORG 0x%04X\n        %s\n        END\n"
                         % (addr, source))
        self.assertEqual(first.image, expected,
                         f"исходная сборка {source!r} дала не те байты")
        text, length = disassemble_one(_MemView(first.base, first.image), addr)
        self.assertEqual(length, len(expected),
                         f"длина {text!r} не совпала с {len(expected)}")
        try:
            second = assemble("        ORG 0x%04X\n        %s\n        END\n"
                              % (addr, text))
        except AsmError as exc:
            self.fail(f"{source!r} -> {text!r} не собирается обратно: {exc}")
        self.assertEqual(second.image, expected,
                         f"{source!r} -> {text!r} не пережил round-trip")
        return text

    def test_immediate_at_or_above_0xa0_roundtrips(self):
        """``MOV A,#0FFh`` -> ``MOV A,#FFh``: литерал обязан остаться числом."""
        self._assert_roundtrip("MOV A,#0FFh", bytes((0x74, 0xFF)))

    def test_direct_address_above_0xa0_roundtrips(self):
        """``MOV 0A9h,A`` -> ``MOV A9h,A``: прямой адрес без имени SFR."""
        self._assert_roundtrip("MOV 0A9h,A", bytes((0xF5, 0xA9)))

    def test_mov_dptr_immediate_roundtrips(self):
        """``disasm`` обязан печатать ``MOV DPTR,#1234h`` с ``#``."""
        text = self._assert_roundtrip("MOV DPTR,#1234h",
                                      bytes((0x90, 0x12, 0x34)))
        self.assertIn("#", text, f"немедленный операнд DPTR без '#': {text!r}")

    def test_anl_orl_c_bit_assembles(self):
        """В ``ENC`` обязаны быть все четыре битовых формы ANL/ORL."""
        for source, expected in (
            ("ANL C,20h.0", bytes((0x82, 0x00))),
            ("ANL C,/20h.0", bytes((0xB0, 0x00))),
            ("ORL C,20h.0", bytes((0x72, 0x00))),
            ("ORL C,/20h.0", bytes((0xA0, 0x00))),
        ):
            with self.subTest(source=source):
                self._assert_roundtrip(source, expected)

    def test_disassembler_decodes_jmp_a_dptr(self):
        """Опкод ``0x73`` больше не выпадает в ``DB``."""
        text, length = disassemble_one(bytes((0x73, 0x10, 0x00)), 0)
        self.assertEqual(" ".join(text.split()), "JMP @A+DPTR", text)
        self.assertEqual(length, 1, text)
        self._assert_roundtrip("JMP @A+DPTR", bytes((0x73,)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
