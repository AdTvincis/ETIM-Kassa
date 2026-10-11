"""Тесты ядра MCS-51 (m8051/cpu.py).

Проверяются те места, где ошибка не падает, а тихо портит поток управления:
порядок байт в стеке, условия переходов, флаги. Оба найденных бага
(``push_pc`` и ``CJNE``) были именно такими, поэтому здесь на каждый из них
есть регрессионный тест.

Запуск::

    python -m unittest tests.test_cpu -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from m8051 import CPU8051, NullBus, ROM  # noqa: E402

SFR_ACC = 0xE0
SFR_PSW = 0xD0
SFR_SP = 0x81
SFR_B = 0xF0
SFR_P1 = 0x90


def make(program: bytes, base: int = 0x0000) -> tuple:
    rom = ROM("unit")
    rom.load_block(base, program)
    cpu = CPU8051(rom, NullBus())
    return cpu, rom


def run_until(cpu: CPU8051, stop_pcs, limit: int = 200) -> int:
    """Выполнять, пока PC не окажется в ``stop_pcs``; вернуть PC."""
    for _ in range(limit):
        if cpu.pc in stop_pcs:
            return cpu.pc
        cpu.step()
    return cpu.pc


class TestStackOrder(unittest.TestCase):
    """LCALL/ACALL кладут в стек младший байт адреса возврата первым."""

    def test_lcall_pushes_low_byte_first(self):
        # 0000: LCALL 0011h ; 0011: RET
        cpu, _ = make(bytes([0x12, 0x00, 0x11, 0x80, 0xFE]) + bytes(0x0C)
                      + bytes([0x22]))
        cpu.step()                     # LCALL
        self.assertEqual(cpu.pc, 0x0011)
        self.assertEqual(cpu.sp, 0x09)
        self.assertEqual(cpu.ram[0x08], 0x03, "в стеке младший байт адреса возврата")
        self.assertEqual(cpu.ram[0x09], 0x00, "затем старший байт")
        cpu.step()                     # RET
        self.assertEqual(cpu.pc, 0x0003, "RET обязан вернуться на 0x0003")
        self.assertEqual(cpu.sp, 0x07)

    def test_return_address_survives_a_page_boundary(self):
        """Адрес возврата хранит оба байта: вызов из 0x0000, возврат на 0x0003.

        Проверяем именно порядок байт: если поменять их местами, RET уйдёт на
        0x0300 — в другую страницу.
        """
        program = bytearray(0x120)
        program[0x00:0x03] = bytes([0x12, 0x01, 0x00])     # LCALL 0100h
        program[0x03] = 0x80                               # SJMP $
        program[0x04] = 0xFE
        program[0x0100] = 0x22                             # RET
        cpu, _ = make(bytes(program))
        cpu.step()
        self.assertEqual(cpu.ram[0x08], 0x03, "младший байт первым")
        self.assertEqual(cpu.ram[0x09], 0x00, "старший байт вторым")
        cpu.step()
        self.assertEqual(cpu.pc, 0x0003, "возврат в младшую страницу, не в 0x0300")

    def test_return_address_keeps_high_byte(self):
        """Адрес возврата из старшей страницы: оба байта обязаны сохраниться."""
        program = bytearray(0x1000)
        program[0x00:0x03] = bytes([0x12, 0x09, 0x00])      # LCALL 0900h
        program[0x03] = 0x80                                # SJMP $
        program[0x04] = 0xFE
        program[0x0100] = 0x22                              # RET
        cpu, _ = make(bytes(program), base=0x0800)
        cpu.pc = 0x0800
        cpu.step()
        self.assertEqual(cpu.pc, 0x0900, "вызов ушёл на 0x0900")
        self.assertEqual(cpu.ram[0x08], 0x03, "младший байт адреса возврата")
        self.assertEqual(cpu.ram[0x09], 0x08, "старший байт адреса возврата")
        cpu.step()
        self.assertEqual(cpu.pc, 0x0803, "возврат в ту же старшую страницу")

    def test_interrupt_and_reti_round_trip(self):
        rom = ROM("irq")
        rom.load_block(0, bytes([0x80, 0xFE]))     # SJMP $
        rom.load_block(0x03, bytes([0x32]))        # RETI на векторе EXT0
        cpu = CPU8051(rom, NullBus())
        cpu.sfr[0xA8] = 0x81                        # EA | EX0
        cpu.sfr[0x88] = 0x02                        # IE0
        cpu.step()                                  # прерывание + сразу RETI
        # Вектор 0x0003 содержит RETI, поэтому один шаг заканчивается возвратом
        # на адрес 0x0000; проверяем, что стек чист и флаг прерывания снят.
        self.assertEqual(cpu.pc, 0x0000)
        self.assertEqual(cpu.sp, 0x07, "стек после RETI пуст")
        self.assertFalse(cpu.sfr[0x88] & 0x02, "IE0 снят при обслуживании")


class TestCJNE(unittest.TestCase):
    """CJNE переходит при НЕРАВЕНСТВЕ; CY ставится отдельно (left < right)."""

    def _branch_program(self, cjne: bytes, setup: bytes = b""):
        """Собрать: <setup> ; CJNE <cjne>,rel ; LJMP NO ; LJMP YES.

        ``cjne`` — опкод и операнды БЕЗ байта смещения.  Смещение считается от
        конца инструкции CJNE (3 байта), поэтому чтобы перепрыгнуть следующий
        трёхбайтовый LJMP, смещение равно 3.
        """
        program = bytearray(setup)
        cjne_at = len(program)
        program += bytes(cjne)                       # опкод + операнд(ы)
        program += b"\x03"                           # смещение: через LJMP NO
        no_at = len(program)
        program += bytes([0x02, 0x00, 0x40])         # сюда, если НЕ перешли
        yes_at = len(program)
        program += bytes([0x02, 0x00, 0x80])         # сюда, если перешли
        program += bytes(0x80 - len(program))
        cpu, _ = make(bytes(program))
        return cpu, no_at, yes_at

    def _run_cjne(self, cjne: bytes, setup: bytes = b"", setup_steps: int = 1):
        cpu, no_at, yes_at = self._branch_program(cjne, setup)
        cpu.run_steps(setup_steps)
        cpu.step()                                   # сама CJNE
        return cpu, no_at, yes_at

    def test_a_immediate_not_equal_branches(self):
        cpu, no_at, yes_at = self._run_cjne(bytes([0xB4, 0x02]), b"\x74\x05")
        self.assertEqual(cpu.pc, yes_at, "5 != 2 -> переход обязан быть")

    def test_a_immediate_equal_falls_through(self):
        cpu, no_at, yes_at = self._run_cjne(bytes([0xB4, 0x05]), b"\x74\x05")
        self.assertEqual(cpu.pc, no_at, "5 == 5 -> перехода быть не должно")

    def test_carry_is_set_when_below(self):
        cpu, no_at, yes_at = self._run_cjne(bytes([0xB4, 0x09]), b"\x74\x05")
        self.assertTrue(cpu.psw & 0x80, "5 < 9 -> CY=1")
        self.assertEqual(cpu.pc, yes_at)

    def test_carry_is_clear_when_above(self):
        cpu, no_at, yes_at = self._run_cjne(bytes([0xB4, 0x01]), b"\x74\x05")
        self.assertFalse(cpu.psw & 0x80, "5 > 1 -> CY=0")
        self.assertEqual(cpu.pc, yes_at)

    def test_direct_form(self):
        cpu, no_at, yes_at = self._branch_program(bytes([0xB5, 0x30]), b"\x74\x05")
        cpu.ram[0x30] = 9
        cpu.run_steps(1)
        cpu.step()
        self.assertEqual(cpu.pc, yes_at)

    def test_register_form(self):
        cpu, no_at, yes_at = self._run_cjne(bytes([0xB8, 0x02]), b"\x78\x05")
        self.assertEqual(cpu.pc, yes_at)

    def test_indirect_form(self):
        # MOV @R0,#7 ; CJNE @R0,#3 -> не равны
        cpu, no_at, yes_at = self._run_cjne(bytes([0xB6, 0x03]), b"\x76\x07")
        self.assertEqual(cpu.pc, yes_at)


class TestArithmetic(unittest.TestCase):

    def _acc_after(self, program: bytes) -> int:
        cpu, _ = make(bytes(program) + b"\x80\xfe")
        cpu.run_steps(50)
        return cpu.acc

    def test_add_sets_carry_and_overflow(self):
        # MOV A,#0FFh ; ADD A,#01h
        cpu, _ = make(b"\x74\xff\x24\x01\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x00)
        self.assertTrue(cpu.psw & 0x80, "CY=1")
        self.assertFalse(cpu.psw & 0x04, "OV=0 при 0xFF+1")

    def test_add_overflow_flag(self):
        # MOV A,#7Fh ; ADD A,#01h  -> 0x80, OV=1
        cpu, _ = make(b"\x74\x7f\x24\x01\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x80)
        self.assertTrue(cpu.psw & 0x04, "OV=1")
        self.assertFalse(cpu.psw & 0x80, "CY=0")

    def test_subb_borrow(self):
        # MOV A,#10h ; SUBB A,#20h -> 0xF0 с заёмом (CY=1)
        cpu, _ = make(b"\x74\x10\x94\x20\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0xF0, "10h - 20h = F0h по модулю 256")
        self.assertTrue(cpu.psw & 0x80, "заём -> CY=1")

    def test_subb_no_borrow(self):
        # MOV A,#20h ; SUBB A,#10h -> 0x10, заёма нет (CY=0)
        cpu, _ = make(b"\x74\x20\x94\x10\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x10)
        self.assertFalse(cpu.psw & 0x80, "без заёма CY обязан сброситься")

    def test_subb_clears_borrow_after_borrow(self):
        # Сначала заём, потом операция без заёма: CY обязан сброситься.
        cpu, _ = make(b"\x74\x10\x94\x20\x74\x20\x94\x10\x80\xfe")
        cpu.run_steps(6)
        self.assertFalse(cpu.psw & 0x80, "второй SUBB прошёл без заёма")

    def test_mul_ab(self):
        # MOV A,#12h ; MOV B,#10h ; MUL AB -> 0x120, A=0x20, B=0x01
        cpu, _ = make(b"\x74\x12\x75\xf0\x10\xa4\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.acc, 0x20)
        self.assertEqual(cpu.sfr[SFR_B], 0x01)
        self.assertTrue(cpu.psw & 0x04, "результат > 0xFF -> OV=1")

    def test_div_ab(self):
        # MOV A,#0Ah ; MOV B,#03h ; DIV AB -> A=3, B=1
        cpu, _ = make(b"\x74\x0a\x75\xf0\x03\x84\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.acc, 3)
        self.assertEqual(cpu.sfr[SFR_B], 1)

    def test_div_by_zero(self):
        cpu, _ = make(b"\x74\x0a\x75\xf0\x00\x84\x80\xfe")
        cpu.run_steps(4)
        self.assertTrue(cpu.psw & 0x04, "деление на 0 -> OV=1")

    def test_da_a_produces_bcd(self):
        # MOV A,#09h ; ADD A,#01h ; DA A -> 0x10
        cpu, _ = make(b"\x74\x09\x24\x01\xd4\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.acc, 0x10, "двоично-десятичная коррекция")

    def test_rlc_rotates_through_carry(self):
        # MOV A,#80h ; RLC A -> A=0, CY=1
        cpu, _ = make(b"\x74\x80\x33\x80\xfe")
        cpu.run_steps(3)
        self.assertEqual(cpu.acc, 0x00)
        self.assertTrue(cpu.psw & 0x80)


class TestMemoryAndBits(unittest.TestCase):

    def test_direct_versus_indirect_ram(self):
        # MOV 30h,#0AAh ; MOV R0,#30h ; MOV A,@R0
        cpu, _ = make(b"\x75\x30\xaa\x78\x30\xe6\x80\xfe")
        cpu.run_steps(4)
        self.assertEqual(cpu.acc, 0xAA)

    def test_register_bank_switching(self):
        # MOV PSW,#08h ; MOV R0,#11h ; MOV PSW,#00h ; MOV A,R0
        cpu, _ = make(b"\x75\xd0\x08\x78\x11\x75\xd0\x00\xe8\x80\xfe")
        cpu.run_steps(5)
        self.assertEqual(cpu.acc, 0x00, "после возврата в банк 0 R0 не тот")
        self.assertEqual(cpu.ram[0x08], 0x11, "R0 банка 1 лежит в 0x08")

    def test_bit_operations(self):
        """SETB/MOV C работают с битовым адресом, а не с номером байта.

        Бит 0x23 — это байт 0x24, разряд 3 (адрес бита = (байт-0x20)*8 + n).
        """
        cpu, _ = make(b"\xd2\x23\xc3\xa2\x23\x80\xfe")
        cpu.run_steps(4)
        self.assertTrue(cpu.psw & 0x80, "бит 0x23 установлен -> CY=1")
        self.assertEqual(cpu.ram[0x24] & 0x08, 0x08, "байт 0x24, разряд 3")
        self.assertEqual(cpu.ram[0x20], 0x00, "байт 0x20 трогать не должны")

    def test_bit_address_maps_to_the_right_byte(self):
        # Бит 0x00 — это байт 0x20 разряд 0; бит 0x2F — байт 0x25 разряд 7
        cpu, _ = make(b"\xd2\x00\xd2\x2f\x80\xfe")
        cpu.run_steps(2)
        self.assertEqual(cpu.ram[0x20] & 0x01, 0x01, "бит 0x00 -> 20h.0")
        self.assertEqual(cpu.ram[0x25] & 0x80, 0x80, "бит 0x2F -> 25h.7")

    def test_push_pop_round_trip(self):
        # MOV A,#5Ah ; PUSH ACC ; MOV A,#00h ; POP ACC
        cpu, _ = make(b"\x74\x5a\xc0\xe0\x74\x00\xd0\xe0\x80\xfe")
        cpu.run_steps(6)
        self.assertEqual(cpu.acc, 0x5A)
        self.assertEqual(cpu.sp, 0x07)

    def test_djnz_counts_down_and_branches(self):
        # MOV R0,#03h ; DJNZ R0,$-2 ; LJMP 0040h
        cpu, _ = make(b"\x78\x03\xd8\xfe\x02\x00\x40")
        cpu.run_steps(12)
        self.assertEqual(cpu.ram[0x00], 0x00)
        self.assertEqual(cpu.pc, 0x0040, "после обнуления выходим из цикла")

    def test_jb_taken_when_bit_is_set(self):
        # SETB 20h.0 (бит 0x00) ; JB 0x00 -> переход мимо LJMP NO
        cpu, _ = make(b"\xd2\x00" + b"\x20\x00\x03"
                      + b"\x02\x00\x30" + b"\x02\x00\x40")
        cpu.run_steps(4)
        self.assertEqual(cpu.pc, 0x0040, "бит установлен -> переход сделан")

    def test_jb_not_taken_when_bit_is_clear(self):
        # Бит снят: JB обязан пройти дальше, не прыгая
        cpu, _ = make(b"\xc2\x00" + b"\x20\x00\x03"
                      + b"\x02\x00\x30" + b"\x02\x00\x40")
        cpu.run_steps(4)
        self.assertEqual(cpu.pc, 0x0030, "бит снят -> JB не переходит")

    def test_jnb_taken_when_bit_is_clear(self):
        # CLR 20h.0 ; JNB 0x00 -> прыжок
        cpu, _ = make(b"\xc2\x00" + b"\x30\x00\x03"
                      + b"\x02\x00\x30" + b"\x02\x00\x40")
        cpu.run_steps(4)
        self.assertEqual(cpu.pc, 0x0040, "бит снят -> переход сделан")

    def test_jbc_clears_the_bit(self):
        # SETB 20h.0 ; JBC 0x00 -> переход и бит снят
        cpu, _ = make(b"\xd2\x00" + b"\x10\x00\x03"
                      + b"\x02\x00\x30" + b"\x02\x00\x40")
        cpu.run_steps(4)
        self.assertEqual(cpu.pc, 0x0040, "JBC переходит")
        self.assertEqual(cpu.ram[0x20] & 0x01, 0x00, "JBC обязан снять бит")

    def test_movx_goes_through_the_bus(self):
        from m8051.bus import NullBus as Bus

        rom = ROM("x")
        rom.load_block(0, b"\x90\x12\x34\x74\x5a\xf0\xe0\x80\xfe")
        bus = Bus()
        cpu = CPU8051(rom, bus)
        cpu.run_steps(4)
        self.assertEqual(bus.ext[0x1234], 0x5A, "MOVX @DPTR,A")
        cpu.step()
        self.assertEqual(cpu.acc, 0x5A, "MOVX A,@DPTR")

    def test_ajmp_stays_in_page(self):
        # AJMP: целевая страница = (PC+2) & 0xF800, плюс биты 10..8 из опкода.
        # Из адреса 0x0000 попасть на 0x0100 можно только опкодом 0x21.
        cpu, _ = make(b"\x21\x00\x80\xfe" + bytes(0x1FA) + b"\x80\xfe")
        cpu.step()
        self.assertEqual(cpu.pc, 0x0100, "AJMP 21 00 из 0x0000 ведёт на 0x0100")

    def test_ajmp_page_zero(self):
        # 0x01 -> биты 10..8 = 000, значит страница нулевая
        cpu, _ = make(b"\x01\x00\x80\xfe")
        cpu.step()
        self.assertEqual(cpu.pc, 0x0000, "AJMP 01 00 остаётся в странице 0")

    def test_ajmp_keeps_upper_address_bits(self):
        # Из 0x0800 опкод 0x01 с операндом 0x10 обязан дать 0x0810:
        # страница берётся из самого адреса инструкции, а не из нуля.
        cpu, _ = make(b"\x01\x10\x80\xfe", base=0x0800)
        cpu.pc = 0x0800
        cpu.step()
        self.assertEqual(cpu.pc, 0x0810, "AJMP обязан сохранить старшие биты")


class TestTimers(unittest.TestCase):

    def test_timer_runs_only_after_tr0_is_set(self):
        """До SETB TR0 счётчик обязан стоять — иначе все тайминги врут."""
        cpu, _ = make(b"\x75\x89\x01\x75\x8c\xff\x75\x8a\xf0\x80\xfe")
        cpu.run_steps(3)                 # настройка без SETB TR0
        self.assertFalse(cpu.sfr[0x88] & 0x10, "TR0 ещё не взведён")
        self.assertEqual(cpu.sfr[0x8C], 0xFF, "TH0 не менялся")
        self.assertEqual(cpu.sfr[0x8A], 0xF0, "TL0 не считал без TR0")
        self.assertFalse(cpu.sfr[0x88] & 0x20, "и переполнения не было")

    def test_timer0_mode1_overflows_and_sets_tf0(self):
        # MOV TMOD,#01h ; MOV TH0,#0FFh ; MOV TL0,#0F0h ; SETB TR0
        # TL0 = F0h: от настройки до переполнения есть запас, поэтому
        # проверяем именно момент переполнения, а не случайный.
        cpu, _ = make(b"\x75\x89\x01\x75\x8c\xff\x75\x8a\xf0\xd2\x8c\x80\xfe")
        cpu.run_steps(3)                 # только три MOV: TR0 ещё не взведён
        self.assertFalse(cpu.sfr[0x88] & 0x10, "TR0 ещё не взведён")
        self.assertFalse(cpu.sfr[0x88] & 0x20, "до переполнения TF0 снят")
        self.assertEqual(cpu.sfr[0x8C], 0xFF, "TH0 = FFh")
        self.assertEqual(cpu.sfr[0x8A], 0xF0, "TL0 = F0h")
        for _ in range(60):              # даём счётчику дойти до 0x10000
            cpu.step()
            if cpu.sfr[0x88] & 0x20:
                break
        self.assertTrue(cpu.sfr[0x88] & 0x20, "TF0 обязан взвестись")
        self.assertEqual(cpu.sfr[0x8C], 0x00, "при переполнении TH0 обнуляется")
        self.assertLess(cpu.sfr[0x8A], 0x40, "TL0 пошёл заново с нуля")

    def test_timer0_does_not_overflow_early(self):
        # TH0/TL0 = 0x1234, всего 4 цикла — переполнения быть не должно
        cpu, _ = make(b"\x75\x89\x01\x75\x8c\x12\x75\x8a\x34\xd2\x8c\x80\xfe")
        cpu.run_steps(6)
        self.assertFalse(cpu.sfr[0x88] & 0x20, "слишком рано для переполнения")
        self.assertEqual(cpu.sfr[0x8C], 0x12, "старший байт не тронут")
        self.assertGreaterEqual(cpu.sfr[0x8A], 0x34, "младший байт только растёт")

    def test_timer1_mode2_auto_reload(self):
        # MOV TMOD,#20h ; MOV TH1,#0FEh ; MOV TL1,#0FEh ; SETB TR1
        # TH1 - регистр перезагрузки: он не должен меняться НИКОГДА.
        cpu, _ = make(b"\x75\x89\x20\x75\x8d\xfe\x75\x8b\xfe\xd2\x8e\x80\xfe")
        cpu.run_steps(5)
        self.assertEqual(cpu.sfr[0x8D], 0xFE, "TH1 после настройки")
        for _ in range(30):
            cpu.step()
        self.assertTrue(cpu.sfr[0x88] & 0x80, "TF1 обязан взвестись")
        self.assertEqual(cpu.sfr[0x8D], 0xFE, "TH1 - регистр перезагрузки, менять нельзя")
        self.assertIn(cpu.sfr[0x8B], (0xFE, 0xFF), "TL1 колеблется у значения перезагрузки")

    def test_timer1_mode2_batch_of_cycles_keeps_reload_register(self):
        """Пакетное продвижение сразу на много циклов не должно портить TH1."""
        cpu, _ = make(b"\x75\x89\x20\x75\x8d\xfe\x75\x8b\xfe\xd2\x8e\x80\xfe")
        cpu.run_steps(5)
        cpu._do_peripherals(1000)          # разом тысяча машинных циклов
        self.assertEqual(cpu.sfr[0x8D], 0xFE, "TH1 не должен измениться")
        self.assertTrue(cpu.sfr[0x88] & 0x80, "переполнение обязано быть отмечено")


class TestHalting(unittest.TestCase):

    def test_unmapped_fetch_stops_the_cpu_and_reports_address(self):
        rom = ROM("sparse")
        rom.load_block(0x8000, b"\x02\x90\x00")     # LJMP 9000h (не отдано)
        cpu = CPU8051(rom, NullBus())
        cpu.pc = 0x8000
        cpu.step()
        self.assertEqual(cpu.pc, 0x9000)
        cpu.step()
        self.assertTrue(cpu.halted)
        self.assertEqual(cpu.missing_pc, 0x9000)
        self.assertIn("0x9000", cpu.error)


class TestAluFlags(unittest.TestCase):
    """ADD/ADDC/SUBB ОБНОВЛЯЮТ CY/AC/OV, а не только выставляют их.

    «Залипающие» флаги ломают DA A, то есть всю десятичную арифметику денег.
    """

    def _after(self, program: bytes, steps: int = 4) -> CPU8051:
        cpu, _ = make(bytes(program) + b"\x80\xfe")
        cpu.run_steps(steps)
        return cpu

    def test_auxiliary_carry_sets_and_clears(self):
        cpu = self._after([0x74, 0x08, 0x24, 0x08])          # 08h + 08h
        self.assertTrue(cpu.psw & 0x40, "перенос из младшей тетрады -> AC=1")
        cpu = self._after([0x74, 0x10, 0x24, 0x01])          # 10h + 01h
        self.assertFalse(cpu.psw & 0x40, "переноса нет -> AC обязан сброситься")

    def test_carry_sets_and_clears(self):
        cpu = self._after([0x74, 0xFF, 0x24, 0x02])
        self.assertTrue(cpu.psw & 0x80, "FFh+2 -> CY=1")
        cpu = self._after([0x74, 0x01, 0x24, 0x01])
        self.assertFalse(cpu.psw & 0x80, "01h+1 -> CY обязан сброситься")

    def test_overflow_sets_and_clears(self):
        cpu = self._after([0x74, 0x7F, 0x24, 0x01])
        self.assertTrue(cpu.psw & 0x04, "7Fh+1 -> OV=1")
        cpu = self._after([0x74, 0x01, 0x24, 0x01])
        self.assertFalse(cpu.psw & 0x04, "01h+1 -> OV обязан сброситься")

    def test_da_a_gives_correct_bcd(self):
        cpu = self._after([0x74, 0x50, 0x24, 0x00, 0xD4], 5)
        self.assertEqual(cpu.acc, 0x50, "50h+0 -> DA A должно дать 50h")
        cpu = self._after([0x74, 0x09, 0x24, 0x01, 0xD4], 5)
        self.assertEqual(cpu.acc, 0x10, "09h+1 -> DA A должно дать 10h")
        cpu = self._after([0x74, 0x99, 0x24, 0x01, 0xD4], 5)
        self.assertEqual(cpu.acc, 0x00, "99h+1 -> DA A должно дать 00h с переносом")
        self.assertTrue(cpu.psw & 0x80, "CY=1")

    def test_add_preserves_register_bank_bits(self):
        # MOV PSW,#18h (RS1+RS0 = банк 3) ; MOV A,#01h ; ADD A,#01h
        cpu = self._after([0x75, 0xD0, 0x18, 0x74, 0x01, 0x24, 0x01], 3)
        self.assertTrue(cpu.psw & 0x08, "ADD не имеет права сбрасывать RS0")
        self.assertTrue(cpu.psw & 0x10, "ADD не имеет права сбрасывать RS1")
        self.assertEqual(cpu.psw & 0x18, 0x18, "выбранный банк обязан сохраниться")
        self.assertEqual(cpu.acc, 0x02)

    def test_add_switches_bank_when_psw_says_so(self):
        # Обратная проверка: смена банка должна работать и влиять на R0.
        cpu, _ = make(b"\x75\xd0\x08\x78\x11\x75\xd0\x00\x78\x22\xe8\x80\xfe")
        cpu.run_steps(5)
        self.assertEqual(cpu.ram[0x08], 0x11, "R0 банка 1")
        self.assertEqual(cpu.ram[0x00], 0x22, "R0 банка 0")
        self.assertEqual(cpu.acc, 0x22, "после возврата в банк 0 читается свой R0")

    def test_subb_clears_borrow(self):
        cpu = self._after([0x74, 0x20, 0x94, 0x10])
        self.assertFalse(cpu.psw & 0x80, "20h-10h -> заёма нет, CY=0")
        self.assertEqual(cpu.acc, 0x10)


class TestAcallAndDecoding(unittest.TestCase):
    """ACALL (0x11/0x31/...) обязан работать: он есть в реальных прошивках."""

    def test_acall_pushes_return_address_and_jumps(self):
        cpu, _ = make(bytes([0x11, 0x20, 0x80, 0xFE]) + bytes(0x1C) + bytes([0x22]))
        cpu.step()
        # ACALL 0020h: страница берётся из (PC+2) & 0xF800
        self.assertEqual(cpu.pc, 0x0020)
        self.assertEqual(cpu.ram[0x08], 0x02, "адрес возврата 0x0002")
        self.assertEqual(cpu.ram[0x09], 0x00)
        cpu.step()
        self.assertEqual(cpu.pc, 0x0002)

    def test_acall_page_bits(self):
        # опкод 0x31 -> страница 0x0100
        cpu, _ = make(bytes([0x31, 0x20, 0x80, 0xFE]) + bytes(0x11C) + bytes([0x22]))
        cpu.step()
        self.assertEqual(cpu.pc, 0x0120)

    def test_disassembler_knows_acall(self):
        from tools.disasm import disassemble_one

        text, length = disassemble_one(bytes([0x11, 0x20, 0x00]), 0)
        self.assertEqual(length, 2)
        self.assertIn("ACALL", text)
        self.assertIn("0020", text)

    def test_disassembler_renders_ram_bits_by_containing_byte(self):
        from tools.disasm import disassemble_one

        # JB 21h,rel: битовый адрес 0x21 -> байт 0x24, бит 1
        text, _ = disassemble_one(bytes([0x20, 0x21, 0x00]), 0)
        self.assertIn("24h.1", text, f"битовый адрес 0x21 это байт 24h.1, получено {text!r}")
        # и обратная проверка: байт 0x20 бит 0 -> битовый адрес 0x00
        text, _ = disassemble_one(bytes([0x20, 0x00, 0x00]), 0)
        self.assertIn("20h.0", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
