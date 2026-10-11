"""Tests for the emulated cash-register hardware (``board/``).

Covers, in order:

* the 8255 PPI (control-word decoding, quasi-bidirectional ports, mode 1
  handshake);
* the display (7-segment decode, frame buffer, the ROM digit-select table);
* the keyboard matrix (active-low columns, tap/press, all contract names);
* the printer (40 columns, firmware transliteration round trip);
* the board wiring (native display refresh, native keyboard read, P3.4 printer
  strobe, INT0 on a key event, ``status()``, ``self_test=True``);
* the ROM evidence the wiring is derived from (<- the point of this file);
* an integration test that runs a hand-assembled 8051 program through the real
  ``m8051.CPU8051`` core and asserts what the board shows and prints - this is
  also the regression test for the core's ``push_pc`` byte order and ``CJNE``
  condition bugs, because a wrong return address or a wrong branch changes the
  board's output.

Run with::

    python -m unittest tests.test_board -v
"""

from __future__ import annotations

import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from m8051 import CPU8051, ROM  # noqa: E402
from m8051.bus import IRQ_INT0  # noqa: E402
from tools.disasm import disassemble_one  # noqa: E402

from board.cashboard import WIRING, CashRegisterBoard  # noqa: E402
from board.display import (  # noqa: E402
    SEG7,
    SEG16,
    char_for_segments,
    gray_index,
    segments_for,
)
from board.keyboard import ALIASES, KEYS, Keyboard  # noqa: E402
from board.ppi8255 import CTRL, PORT_A, PORT_B, PORT_C, PPI8255  # noqa: E402
from board.printer import ReceiptPrinter, decode_text, encode_text  # noqa: E402

ROM_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "firmware", "nm27c512n.hex",
)

REQUIRED_KEYS = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ".", "00",
    "СУММА", "ОПЛ", "X", "ITOG", "ОТМЕНА", "ВОЗВРАТ", "СКИДКА",
    "КАССИР", "СЕРВИС", "РЕЖИМ", "ВВОД", "СБРОС", "ПОДЫТОГ",
    "ЧЕК", "КС", "Z", "ПИТ", "СТРЕЛКА_ВЛЕВО", "СТРЕЛКА_ВПРАВО",
    "ПРОБЕЛ", "ТАБ",
]


# --------------------------------------------------------------------------
# a tiny two-pass assembler for the handful of instructions the integration
# test needs; hand-encoding addresses is how bugs creep into tests.
# --------------------------------------------------------------------------
class Asm:
    def __init__(self, base: int = 0x0000) -> None:
        self.base = base
        self.items = []          # (bytes or ("fixup", kind, label, size))
        self.labels = {}

    def _emit(self, raw: bytes) -> None:
        self.items.append(("raw", raw))

    def label(self, name: str) -> None:
        self.labels[name] = None
        self.items.append(("label", name))

    # --- instructions -----------------------------------------------------
    def mov_dptr(self, addr: int) -> None:
        self._emit(bytes([0x90, (addr >> 8) & 0xFF, addr & 0xFF]))

    def mov_a(self, imm: int) -> None:
        self._emit(bytes([0x74, imm & 0xFF]))

    def mov_r0(self, imm: int) -> None:
        self._emit(bytes([0x78, imm & 0xFF]))

    def movx_dptr_a(self) -> None:
        self._emit(b"\xF0")

    def movx_a_dptr(self) -> None:
        self._emit(b"\xE0")

    def ret(self) -> None:
        self._emit(b"\x22")

    def nop(self) -> None:
        self._emit(b"\x00")

    def lcall(self, label: str) -> None:
        self.items.append(("lcall", label))

    def sjmp(self, label: str) -> None:
        self.items.append(("sjmp", label))

    def jb_acc(self, bit: int, label: str) -> None:
        self.items.append(("jb_acc", (bit, label)))

    def cjne_a_imm(self, imm: int, label: str) -> None:
        self.items.append(("cjne_a_imm", (imm, label)))

    def halt(self) -> None:
        self._emit(bytes([0x80, 0xFE]))          # SJMP $ (2 bytes)

    # --- assembly ---------------------------------------------------------
    def assemble(self) -> bytes:
        size = 0
        for kind, payload in self.items:
            if kind == "raw":
                size += len(payload)
            elif kind == "label":
                self.labels[payload] = self.base + size
            else:                                # all remaining forms are 3 bytes
                size += 3
        out = bytearray()
        for kind, payload in self.items:
            addr = self.base + len(out)
            if kind == "raw":
                out += payload
            elif kind == "label":
                continue
            elif kind == "lcall":
                tgt = self.labels[payload]
                out += bytes([0x12, (tgt >> 8) & 0xFF, tgt & 0xFF])
            elif kind == "sjmp":
                off = (self.labels[payload] - (addr + 2)) & 0xFF
                out += bytes([0x80, off])
            elif kind == "jb_acc":
                bit, label = payload
                off = (self.labels[label] - (addr + 3)) & 0xFF
                out += bytes([0x20, 0xE0 | (bit & 7), off])
            elif kind == "cjne_a_imm":
                imm, label = payload
                off = (self.labels[label] - (addr + 3)) & 0xFF
                out += bytes([0xB4, imm & 0xFF, off])
        return bytes(out)


def make_cpu(program: bytes, board=None) -> CPU8051:
    rom = ROM("unit")
    rom.load_block(0x0000, program)
    return CPU8051(rom, board if board is not None else CashRegisterBoard())


# ==========================================================================
class PPI8255Tests(unittest.TestCase):
    def test_reset_state_is_all_inputs_mode0(self):
        p = PPI8255()
        self.assertEqual(p.mode_a, 0)
        self.assertEqual(p.mode_b, 0)
        self.assertEqual(p.ddr, [0xFF, 0xFF, 0xFF])

    def test_mode_word_0x89_decodes_as_the_firmware_expects(self):
        """0x89 = group A mode 0, A out, C-upper in, B out, C-lower in."""
        p = PPI8255()
        p.write_control(0x89)
        self.assertEqual(p.mode_a, 0)
        self.assertEqual(p.mode_b, 0)
        self.assertEqual(p.ddr[PORT_A], 0x00, "port A output")
        self.assertEqual(p.ddr[PORT_B], 0x00, "port B output")
        self.assertEqual(p.ddr[PORT_C], 0xFF, "port C input")
        self.assertEqual(p.read_control() & 0x7F, 0x09)

    def test_mode_word_0xa9_is_group_a_mode1(self):
        """0xA9 = the same but group A mode 1: port A becomes a strobed port."""
        p = PPI8255()
        p.write_control(0xA9)
        self.assertEqual(p.mode_a, 1)
        self.assertEqual(p.ddr[PORT_A], 0x00)
        self.assertEqual(p.read_control() & 0x7F, 0x29)

    def test_bit_set_reset_word_touches_one_pc_bit(self):
        p = PPI8255()
        p.write_control(0x89)                  # port C is an input: no output
        p.write_control(0x80)                  # BSR: PC0 = output? no - 0x80 -> bit0 set
        self.assertEqual(p.latch[PORT_C] & 1, 1)
        p.write_control(0x00)                  # bit0 reset
        self.assertEqual(p.latch[PORT_C] & 1, 0)

    def test_quasi_bidirectional_read_returns_pin_not_latch(self):
        p = PPI8255()
        p.write_control(0x89)
        p.set_pins(PORT_C, 0xFE)               # keyboard pulls bit0 low
        self.assertEqual(p.read(PORT_C), 0xFE)
        p.set_pins(PORT_C, 0xFF)
        self.assertEqual(p.read(PORT_C), 0xFF)

    def test_mode1_output_handshake_obf_ack_intr(self):
        p = PPI8255()
        p.write_control(0xA9)                  # group A mode 1, port A output
        p.write(PORT_A, 0x41)
        self.assertEqual(p.obf_a, 0, "/OBF asserted when data is written")
        self.assertEqual(p.read(PORT_C) & 0x80, 0x00, "PC7 = /OBF low")
        p.notify_ack(PORT_A)
        self.assertEqual(p.obf_a, 1)
        self.assertEqual(p.intr_a, 1, "INTR follows /ACK when INTE is set")
        self.assertTrue(p.interrupt())
        p.clear_intr(PORT_A)
        self.assertFalse(p.interrupt())

    def test_mode2_sets_all_handshake_pins(self):
        p = PPI8255()
        p.write_control(0x80 | 0x40 | 0x10)    # D7=1, group A mode 2, A output
        self.assertEqual(p.mode_a, 2)
        self.assertEqual(p.ddr[PORT_C] & 0xF8, 0xF8)

    def test_bsr_set_reset_is_applied_to_the_latch(self):
        p = PPI8255()
        p.write_control(0x89)                  # PC input -> not usable as output
        p.write_control(0x8D)                  # mode set, A/B out, PC upper out, PC lower in
        p.write_control(0x0F)                  # BSR: set PC7
        self.assertEqual(p.latch[PORT_C] & 0x80, 0x80)

    def test_writes_reach_the_callback(self):
        seen = []
        p = PPI8255()
        p.on_output = lambda port, value: seen.append((port, value))
        p.write_control(0x89)
        p.write(PORT_A, 0x3F)
        p.write(PORT_B, 0x01)
        self.assertEqual(seen, [(PORT_A, 0x3F), (PORT_B, 0x01)])

    # -- handshake hardening: INTE / статусные биты -------------------------
    def test_bsr_arms_and_disarms_the_interrupt_enable(self):
        """PC4 в mode 1 — это INTE: BSR взводит/гасит INTR группы A."""
        p = PPI8255()
        p.write_control(0xA9)                    # group A mode 1, A out
        self.assertEqual(p.inte_a, 0)
        p.write_control(0x09)                    # BSR: set PC4 -> INTE A
        self.assertEqual(p.inte_a, 1)
        self.assertEqual(p.read(PORT_C) & 0x10, 0x10, "PC4 читается как INTE")
        p.write(PORT_A, 0x41)
        self.assertEqual(p.intr_a, 1, "INTR следует за взведённым INTE")
        self.assertTrue(p.interrupt())
        p.clear_intr(PORT_A)
        self.assertFalse(p.interrupt())
        p.write_control(0x08)                    # BSR: reset PC4
        self.assertEqual(p.inte_a, 0)
        self.assertEqual(p.read(PORT_C) & 0x10, 0)

    def test_mode_set_disarms_interrupt_enable(self):
        """Новое слово режима возвращает INTE в 0 — пора взводить заново."""
        p = PPI8255()
        p.write_control(0xA9)
        p.write_control(0x09)
        self.assertEqual(p.inte_a, 1)
        p.write_control(0xA9)
        self.assertEqual(p.inte_a, 0)
        self.assertEqual(p.inte_b, 0)

    def test_mode2_status_shows_ibf_stb_and_obf(self):
        """Mode 2: статус на PC7..PC3 отдаёт весь handshake, а не 3 бита."""
        p = PPI8255()
        p.write_control(0xD0)                    # group A mode 2
        status = p.read(PORT_C)
        self.assertEqual(status & 0x80, 0x80, "/OBF idle high")
        self.assertEqual(status & 0x10, 0x10, "/STB idle high")
        p.notify_stb(PORT_A, 0x5A)
        status = p.read(PORT_C)
        self.assertEqual(status & 0x20, 0x20, "IBF выставлен стробом")
        self.assertEqual(status & 0x10, 0x00, "/STB активен (low)")
        p.notify_ack(PORT_A)
        self.assertEqual(p.read(PORT_C) & 0x40, 0, "/ACK активен (low)")


# ==========================================================================
class DisplayTests(unittest.TestCase):
    def test_seven_segment_decode_round_trip(self):
        # some masks are shared (e.g. '1' and 'I' are both 0x06), so accept any
        # character that maps onto the same mask
        by_mask = {}
        for ch, mask in SEG7.items():
            by_mask.setdefault(mask & 0xFF, []).append(ch)
        for ch, mask in SEG7.items():
            if ch == " ":
                continue
            self.assertIn(char_for_segments(mask & 0xFF), by_mask[mask & 0xFF],
                          f"mask 0x{mask:02X} for {ch!r}")

    def test_common_cathode_values(self):
        for ch, mask in (("0", 0x3F), ("1", 0x06), ("2", 0x5B), ("8", 0x7F),
                         ("9", 0x6F), ("-", 0x40), (" ", 0x00)):
            self.assertEqual(SEG7[ch], mask, ch)

    def test_text_after_ppi_style_writes(self):
        from board.display import Display
        d = Display(8, 1)
        d.select_grid(0, commit=False)
        d.latch_segments(SEG7["4"], None)
        d.commit_grid()
        d.select_grid(1, commit=False)
        d.latch_segments(SEG7["2"], None)
        d.commit_grid()
        self.assertEqual(d.text(), "42      ")
        self.assertEqual(d.cell_segments(0), 0x66)
        self.assertEqual(d.cell_segments(1), 0x5B)

    def test_report_refresh_order_commits_pending_segments(self):
        """ROM order (0x8309..0x831E): segment bytes first, then the grid."""
        from board.display import Display
        d = Display(8, 1)
        d.latch_segments(SEG7["7"], None)
        d.select_grid(3, commit=True)
        self.assertEqual(d.text()[3], "7")

    def test_grid_8_blanks_the_display(self):
        from board.display import Display
        d = Display(8, 1)
        d.latch_segments(SEG7["5"], None)
        d.select_grid(0, commit=True)
        d.select_grid(8, commit=False)
        self.assertTrue(d.blank)
        self.assertEqual(d.grid, -1)
        self.assertEqual(d.text()[0], "5", "frame buffer keeps the last frame")

    def test_render_rows_shape(self):
        from board.display import Display
        d = Display(8, 1)
        d.set_segments_at(0, segments_for("8"))
        rows = d.render_rows()
        self.assertEqual(len(rows), 7)
        self.assertEqual(len(rows[0]), 40)
        self.assertEqual(set("".join(rows)), {"#", "."})
        self.assertEqual(len(d.render_rows(2)), 14)
        self.assertEqual(len(d.render_rows(2)[0]), 80)

    def test_rom_digit_select_table_decodes_as_gray_code(self):
        """The table the firmware ORs into the 0xA1 write is 0x40|gray(i)."""
        for i, value in enumerate((0x41, 0x49, 0x48, 0x4C, 0x44, 0x46, 0x42, 0x43)):
            self.assertEqual(gray_index(value), i, hex(value))

    def test_16bit_alphabet_has_cyrillic(self):
        for ch in "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ":
            self.assertIn(ch, SEG16)
        self.assertNotEqual(segments_for("Ж"), 0)

    # -- краевые случаи рендеринга 8-разрядного индикатора ------------------
    def test_lone_decimal_point_decodes_as_dot(self):
        """Ячейка только с dp (разделитель денег «12.34») — это '.', не blank."""
        from board.display import Display, char_for_segments
        self.assertEqual(char_for_segments(0x80), ".")
        d = Display(8, 1)
        d.set_segments_at(0, 0x80)
        self.assertEqual(d.text()[0], ".")
        # тот же путь и через шину: сегмент в 0x82xx, сетка в 0xA2xx
        b = CashRegisterBoard()
        b.ext_write(0x8200, 0x80)
        b.ext_write(0xA200, 0)
        self.assertEqual(b.display.text()[0], ".")

    def test_grid_codes_above_seven_blank_the_display(self):
        """ROM шлёт R0&7 (0..7) и 8=гашение; BCD > 9 и мусор гасят сетку."""
        from board.display import Display
        d = Display(8, 1)
        d.latch_segments(SEG7["5"], None)
        d.select_grid(0, commit=True)
        for code in (8, 9, 10, 0x0A, 0x99, 0xFF):
            d.select_grid(code, commit=True)
            self.assertTrue(d.blank, hex(code))
            self.assertEqual(d.grid, -1, hex(code))
        self.assertEqual(d.text()[0], "5", "кадр в ячейках сохраняется")

    def test_multiline_grid_stays_within_rom_digits(self):
        """Разряды 0..7 адресуются всегда, даже если колонок меньше."""
        from board.display import Display
        d = Display(4, 2)                        # 8 ячеек, 4 колонки
        d.latch_segments(SEG7["7"], None)
        d.select_grid(5, commit=True)
        self.assertEqual(d.text()[5], "7")
        d.select_grid(8, commit=True)            # 8 = гашение (ROM 0x82E1)
        self.assertTrue(d.blank)

    def test_out_of_range_cell_writes_are_ignored(self):
        """Запись за пределы кадра (переполнение money-поля) не падает."""
        from board.display import Display
        d = Display(8, 1)
        d.write_digit_byte(99, SEG7["1"])
        d.write_digit_byte(-1, SEG7["1"])
        d.commit_grid(99)
        d.write_char(64, ord("A"))
        d.set_segments_at(-5, 0xFFFF)
        self.assertEqual(d.text(), " " * 8)
        self.assertEqual(d.cell_segments(999), 0)
        self.assertEqual(d.cell_char(999), " ")

    def test_render_rows_clamps_degenerate_scales(self):
        from board.display import Display
        d = Display(2, 1)
        d.write_char(0, 0x07)                    # несимвольный код -> '?'
        self.assertEqual(d.cell_char(0), "?")
        for scale in (0, -3, 1):
            rows = d.render_rows(scale)
            self.assertEqual(len(rows), 7, scale)
            self.assertEqual(len(rows[0]), 10, scale)
            self.assertTrue(set("".join(rows)) <= {"#", "."})


# ==========================================================================
class KeyboardTests(unittest.TestCase):
    def test_every_contract_key_exists(self):
        kb = Keyboard()
        for name in REQUIRED_KEYS:
            self.assertIn(name, kb.keys, name)
        for name in KEYS:
            self.assertIsNotNone(kb.position(name), name)

    def test_press_release_tap(self):
        kb = Keyboard()
        self.assertFalse(kb.is_pressed("7"))
        kb.press("7")
        self.assertTrue(kb.is_pressed("7"))
        kb.release("7")
        self.assertFalse(kb.is_pressed("7"))
        kb.tap("8")
        self.assertTrue(kb.is_pressed("8"))
        kb.tick(kb.tap_cycles + 1)
        self.assertFalse(kb.is_pressed("8"), "a tap must expire on tick()")

    def test_columns_are_active_low_per_row(self):
        kb = Keyboard()
        row = kb.row_of("7")
        col = kb.col_of("7")
        self.assertEqual(kb.read_columns(row), 0xFF, "idle row reads all ones")
        kb.press("7")
        self.assertEqual(kb.read_columns(row), (~(1 << col)) & 0xFF)
        self.assertEqual(kb.read_columns((row + 1) % 8), 0xFF, "other rows idle")

    def test_unpopulated_positions_read_idle(self):
        kb = Keyboard()
        self.assertEqual(kb.read_columns(7), 0xFF)

    def test_press_into_thin_air_is_accepted(self):
        kb = Keyboard()
        kb.press("НЕТ_ТАКОЙ_КЛАВИШИ")
        self.assertTrue(kb.is_pressed("НЕТ_ТАКОЙ_КЛАВИШИ"))
        kb.release("НЕТ_ТАКОЙ_КЛАВИШИ")

    def test_aliases_resolve(self):
        kb = Keyboard()
        self.assertEqual(kb.position("ИТОГ"), kb.position("ITOG"))
        self.assertIsNotNone(kb.position(ALIASES["ENTER"] if "ENTER" in ALIASES else "ВВОД"))

    def test_row_bits_and_scan(self):
        kb = Keyboard()
        kb.press("0")
        kb.press("Z")
        bits = kb.row_bits()
        self.assertEqual(bits, (1 << kb.row_of("0")) | (1 << kb.row_of("Z")))
        names = {n for _r, _c, n in kb.scan()}
        self.assertEqual(names, {"0", "Z"})

    # -- краевые случаи: алиасный tap и пустой ввод -------------------------
    def test_alias_tap_expires_instead_of_sticking(self):
        """tap() канонизирует имя: «ИТОГ» -> ITOG, иначе ключ залипает."""
        kb = Keyboard()
        kb.tap("ИТОГ")
        self.assertTrue(kb.is_pressed("ИТОГ"))
        kb.tick(kb.tap_cycles + 1)
        self.assertFalse(kb.is_pressed("ITOG"),
                         "tap через алиас обязан истечь на tick()")

    def test_empty_key_name_is_ignored(self):
        kb = Keyboard()
        kb.press("")
        kb.tap("")
        kb.release("")
        self.assertFalse(kb.any_pressed())
        self.assertEqual(kb.pressed_keys(), [])
        self.assertEqual(kb.event_count, 0, "пустое имя не рождает событий")
        self.assertEqual(kb.read_columns(0), 0xFF)


# ==========================================================================
class PrinterTests(unittest.TestCase):
    def test_print_and_paper(self):
        p = ReceiptPrinter()
        p.write_bytes(encode_text("ИТОГ 12.34\n"))
        self.assertEqual(p.paper(), ["ИТОГ 12.34"])
        self.assertEqual(p.text(), "ИТОГ 12.34")

    def test_wraps_at_columns(self):
        p = ReceiptPrinter(columns=10, decode=False)
        p.write_bytes(b"AAAAAAAAAAAAAAA")           # 15 'A'
        self.assertEqual(p.paper(), ["AAAAAAAAAA", "AAAAA"])

    def test_carriage_return_and_backspace(self):
        # Семантика 0x0D: возврат каретки в колонку 0 БЕЗ стирания —
        # текст остаётся на ленте и перезаписывается поверх (как на
        # настоящем принтере). CRLF не теряет строку.
        p = ReceiptPrinter(decode=False)
        p.write_bytes(b"ABC\rXY\n")
        self.assertEqual(p.paper(), ["XYC"])
        p3 = ReceiptPrinter(decode=False)
        p3.write_bytes(b"ABC\r\n")
        self.assertEqual(p3.paper(), ["ABC"], "CRLF печатает строку целиком")
        p2 = ReceiptPrinter(decode=False)
        p2.write_bytes(b"ABC\x08D\n")
        self.assertEqual(p2.paper(), ["ABD"])

    def test_feed_and_clear(self):
        p = ReceiptPrinter(decode=False)
        p.write_bytes(b"one\ntwo")
        p.feed(2)
        paper = p.paper()
        self.assertEqual(paper[0], "one")
        self.assertEqual(paper[1], "two")
        self.assertEqual(paper[-1], "")
        p.clear()
        self.assertEqual(p.paper(), [])

    def test_never_busy(self):
        p = ReceiptPrinter(decode=False)
        p.write_bytes(b"x" * 100)
        self.assertFalse(p.is_busy())
        p.tick(10)
        self.assertFalse(p.is_busy())

    def test_transliteration_round_trip(self):
        """The firmware encoding must survive encode -> decode."""
        words = ["КАССА", "ИТОГ", "НАЛИЧНЫЕ", "СКИДКА", "СПАСИБО",
                 "КОЛИЧЕСТВО", "ВОЗВРАТ", "ФИСКАЛЬНЫЙ", "ПАРОЛЬ"]
        for word in words:
            decoded = decode_text(encode_text(word))
            # the firmware has a single byte for ч/щ/ъ/э/ю/ж/ш, so upper case
            # of those letters cannot survive the round trip
            self.assertEqual(decoded.upper(), word.upper(), word)

    def test_confirmed_letters_from_the_message_table(self):
        """Every letter of these strings is quoted from the recovered table."""
        self.assertEqual(decode_text(b"kontrolxnaq lenta"), "контрольная лента")
        self.assertEqual(decode_text(b"nali~nye w kasse"), "наличные в кассе")
        self.assertEqual(decode_text(b"wnesennaq summa"), "внесенная сумма")
        self.assertEqual(decode_text(b"teku}ij itog"), "текущий итог")
        self.assertEqual(decode_text(b"fiskalxnyi ot~et"), "фискальныи отчет")
        self.assertEqual(decode_text(b"konec"), "конец")
        self.assertEqual(decode_text(b"kassir"), "кассир")
        self.assertEqual(decode_text(b"wyru~ka"), "выручка")

    def test_raw_paper_keeps_the_original_bytes(self):
        p = ReceiptPrinter(decode=False)
        p.write_bytes(b"kassir\n")
        self.assertEqual(p.paper(), ["kassir"])

    # -- краевые случаи ленты: 0x0D quirk, NUL, пустой ввод, ширина --------
    def test_cr_quirk_returns_the_head_without_erasing(self):
        """0x0D возвращает голову в колонку 0; отпечатанное не теряется."""
        p = ReceiptPrinter(decode=False)
        p.write_bytes(b"\r")                      # CR по пустой строке
        self.assertEqual(p.paper(), [], "пустой ввод: CR не создаёт строк")
        p.write_bytes(b"A\x1B\rB\n")              # ESC глотает следующий CR
        self.assertEqual(p.raw_paper(), ["AB"])
        p2 = ReceiptPrinter(columns=4, decode=False)
        p2.write_bytes(b"AAAA\rB\n")              # CR после автопереноса
        self.assertEqual(p2.raw_paper(), ["AAAA", "B"])
        p3 = ReceiptPrinter(decode=False)
        p3.write_bytes(b"AB\r\rCD\n")             # двойной CR — no-op
        self.assertEqual(p3.raw_paper(), ["CD"])

    def test_nul_byte_never_reaches_the_tape(self):
        """0x00 (терминатор C-строки) не пробивает дыру в ленте."""
        p = ReceiptPrinter(decode=False)
        p.write_bytes(b"A\x00B\n")
        self.assertEqual(p.raw_paper(), ["AB"])
        self.assertEqual(p.bytes_written, 4, "NUL считается, но не печатается")

    def test_empty_input_produces_no_paper(self):
        p = ReceiptPrinter()
        p.write_bytes(b"")
        p.write_text("")
        p.feed(0)
        p.feed(-5)
        self.assertEqual(p.paper(), [])
        self.assertEqual(p.text(), "")
        self.assertFalse(p.is_busy())
        p.newline()                               # явная пустая строка — есть
        self.assertEqual(p.paper(), [""])

    def test_columns_width_is_clamped_to_at_least_one(self):
        for width in (0, -3):
            p = ReceiptPrinter(columns=width, decode=False)
            self.assertEqual(p.columns, 1, width)
            p.write_bytes(b"AB\n")
            self.assertEqual(p.raw_paper(), ["A", "B", ""], width)

    def test_koi8r_stream_renders_readable_russian(self):
        """Строки с 8-битными байтами — KOI8-R, а не latin-1 mojibake."""
        p = ReceiptPrinter()
        p.write_bytes("ДЕМО-ПРОГРАММА\n".encode("koi8-r"))
        self.assertEqual(p.paper(), ["ДЕМО-ПРОГРАММА"])
        self.assertEqual("".join(p.raw_paper()).encode("latin-1"),
                         "ДЕМО-ПРОГРАММА".encode("koi8-r"),
                         "raw_paper отдаёт исходные байты")
        # чисто-ASCII строки по-прежнему идут через транслит ПЗУ
        q = ReceiptPrinter()
        q.write_bytes(encode_text("ИТОГ\n"))
        self.assertEqual(q.paper(), ["ИТОГ"])


# ==========================================================================
class BoardRoutingTests(unittest.TestCase):
    def setUp(self):
        self.b = CashRegisterBoard()

    def test_ppi_windows_decode_to_one_chip(self):
        self.b.ext_write(0x0003, 0x89)          # control via window 1
        self.assertEqual(self.b.ppi.mode_a, 0)
        self.b.ext_write(0x000B, 0xA9)          # control via window 2 (mirror)
        self.assertEqual(self.b.ppi.mode_a, 1)
        self.b.ext_write(0x0003, 0x89)
        self.b.ext_write(0x0000, 0x3F)          # port A
        self.assertEqual(self.b.ppi.latch[PORT_A], 0x3F)
        self.assertEqual(self.b.ext_read(0x0008), 0x3F, "PA alias at 0x0008")

    def test_display_shows_what_ppi_writes(self):
        self.b.ext_write(0x0003, 0x89)
        self.b.ext_write(0x0001, 1 << 2)                       # digit 2
        self.b.ext_write(0x0000, SEG7["9"])
        self.assertEqual(self.b.display.text(), "  9     ")
        self.assertEqual(self.b.display.cell_segments(2), SEG7["9"])

    def test_display_data_first_order_also_works(self):
        b = CashRegisterBoard()
        b.ext_write(0x0003, 0x89)
        b.ext_write(0x0000, SEG7["3"])                         # data first
        b.ext_write(0x0001, 1 << 4)                            # then the digit
        self.assertEqual(b.display.text(), "    3   ")

    def test_keyboard_visible_through_ppi_port_c(self):
        self.b.ext_write(0x0003, 0x89)
        self.b.ext_write(0x0001, 1 << self.b.keyboard.row_of("5"))
        col = self.b.keyboard.col_of("5")
        self.assertEqual(self.b.ext_read(0x0002), 0xFF)
        self.b.keyboard.press("5")
        self.assertEqual(self.b.ext_read(0x0002), (~(1 << col)) & 0xFF)
        self.b.keyboard.release("5")
        self.assertEqual(self.b.ext_read(0x0002), 0xFF)

    def test_native_display_refresh_transaction(self):
        """Exactly the ROM sequence 0x8312/0x8317/0x831E."""
        b = CashRegisterBoard()
        b.ext_write(0x9200, 0x00)              # segment byte 1
        b.ext_write(0x8200, SEG7["8"])         # segment byte 0
        b.ext_write(0xA200, 0x01)              # grid select -> digit 1
        self.assertEqual(b.display.text(), " 8      ")
        self.assertEqual(b.display.grid, 1)

    def test_native_keyboard_read_uses_the_row_in_the_address(self):
        row = self.b.keyboard.row_of("X")
        self.b.keyboard.press("X")
        got = self.b.ext_read(0x9130 + row)
        self.assertEqual(got, (~(1 << self.b.keyboard.col_of("X"))) & 0xFF)
        self.assertEqual(self.b.ext_read(0x9100 + ((row + 1) % 8)), 0xFF)

    def test_native_printer_strobe_on_p34(self):
        b = CashRegisterBoard()
        b.ext_write(0x8131, ord("A"))
        self.assertEqual(b.printer.paper(), [], "data alone must not print")
        b.port_write(3, 0x10)                  # SETB P3.4
        self.assertEqual(b.printer.raw_paper(), ["A"])
        b.port_write(3, 0x00)                  # CLR P3.4
        b.ext_write(0x8131, ord("B"))
        self.assertEqual(b.printer.raw_paper(), ["A"])

    def test_printer_via_ppi_mode1(self):
        b = CashRegisterBoard()
        b.ext_write(0x0003, 0xA9)
        for ch in encode_text("OK"):
            b.ext_write(0x0000, ch)
        b.ext_write(0x0000, 0x0A)
        self.assertEqual(b.printer.raw_paper(), ["OK"])

    def test_ram_below_the_peripheral_window(self):
        self.b.ext_write(0x1B83, 0x5A)
        self.assertEqual(self.b.ext_read(0x1B83), 0x5A)
        self.assertEqual(self.b.ext_read(0x0042), 0xFF, "unmapped RAM reads FF")

    def test_motor_latch_and_lamp_readback(self):
        self.b.ext_write(0xB100, 0x0F)
        self.assertEqual(self.b.motor, 0x0F)
        self.b.ext_write(0xA103, 0x41)         # 0x40|gray(0)
        self.assertEqual(self.b.display.lamp_index, 0)
        self.assertTrue(self.b.ext_read(0xA100) & 0x80)

    def test_key_present_on_p13(self):
        b = CashRegisterBoard()
        self.assertEqual(b.port_read(1) & 0x08, 0, "no key -> P1.3 low")
        b.keyboard.press("1")
        self.assertEqual(b.port_read(1) & 0x08, 0x08, "key -> P1.3 high")
        b.keyboard.release("1")

    def test_int0_requested_on_key_event_and_expires(self):
        # Дефолтный wiring INT0 по нажатию НЕ поднимает (INT0 = линия питания,
        # см. WIRING): событие есть, импульса нет.
        b = CashRegisterBoard()
        b.keyboard.tap("9")
        self.assertEqual(b.irq_requested() & IRQ_INT0, 0,
                         "дефолт: INT0 не имитирует выключение по клавише")
        # Механизм импульса жив и включается явным wiring (на нём стоят
        # тесты EA-гейтинга ниже).
        b2 = CashRegisterBoard(wiring={"INT0_ON_KEYPRESS": True})
        self.assertEqual(b2.irq_requested() & IRQ_INT0, 0)
        b2.keyboard.tap("9")
        self.assertEqual(b2.irq_requested() & IRQ_INT0, IRQ_INT0)
        b2.tick(int(WIRING["INT0_HOLD_CYCLES"]) + 1)
        self.assertEqual(b2.irq_requested() & IRQ_INT0, 0)

    def test_tick_advances_and_status_reports(self):
        b = CashRegisterBoard()
        b.tick(1000)
        b.note_pc(0x8123)
        st = b.status()
        self.assertEqual(st["cycles"], 1000)
        self.assertEqual(st["pc"], 0x8123)
        self.assertIn("source", st)
        self.assertIsInstance(b.status_text(), str)

    def test_serial_round_trip(self):
        b = CashRegisterBoard()
        b.serial_write(0x41)
        self.assertEqual(list(b.serial_out), [0x41])
        self.assertFalse(b.serial_available())
        b.feed_serial([0x42])
        self.assertTrue(b.serial_available())
        self.assertEqual(b.serial_read(), 0x42)

    def test_self_test_true_shows_and_prints_without_faking(self):
        b = CashRegisterBoard(self_test=True)
        self.assertEqual(b.display.text(), "12345678")
        paper = b.printer.paper()
        self.assertIn("КАССА", paper)
        self.assertIn("СПАСИБО!", paper)
        self.assertEqual(b.status()["source"], "self-test")

    def test_self_test_false_leaves_everything_blank(self):
        b = CashRegisterBoard()
        self.assertEqual(b.display.text().strip(), "")
        self.assertEqual(b.printer.paper(), [])

    def test_ext_probe(self):
        self.assertTrue(self.b.ext_probe(0x0001))
        self.assertTrue(self.b.ext_probe(0x8200))
        self.assertFalse(self.b.ext_probe(0x1000))

    # -- handshake PPI 8255 на шине ---------------------------------------
    def test_mode1_input_status_keeps_matrix_on_free_pins(self):
        """Mode 1 (вход): IBF/STB — статус, PC6/PC7 всё ещё клавиатура."""
        b = CashRegisterBoard()
        b.ext_write(0x0003, 0xB9)                # group A mode 1, A input
        b.ppi.notify_stb(PORT_A, 0x33)           # /STB: данные защёлкнуты
        status = b.ext_read(0x0002)
        self.assertEqual(status & 0x20, 0x20, "IBF выставлен")
        self.assertEqual(status & 0x10, 0, "/STB отпущен")
        b.keyboard.press("00")                   # строка 0, колонка 7 -> PC7
        status = b.ext_read(0x0002)
        self.assertEqual(status & 0x80, 0,
                         "PC6/PC7 в mode 1 input — свободные пины: тут матрица")
        self.assertEqual(status & 0x20, 0x20, "IBF не сбит чтением матрицы")
        b.keyboard.release("00")

    def test_mode1_output_status_and_bsr_through_the_window(self):
        """Mode 1 (выход): /OBF на статусе, INTE взводится BSR через 0x0003."""
        b = CashRegisterBoard()
        b.ext_write(0x0003, 0xA9)                # group A mode 1, A output
        b.keyboard.press("7")                    # строка 0, колонка 0 -> PC0
        value = b.ext_read(0x0002)
        self.assertEqual(value & 0x01, 0, "PC0 свободен -> матрица видна")
        self.assertEqual(value & 0x80, 0x80, "/OBF idle high")
        self.assertEqual(value & 0x10, 0, "INTE ещё не взведён")
        b.ext_write(0x0003, 0x09)                # BSR: PC4 = INTE A
        value = b.ext_read(0x0002)
        self.assertEqual(value & 0x10, 0x10, "INTE читается обратно с PC4")
        b.keyboard.release("7")

    # -- самотест (self_test) ----------------------------------------------
    def test_self_test_disarms_the_stale_printer_strobe(self):
        b = CashRegisterBoard(self_test=True)
        self.assertFalse(b._print_pending,
                         "самотест не оставляет взведённый строб")
        before = b.printer.raw_paper()
        b.port_write(3, 0x00)                    # CLR P3.4
        b.port_write(3, 0x10)                    # SETB P3.4 без свежих данных
        self.assertEqual(b.printer.raw_paper(), before,
                         "фантомный строб не должен печатать байт")
        self.assertFalse(b._print_pending)

    def test_self_test_twice_keeps_one_screen(self):
        b = CashRegisterBoard()
        b.run_self_test()
        lines = len(b.printer.paper())
        self.assertEqual(b.display.text(), "12345678")
        self.assertEqual(lines, 7, "чек самотеста — 7 строк")
        b.run_self_test()
        self.assertEqual(b.display.text(), "12345678",
                         "экран самотеста идемпотентен")
        self.assertEqual(len(b.printer.paper()), 2 * lines,
                         "бумага копится, как на настоящей ленте")

    # -- крайние значения: переполнение денег и BCD > 9 --------------------
    def test_display_overflow_past_eight_digits_keeps_the_frame(self):
        b = CashRegisterBoard()
        for i in range(8):
            b.ext_write(0x8200, SEG7["8"])
            b.ext_write(0xA200, i)
        b.ext_write(0x8200, SEG7["9"])           # 9-й разряд money-поля
        b.ext_write(0xA200, 8)                   # переполнение -> гашение
        self.assertEqual(b.display.text(), "88888888",
                         "переполнение не портит уже отрисованный кадр")
        self.assertEqual(b.display.grid, -1)

    def test_invalid_bcd_codes_do_not_reach_the_digits(self):
        b = CashRegisterBoard()
        b.ext_write(0x8200, SEG7["1"])
        b.ext_write(0xA200, 0)
        for code in (0x0A, 0x0B, 0x99, 0xFF):    # BCD > 9 / мусор
            b.ext_write(0xA200, code)
            self.assertEqual(b.display.grid, -1, hex(code))
        b.display.write_digit_byte(0x0A, SEG7["7"])   # индекс = BCD 10
        self.assertEqual(b.display.text(), "1       ",
                         "ячейка с недопустимым индексом не тронута")
        b.display.write_lamp(0x00)
        self.assertEqual(b.display.annunciators(),
                         {"bank1": 0, "bank2": 0, "bank3": 0})

    def test_clock_bcd_bytes_are_stored_verbatim(self):
        """Плата хранит BCD-байты RTC как есть (в т.ч. недопустимые > 9)."""
        b = CashRegisterBoard()
        rtc = int(WIRING["RTC_BASE"])
        values = (0x99, 0xFF, 0x00, 0x25)
        for i, v in enumerate(values):
            b.ext_write(rtc + i, v)
        self.assertEqual([b.ext_read(rtc + i) for i in range(4)], list(values))
        # граница ОЗУ: 0x7FFF — RAM (probe=False), 0x8000 — периферия
        b.ext_write(0x7FFF, 0x42)
        self.assertEqual(b.ext_read(0x7FFF), 0x42)
        self.assertFalse(b.ext_probe(0x7FFF))
        self.assertTrue(b.ext_probe(0x8000))

    def test_keyboard_row_address_above_seven_is_masked(self):
        """Младший байт адреса «BCD 10» (0x3A) маскируется в строку 0..7."""
        b = CashRegisterBoard()
        self.assertEqual(b.ext_read(0x913A), b.ext_read(0x9132))
        b.keyboard.press("1")                    # строка 2, колонка 0
        self.assertEqual(b.ext_read(0x913A), (~(1 << 0)) & 0xFF)
        b.keyboard.release("1")

    def test_empty_firmware_streams_leave_the_board_quiet(self):
        b = CashRegisterBoard()
        b.serial_read()
        b.feed_serial([])
        self.assertIsNone(b.serial_read())
        self.assertFalse(b.serial_available())
        self.assertEqual(b.keyboard.read_columns(-1), 0xFF)
        self.assertEqual(b.keyboard.read_columns(8), 0xFF)
        self.assertEqual(b.status()["printer_lines"], 0)
        self.assertEqual(b.display.text(), " " * 8)


# ==========================================================================
class FirmwareEvidenceTests(unittest.TestCase):
    """The wiring above must be traceable to bytes of the real firmware."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(ROM_PATH):
            raise unittest.SkipTest("firmware dump not available")
        cls.rom = ROM("nm27c512n").load_file(ROM_PATH)

    def test_digit_select_table_in_rom_is_gray_coded(self):
        self.assertEqual(self.rom.get_slice(0x8266, 8), b"AIHLDFBC")
        self.assertEqual(self.rom.get_slice(0x8203, 8), b"AIHLDFBC")

    def test_fun_810f_writes_the_a1_page(self):
        self.assertEqual(disassemble_one(self.rom, 0x810F)[0], "MOV    DPH,#A1h")
        self.assertEqual(disassemble_one(self.rom, 0x8112)[0], "MOVX   @DPTR,A")

    def test_refresh_writes_pages_92_82_a2(self):
        self.assertEqual(disassemble_one(self.rom, 0x830F)[0], "MOV    DPH,#92h")
        self.assertEqual(disassemble_one(self.rom, 0x8314)[0], "MOV    DPH,#82h")
        self.assertEqual(disassemble_one(self.rom, 0x831B)[0], "MOV    DPH,#A2h")

    def test_keyboard_row_read_is_active_low(self):
        self.assertEqual(disassemble_one(self.rom, 0x8393)[0], "MOV    DPH,#91h")
        self.assertEqual(disassemble_one(self.rom, 0x8398)[0], "MOVX   A,@DPTR")
        self.assertEqual(disassemble_one(self.rom, 0x8399)[0], "CPL    A")

    def test_printer_data_port_and_strobe(self):
        self.assertEqual(self.rom.get_slice(0x81E7, 3).hex().upper(), "758231")
        self.assertEqual(disassemble_one(self.rom, 0x81F3)[0], "MOV    DPH,#81h")
        self.assertEqual(disassemble_one(self.rom, 0x81F7)[0], "SETB   P3.4")
        self.assertEqual(disassemble_one(self.rom, 0x83F8)[0], "CLR    P3.4")

    def test_ppi_mode_words_are_in_the_rom(self):
        # 0xB27A: MOV A,#89h / JNB 3Ch,+2 / MOV A,#0A9h / MOVX @R1,A
        self.assertEqual(self.rom.get_slice(0xB27A, 8).hex().upper(),
                         "7489303C0274A9F3")
        self.assertEqual(disassemble_one(self.rom, 0xB278)[0], "MOV    R1,#0Bh")

    def test_timer_reload_table_and_tmod(self):
        # 0x821F: MOV A,R5 ; RL A ; ADD A,#74h ; MOVC A,@A+PC ; MOV TL1,A
        self.assertEqual(self.rom.get_slice(0x8224, 2).hex().upper(), "F58B")
        self.assertEqual(self.rom.get_slice(0x822B, 2).hex().upper(), "F58D")
        self.assertEqual(self.rom.get_slice(0x8297, 5).hex().upper(), "01E2FC65FC")
        # TMOD = 0x11 (both timers mode 1) at 0x8A20 and 0xDAE9
        self.assertEqual(self.rom.get_slice(0x8A20, 3).hex().upper(), "758911")
        self.assertEqual(self.rom.get_slice(0xDAE9, 3).hex().upper(), "758911")

    def test_key_ring_buffer_and_rtc_addresses(self):
        # 0x83E0: MOV DPH,#0Ch ; MOV DPL,4Fh ; MOVX @DPTR,A
        self.assertEqual(self.rom.get_slice(0x83E0, 8).hex().upper(),
                         "75830C854F82CDF0")
        # 0x832B: MOV DPTR,#0CB0h ; MOVX A,@DPTR ; ADD A,#01h ; DA A ; CJNE A,#60h
        self.assertEqual(self.rom.get_slice(0x832B, 9).hex().upper(), "900CB0E02401D4B460")


# ==========================================================================
class IntegrationTests(unittest.TestCase):
    """A hand-assembled 8051 program drives the board through real MOVX/port
    instructions, using LCALL/RET (push_pc regression) and CJNE/RET."""

    def build(self, key_pressed: bool):
        a = Asm()
        a.mov_dptr(0x0003)          # PPI control
        a.mov_a(0x89)               # mode 0: A/B out, C in
        a.movx_dptr_a()
        a.mov_r0(0x00)
        a.mov_dptr(0x0001)          # port B = digit 0
        a.mov_a(0x01)
        a.movx_dptr_a()
        a.mov_dptr(0x0000)          # port A = segments
        a.mov_a(SEG7["4"])
        a.movx_dptr_a()
        a.mov_dptr(0x0001)
        a.mov_a(0x02)               # port B = digit 1
        a.movx_dptr_a()
        a.mov_dptr(0x0000)
        a.mov_a(SEG7["2"])
        a.movx_dptr_a()
        a.lcall("print")            # <- subroutine call + RET
        a.cjne_a_imm(0x5A, "after")  # CJNE: equal -> fall through
        a.mov_a(0x00)               # wrong branch lands here
        a.label("after")
        a.mov_dptr(0x0002)          # read keyboard columns (port C)
        a.movx_a_dptr()
        a.jb_acc(0, "nokey")        # bit0 high -> not pressed
        a.mov_dptr(0x0000)
        a.mov_a(0x2A)               # '*' via port A (mode 1 -> printer)
        a.movx_dptr_a()
        a.mov_a(0x0A)
        a.movx_dptr_a()
        a.label("nokey")
        a.mov_a(0x5A)               # marker proves the RET came home
        a.halt()
        a.label("print")
        a.mov_dptr(0x0003)
        a.mov_a(0xA9)               # printer mode
        a.movx_dptr_a()
        a.mov_dptr(0x0000)
        for byte in encode_text("ИТОГ\n"):
            a.mov_a(byte)
            a.movx_dptr_a()
        a.ret()
        return a.assemble()

    def run_program(self, key_pressed: bool):
        board = CashRegisterBoard()
        if key_pressed:
            # the program leaves port B = 0x02, i.e. keyboard row 1, so press a
            # key from that row ("4" is row 1, column 0)
            board.keyboard.press("4")
        cpu = make_cpu(self.build(key_pressed), board)
        for _ in range(400):
            if cpu.error:
                break
            cpu.step()
        return cpu, board

    def test_lcall_ret_returns_to_the_instruction_after_the_call(self):
        cpu, board = self.run_program(False)
        self.assertIsNone(cpu.error)
        self.assertEqual(cpu.acc, 0x5A,
                         "A must hold the marker set AFTER the LCALL returned")

    def test_display_shows_the_two_digits_the_program_wrote(self):
        _cpu, board = self.run_program(False)
        self.assertEqual(board.display.text(), "42      ")

    def test_subroutine_printed_the_line_through_the_real_printer_port(self):
        _cpu, board = self.run_program(False)
        self.assertEqual(board.printer.paper(), ["ИТОГ"])
        self.assertEqual(board.display.text(), "42      ",
                         "printing must not disturb the display")

    def test_keyboard_key_is_seen_by_the_program(self):
        _cpu, board = self.run_program(False)
        self.assertNotIn("*", board.printer.text())
        cpu, board = self.run_program(True)
        self.assertIn("*", board.printer.raw_paper()[-1])

    def test_cjne_equal_falls_through(self):
        cpu, _board = self.run_program(False)
        self.assertEqual(cpu.acc, 0x5A, "CJNE A,#5Ah with A==0x5A must not branch")


# ==========================================================================
class InterruptGatingTests(unittest.TestCase):
    """EA-гейтинг ядра (m8051/cpu.py) x INT0 платы.

    Плата умеет поднять INT0 на событии клавиатуры, но дефолтный wiring этого
    не делает (INT0 = линия отключения питания, см. WIRING) - тесты включают
    `wiring={"INT0_ON_KEYPRESS": True}` явно, чтобы проверить саму разводку:
    ядро поллит ``bus.irq_requested()`` только при IE.7=1 и принимает
    источник только при IE.0=1. Регрессионная страховка после введения
    EA-гейтинга в run/run_steps: ISR обязан просыпаться при EA+EX0 и
    обязан НЕ просыпаться, когда хоть один бит не выставлен.
    """

    @staticmethod
    def _image(ie_value: int) -> bytes:
        img = bytearray(0x50)
        img[0:3] = bytes([0x02, 0x00, 0x30])    # 0000: LJMP main
        img[3:6] = bytes([0x02, 0x00, 0x40])    # 0003: LJMP isr (вектор INT0)
        img[0x30:0x36] = bytes([
            0x74, 0x11,                         # MOV A,#11h  (marker main)
            0x75, 0xA8, ie_value,               # MOV IE,#<ie>
            0x80, 0xFE,                         # SJMP $ (холостой цикл)
        ])
        img[0x40:0x43] = bytes([
            0x74, 0x77,                         # MOV A,#77h  (marker ISR)
            0x32,                               # RETI
        ])
        return bytes(img)

    def _run_with_key(self, ie_value: int):
        board = CashRegisterBoard(wiring={"INT0_ON_KEYPRESS": True})
        rom = ROM("ea-gate")
        rom.load_block(0x0000, self._image(ie_value))
        cpu = CPU8051(rom, board)
        cpu.run_steps(6)                        # main: A=11h, IE=..., цикл
        self.assertIsNone(cpu.error)
        self.assertEqual(cpu.acc, 0x11)
        board.keyboard.tap("9")                 # событие -> INT0 платы
        cpu.run_steps(40)
        self.assertIsNone(cpu.error)
        return cpu

    def test_int0_from_the_board_is_serviced_when_ea_is_set(self):
        cpu = self._run_with_key(0x81)           # IE = EA | EX0 (IE.7|IE.0)
        self.assertEqual(cpu.acc, 0x77,
                         "ISR должен просыпаться от INT0 платы при EA=1")

    def test_int0_stays_masked_when_ea_is_clear(self):
        cpu = self._run_with_key(0x01)           # IE = EX0, EA = 0
        self.assertEqual(cpu.acc, 0x11,
                         "при EA=0 поллинг платы не должен будить ISR")

    def test_int0_stays_masked_when_ex0_is_clear(self):
        cpu = self._run_with_key(0x80)           # IE = EA, EX0 = 0
        self.assertEqual(cpu.acc, 0x11,
                         "без IE.0 (EX0) собственное битовое разрешение не пускает")


# ==========================================================================
class ThreadSafetyTests(unittest.TestCase):
    def test_key_press_from_another_thread_is_visible_to_the_next_scan(self):
        board = CashRegisterBoard()
        seen = []
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                seen.append(board.display.text())

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            for i in range(300):
                board.keyboard.tap("1")
                board.ext_write(0x0003, 0x89)
                board.ext_write(0x0001, 1 << (i % 8))
                board.ext_write(0x0000, SEG7[str(i % 10)])
                board.keyboard.release("1")
                board.tick(100)
                self.assertIsInstance(board.display.text(), str)
                self.assertIsInstance(board.printer.paper(), list)
        finally:
            stop.set()
            t.join(timeout=5)
        self.assertTrue(seen, "the reader thread must observe snapshots")

    def test_tap_survives_until_the_firmware_polls(self):
        board = CashRegisterBoard()
        board.keyboard.tap("5")
        row = board.keyboard.row_of("5")
        col = board.keyboard.col_of("5")
        self.assertEqual(board.ext_read(0x9130 + row), (~(1 << col)) & 0xFF)
        board.tick(board.keyboard.tap_cycles + 1)
        self.assertEqual(board.ext_read(0x9130 + row), 0xFF)


if __name__ == "__main__":
    unittest.main(verbosity=2)
