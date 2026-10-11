"""Hardware model of the AO "ETIM" cash register, assembled on an 8051 bus.

Every pin assignment lives in the :data:`WIRING` block below so it can be
retuned in one place.  The defaults come from the reverse engineering in
``docs/hardware_analysis.md`` and ``docs/hardware_from_pseudocode.md``; each
entry is marked CONFIRMED (quoted ROM/C evidence), HYPOTHESIS (best guess) or
DEMO (an interface the board offers for the demo firmware).

External (``MOVX``) map
-----------------------
===============  =====================================================
address          device
===============  =====================================================
0x0000-0x0003    8255 PPI window 1: PA, PB, PC, CTRL      (HYPOTHESIS)
0x0008-0x000B    8255 PPI window 2 (mirror, same chip)    (HYPOTHESIS)
0x0000-0x7FFF    external RAM (data + key ring buffer)
0x8100-0x81FF    printer data latch (native path)
0x8200-0x82FF    display segment byte 0 (7 segments + dp)
0x9100-0x91FF    keyboard column read, row = low 3 bits of the address
0x9200-0x92FF    display segment byte 1 (extra segments)
0xA100-0xA1FF    display digit/annunciator byte (digit = low 3 bits)
0xA200-0xA2FF    display grid select (0..7 active, 8 = blank)
0xB100-0xB1FF    printer/aux motor phase latch (0x0F / 0x0E)
===============  =====================================================
"""

from __future__ import annotations

import collections
import threading
from typing import Deque, Dict, List, Optional

from m8051.bus import (
    HardwareBus,
    IRQ_INT0,
    IRQ_INT1,
    IRQ_RX,
    IRQ_T0,
    IRQ_T1,
    IRQ_TX,
)

from board.display import SEG7, Display
from board.keyboard import Keyboard
from board.ppi8255 import CTRL, PORT_A, PORT_B, PORT_C, PPI8255
from board.printer import ReceiptPrinter, encode_text

__all__ = ["CashRegisterBoard", "WIRING"]


# ==========================================================================
#  W I R I N G   B L O C K
#  Single source of truth for every address, page and bit the board decodes.
#  Retune here; nothing below this block hard-codes a pin.
# ==========================================================================
WIRING: Dict[str, object] = {
    # ---------------------------------------------------------------- 8255
    # The only *quoted* evidence is
    #   FUN_CODE_b469: DAT_EXTMEM_0009 = 0x89; ... DAT_EXTMEM_0009 = 0xa9;
    #   FUN_CODE_b274: DAT_EXTMEM_000b = 0x89; ... DAT_EXTMEM_000b = 0xa9;
    # and the ROM bytes 0xB27A..0xB281 = 74 89 30 3C 02 74 A9 F3
    # (MOV A,#89h / JNB 3Ch,+2 / MOV A,#0A9h / MOVX @R1,A) which are 8255
    # mode-set words.  The register base is a HYPOTHESIS: docs/architecture.md
    # says 0x0000..0x0003, the firmware writes through R1 = 0x0B with P2
    # unresolved, so both windows are decoded onto one PPI.
    "PPI_BASE": 0x0000,                 # HYPOTHESIS (docs/architecture.md)
    "PPI_MIRROR_BASES": (0x0008,),      # HYPOTHESIS (R1 = 0x0B in ROM)
    "PPI_MODE_WORD_DISPLAY": 0x89,      # C L1109/L850 - group A mode 0
    "PPI_MODE_WORD_PRINTER": 0xA9,      # C L1111/L852 - group A mode 1
    "PPI_A_MEANING": "segments",        # DEMO: "segments" (7-seg mask) | "chars"
    "PPI_B_MEANING": "onehot",          # DEMO: "onehot" (bit i) | "binary"
    "PPI_C_IS_KEYBOARD": True,          # DEMO: port C = column byte

    # ------------------------------------------------------- display (native)
    # CONFIRMED: ROM 0x8309..0x831E
    #   830F MOV DPH,#92h / 8312 MOVX @DPTR,A   (segment byte 1)
    #   8314 MOV DPH,#82h / 8317 MOVX @DPTR,A   (segment byte 0)
    #   8319 ANL A,#07h / 831B MOV DPH,#0A2h / 831E MOVX @DPTR,A (grid)
    #   C L611: FUN_CODE_810f(*(byte *)((param_2 + 0x1c) + 0x824a) | ...)
    "DISPLAY_SEG0_PAGE": 0x82,
    "DISPLAY_SEG1_PAGE": 0x92,
    "DISPLAY_GRID_PAGE": 0xA2,
    "DISPLAY_GRID_BLANK": 0x08,         # ROM 0x82E1: MOV A,#08h -> 0xA2
    "DISPLAY_DIGIT_PAGE": 0xA1,         # FUN_CODE_810f: CONCAT11(0xa1,index)
    "DISPLAY_DIGITS": 8,                # param_3 clamped 0..7 (C L411-419)
    "DISPLAY_LINES": 1,
    # ROM 0x8266 holds "AIHLDFBC" = 0x41 0x49 0x48 0x4C 0x44 0x46 0x42 0x43,
    # i.e. 0x40 | gray(i): a *selector*, not a segment pattern.
    "DISPLAY_A1_GRAY_IS_LAMP": True,
    "SEGMENT_ROM_TABLE": 0x8266,        # digit-select/segment table found in ROM

    # ------------------------------------------------------ keyboard (native)
    # CONFIRMED: ROM 0x838B..0x8398 - row = R0 & 7, read MOVX from DPH:R1
    # with the row in the low address byte and active-low columns (CPL A).
    "KEYBOARD_READ_PAGE": 0x91,
    "KEYBOARD_READ_BASE": 0x9130,       # low byte = row index (0..7)
    "KEYBOARD_ROWS": 8,
    "KEYBOARD_COLS": 8,
    "KEYBOARD_ACTIVE_LOW": True,

    # ------------------------------------------------------- printer (native)
    # CONFIRMED: ROM 0x81F3 MOV DPH,#81h / 0x81F6 MOVX @DPTR,A  then
    # 0x81F7 SETB P3.4; released by 0x83F8 CLR P3.4 in the ISR epilogue
    # (C L618-626: FUN_CODE_83f0 { EA = 1; T0 = 0; } where Ghidra's T0 = P3.4).
    "PRINTER_DATA_PAGE": 0x81,
    "PRINTER_DATA_IS_DOTS": False,      # DEMO: native path sends character bytes
    "PRINTER_STROBE_PORT": 3,
    "PRINTER_STROBE_BIT": 4,            # P3.4, active high pulse
    "PRINTER_BUSY_PORT": 1,
    "PRINTER_BUSY_BIT": 3,              # P1.3 low = ready (HYPOTHESIS)
    "PRINTER_BUSY_ACTIVE_LOW": True,
    "PRINTER_COLUMNS": 40,
    "PRINTER_BUSY_CYCLES": 0,           # never wedge the firmware

    # --------------------------------------------------------- other devices
    "MOTOR_PAGE": 0xB1,                 # ROM 0x840D/0x841A write 0x0F / 0x0E
    "MOTOR_PHASES": (0x0F, 0x0E),       # HYPOTHESIS: stepper/carriage phases
    "RAM_LIMIT": 0x8000,                # XDATA below this is plain RAM
    "KEY_RING_LO": 0x0C80,              # ROM 0x83E0 key ring buffer
    "KEY_RING_HI": 0x0C9F,
    "RTC_BASE": 0x0CB0,                 # ROM 0x832B: sec/min/hour, BCD

    # ------------------------------------------------------------ senses
    # C L464: cVar1 = P1_3; if (cVar1 != '\0') { ... TCON &= 0x3f; ET1 = 0; }
    "KEY_PRESENT_PORT": 1,
    "KEY_PRESENT_BIT": 3,               # P1.3, active high
    "KEY_PRESENT_ACTIVE_HIGH": True,

    # -------------------------------------------------------- interrupts
    # DISPROVED as the key path (см. дизассемблинг настоящего вектора INT0,
    # CPU 0x0003 -> 0x04D1): обработчик гасит сетку индикатора, копирует
    # внутреннее ОЗУ 0x01..0x7F в XDATA 0x0BD1, пишет magic 0x55/0xAA в
    # батарейную область 0x83xx и навсегда замирает (SJMP $ при CPU 0x4DF,
    # EA выключен; при незаданном флаге 0x24.0 — сразу замирает). То есть
    # INT0 = линия ОТКЛЮЧЕНИЯ ПИТАНИЯ (save state -> halt), а не клавиатура:
    # подача INT0 по нажатию убивала бы кассу на каждое нажатие.
    # Механизм импульса сохранён и включается явно: wiring={"INT0_ON_KEYPRESS": True}
    # (тесты платы так и делают, проверяя саму разводку IRQ).
    "INT0_ON_KEYPRESS": False,
    "INT0_HOLD_CYCLES": 2_000,
    "EXTRA_IRQ": 0,
}

# handy named pages derived from the wiring block
_PPI_CTRL_ALIASES = tuple(
    [WIRING["PPI_BASE"] + CTRL]                                  # type: ignore[operator]
    + [b + CTRL for b in WIRING["PPI_MIRROR_BASES"]]            # type: ignore[union-attr]
)
#: every external address that decodes to an 8255 register (both windows,
#: including the control register), same PPI object.
_PPI_ALIASES: Dict[int, int] = {}
for _base in (WIRING["PPI_BASE"],) + tuple(WIRING["PPI_MIRROR_BASES"]):   # type: ignore[arg-type]
    for _reg in (PORT_A, PORT_B, PORT_C, CTRL):
        _PPI_ALIASES[_base + _reg] = _reg
_PPI_READ_ALIASES = _PPI_ALIASES


class CashRegisterBoard(HardwareBus):
    """The whole machine: PPI + display + keyboard + printer, on one bus.

    Thread safety
    -------------
    ``main.py`` runs the CPU on a daemon thread while Tk calls
    :meth:`Keyboard.tap` and reads ``display.text()`` / ``printer.paper()``.
    Every entry point here takes :attr:`_lock` (a re-entrant lock) and the
    :class:`~board.display.Display` has its own lock, so a key pressed from the
    GUI thread is visible to the very next port scan and string snapshots are
    consistent.
    """

    def __init__(
        self,
        display: Optional[Display] = None,
        keyboard: Optional[Keyboard] = None,
        printer: Optional[ReceiptPrinter] = None,
        wiring: Optional[Dict[str, object]] = None,
        self_test: bool = False,
        cpu=None,
    ) -> None:
        self._lock = threading.RLock()
        self.wiring: Dict[str, object] = dict(WIRING)
        if wiring:
            self.wiring.update(wiring)

        # PPI decode follows THIS instance's wiring.  A module-level alias map
        # would pin every board to one hypothesis; the real ETIM firmware
        # self-tests XDATA 0x0000..0x1FFF as plain RAM (four patterns + a
        # walking test over 256 blocks), so its 8255 windows must live
        # outside that range - see the evidence note on WIRING["PPI_BASE"].
        self._ppi_aliases: Dict[int, int] = {}
        _ppi_bases = (int(self.wiring["PPI_BASE"]),) + tuple(
            int(b) for b in self.wiring["PPI_MIRROR_BASES"]       # type: ignore[union-attr]
        )
        for _base in _ppi_bases:
            for _reg in (PORT_A, PORT_B, PORT_C, CTRL):
                self._ppi_aliases[(_base + _reg) & 0xFFFF] = _reg

        # Кэш «горячих» строк wiring: _ppi_port_a/_ppi_port_b зовутся на
        # КАЖДУЮ запись дисплея, и поиск по dict со строковым ключом там был
        # заметен (бенчмарк: цепь ext_write ~24% времени demo51).
        self._ppi_a_meaning = self.wiring["PPI_A_MEANING"]
        self._ppi_b_meaning = self.wiring["PPI_B_MEANING"]
        self._grid_blank = int(self.wiring["DISPLAY_GRID_BLANK"])

        self.display = display or Display(
            int(self.wiring["DISPLAY_DIGITS"]), int(self.wiring["DISPLAY_LINES"]))
        self.keyboard = keyboard or Keyboard()
        self.printer = printer or ReceiptPrinter(
            columns=int(self.wiring["PRINTER_COLUMNS"]),
            busy_cycles=int(self.wiring["PRINTER_BUSY_CYCLES"]),
        )
        self.ppi = PPI8255("main")

        # external RAM (0x0000 .. RAM_LIMIT-1) - sparse, reads back 0xFF
        self.ram: Dict[int, int] = {}
        self.ext: Dict[int, int] = {}          # unmapped-but-observed addresses

        self.cycles = 0
        self._cpu = cpu
        self._last_pc = 0
        self.source = "reset"
        self.motor = 0x00
        self.print_latch = 0x00
        self._print_pending = False
        self.busy = False
        self._busy_until = 0
        self._int0_hold = 0
        self._seen_events = self.keyboard.event_count
        self._port_latch = [0xFF, 0xFF, 0xFF, 0xFF]
        # "A" = the firmware writes display data before the digit select,
        # "B" = digit select first.  Latched from the first display event.
        self._ppi_order: Optional[str] = None
        self.serial_out: Deque[int] = collections.deque(maxlen=4096)
        self.serial_in: Deque[int] = collections.deque()
        self.writes: List[tuple] = []
        self.trace_limit = 4096

        # PPI port A/B/C are outputs for the demo firmware's mode word; the
        # keyboard drives port C pins.
        self._refresh_ppi_pins()

        if self_test:
            self.run_self_test()

    # ================================================================= time
    def tick(self, cycles: int) -> None:
        # Горячий путь: tick зовётся почти на каждой машинной инструкции
        # (см. tools/_bench.py: 200K+ вызовов за 266K инструкций), поэтому
        # здесь НЕ берётся общий замок: cycles/busy/_int0_hold пишет только
        # поток эмуляции, а GUI читает атомарными атрибутами.  Замок нужен
        # только там, где состояние реально разделяется (истечение тапа
        # клавиатуры — внутри Keyboard.tick).
        cycles = int(cycles)
        self.cycles += cycles
        if self._int0_hold > 0:
            self._int0_hold = max(0, self._int0_hold - cycles)
        if self._busy_until and self.cycles >= self._busy_until:
            self.busy = False
        self.printer.tick(cycles)
        self.keyboard.tick(cycles)

    def note_pc(self, pc: int) -> None:
        """Cheap hook so :meth:`status` can report the CPU's PC."""
        self._last_pc = int(pc) & 0xFFFF

    def attach_cpu(self, cpu) -> None:
        self._cpu = cpu

    # ====================================================== external memory
    def _is_ppi(self, addr: int) -> Optional[int]:
        return self._ppi_aliases.get(addr)

    def ext_write(self, addr: int, value: int) -> None:
        addr &= 0xFFFF
        value &= 0xFF
        with self._lock:
            self._record(addr, value, "w")
            reg = self._is_ppi(addr)
            if reg is not None:
                self.ppi.write(reg, value)
                if reg == PORT_A:
                    self._ppi_port_a(value)
                elif reg == PORT_B:
                    self._ppi_port_b(value)
                elif reg == PORT_C:
                    self._refresh_ppi_pins()
                return

            page = addr >> 8
            low = addr & 0xFF
            if addr < int(self.wiring["RAM_LIMIT"]):
                self.ram[addr] = value
                return
            if page == self.wiring["DISPLAY_SEG0_PAGE"]:
                self.display.latch_segments(low=value, high=None)
            elif page == self.wiring["DISPLAY_SEG1_PAGE"]:
                self.display.latch_segments(low=None, high=value)
            elif page == self.wiring["DISPLAY_GRID_PAGE"]:
                # ROM 0x831B: MOV DPH,#0A2h ; MOVX @DPTR,A - the *data* byte is
                # the grid number (R0 & 7), not the address low byte.
                self.display.select_grid(value, commit=True)
            elif page == self.wiring["DISPLAY_DIGIT_PAGE"]:
                self.display.write_digit_byte(low & 0x07, value)
            elif page == self.wiring["PRINTER_DATA_PAGE"]:
                self.print_latch = value
                self._print_pending = True
                if self.wiring["PRINTER_DATA_IS_DOTS"]:
                    self.printer.write_column(value)
            elif page == self.wiring["MOTOR_PAGE"]:
                self.motor = value
            elif page == self.wiring["KEYBOARD_READ_PAGE"]:
                pass                       # write-only decode, nothing latched
            else:
                self.ext[addr] = value

    def ext_read(self, addr: int, code: bool = False) -> int:
        addr &= 0xFFFF
        with self._lock:
            reg = self._is_ppi(addr)
            if reg is not None:
                self._refresh_ppi_pins()
                if reg == PORT_C:
                    return self._read_port_c()
                return self.ppi.read(reg)
            if addr < int(self.wiring["RAM_LIMIT"]):
                return self.ram.get(addr, 0xFF)
            page = addr >> 8
            low = addr & 0xFF
            key_page = self.wiring["KEYBOARD_READ_PAGE"]
            if page == key_page:
                row = (low - (int(self.wiring["KEYBOARD_READ_BASE"]) & 0xFF)) & 0xFF
                if int(self.wiring["KEYBOARD_READ_BASE"]) >> 8 != page:
                    row = low
                return self.keyboard.read_columns(row & 0x07)
            if page == self.wiring["DISPLAY_DIGIT_PAGE"]:
                return self.display.lamp_readback()
            if page == self.wiring["DISPLAY_SEG0_PAGE"]:
                return self.display.seg0
            if page == self.wiring["DISPLAY_SEG1_PAGE"]:
                return self.display.seg1
            if page == self.wiring["PRINTER_DATA_PAGE"]:
                return self.print_latch
            if page == self.wiring["MOTOR_PAGE"]:
                return self.motor
            return self.ext.get(addr, 0xFF)

    def ext_probe(self, addr: int) -> bool:
        addr &= 0xFFFF
        if self._is_ppi(addr) is not None:
            return True
        return addr >= int(self.wiring["RAM_LIMIT"])

    # ============================================================== PPI paths
    def _ppi_port_a(self, value: int) -> None:
        """Port A: display segments (mode 0) or a printer byte (mode 1).

        The display is written "digit select first, then data" (order B) or
        "data first, then digit select" (order A).  The order is latched from
        the very first display event of the session, after which both orders
        produce an exact per-digit frame buffer.
        """
        if self.ppi.mode_a == 1 and not self.ppi.ddr[PORT_A]:
            self.printer.write_byte(value)
            self.print_latch = value
            self.ppi.notify_ack(PORT_A)
            self.ppi.clear_intr(PORT_A)
            return
        if self._ppi_order is None:
            self._ppi_order = "A"
        if self._ppi_a_meaning == "chars":
            idx = self._ppi_digit()
            if idx >= 0:
                self.display.write_char(idx, value)
            return
        self.display.latch_segments(value, None)
        if self._ppi_order == "B":
            self.display.commit_grid()

    def _ppi_port_b(self, value: int) -> None:
        if self._ppi_order is None:
            self._ppi_order = "B"
        idx = self._ppi_digit(value)
        if idx < 0:
            self.display.select_grid(self._grid_blank, commit=False)
            return
        self.display.select_grid(idx, commit=(self._ppi_order == "A"))

    def _ppi_digit(self, value: Optional[int] = None) -> int:
        """Digit index selected by PPI port B (one-hot or binary)."""
        if value is None:
            value = self.ppi.latch[PORT_B] & 0xFF
            # in mode 1 there is no digit select on port B; keep the last one
            if self.ppi.mode_b == 1:
                return self.display.grid if self.display.grid is not None else -1
        if self._ppi_b_meaning == "binary":
            idx = value & 0x0F
        elif value == 0:
            return -1
        else:
            idx = -1
            for bit in range(8):
                if value & (1 << bit):
                    idx = bit
                    break
        if idx < 0 or idx >= self.display.digits:
            return -1
        return idx

    def _refresh_ppi_pins(self) -> None:
        """Drive the PPI's port C pins from the keyboard columns."""
        if not self.wiring["PPI_C_IS_KEYBOARD"]:
            return
        row = self.display.grid if self.display.grid >= 0 else 0
        self.ppi.set_pins(PORT_C, self.keyboard.read_columns(row))

    def _read_port_c(self) -> int:
        """Port C = keyboard columns, except where the PPI owns the pin.

        In mode 0 every bit that is programmed as an input sees the matrix
        (the firmware writes 0x89: "A out, B out, C in").  In mode 1/2 the
        *handshake* pins belong to the printer and keep the 8255 status value;
        the remaining pins are resolved through the port C direction bits -
        inputs still see the keyboard matrix, outputs read back the latch.
        The claimed set follows the real pin allocation:

        * mode 1, port A output - PC7 /OBF, PC6 /ACK, PC4 INTE, PC3 INTR;
        * mode 1, port A input  - PC5 IBF, PC4 /STB, PC3 INTR (PC6/PC7 stay
          general port C pins and keep the matrix);
        * mode 2                - PC7..PC3 are all handshake;
        * group B mode 1        - PC2..PC0 (ACK/OBF/INTR).
        """
        row = self.display.grid if self.display.grid >= 0 else 0
        cols = self.keyboard.read_columns(row)
        mode_a = self.ppi.mode_a
        if mode_a in (1, 2) or self.ppi.mode_b == 1:
            status = self.ppi.read(PORT_C)
            claimed = 0x00
            if mode_a == 2:
                claimed |= 0xF8                     # /OBF /ACK IBF /STB INTR
            elif mode_a == 1:
                if self.ppi.ddr[PORT_A] & 0xFF:     # port A input
                    claimed |= 0x38                 # IBF /STB INTR
                else:                               # port A output
                    claimed |= 0xD8                 # /OBF /ACK INTE INTR
            if self.ppi.mode_b == 1:
                claimed |= 0x07                     # group B handshake
            ddr = self.ppi.ddr[PORT_C]              # 1 = input
            free_in = (~claimed) & ddr & 0xFF       # matrix pins
            free_out = (~claimed) & ~ddr & 0xFF     # port C output latch
            return ((status & claimed) | (cols & free_in)
                    | (self.ppi.latch[PORT_C] & free_out)) & 0xFF
        mask = self.ppi.ddr[PORT_C]              # 1 = input
        return (self.ppi.latch[PORT_C] & ~mask & 0xFF) | (cols & mask)

    # ============================================================== ports
    def port_read(self, port: int) -> int:
        with self._lock:
            value = 0xFF
            if port == self.wiring["KEY_PRESENT_PORT"]:
                bit = int(self.wiring["KEY_PRESENT_BIT"])
                present = self.keyboard.any_pressed()
                if not self.wiring["KEY_PRESENT_ACTIVE_HIGH"]:
                    present = not present
                if present:
                    value |= 1 << bit
                else:
                    value &= ~(1 << bit) & 0xFF
            if port == self.wiring["PRINTER_BUSY_PORT"]:
                bit = int(self.wiring["PRINTER_BUSY_BIT"])
                busy = self.busy or self.printer.is_busy()
                if self.wiring["PRINTER_BUSY_ACTIVE_LOW"]:
                    if busy:
                        value &= ~(1 << bit) & 0xFF
                elif busy:
                    value |= 1 << bit
            return value & 0xFF

    def port_write(self, port: int, value: int) -> None:
        with self._lock:
            old = self._port_latch[port & 3]
            self._port_latch[port & 3] = value & 0xFF
            self.port_change(port & 3, old, value & 0xFF)

    def port_change(self, port: int, old: int, new: int) -> None:
        """Strobe edges.  NOTE: m8051/cpu.py calls port_write() only, so the
        board has to do its own edge detection here as well."""
        with self._lock:
            if port == int(self.wiring["PRINTER_STROBE_PORT"]):
                bit = int(self.wiring["PRINTER_STROBE_BIT"])
                was = (old >> bit) & 1
                now = (new >> bit) & 1
                # ROM 0x81F6/0x81F7: data byte, then SETB P3.4.  A strobe is
                # either a rising edge or the first time the line is raised
                # after fresh data was latched.
                if now and (not was or self._print_pending):
                    self._print_pending = False
                    if self.wiring["PRINTER_DATA_IS_DOTS"]:
                        self.printer.write_column(self.print_latch)
                    else:
                        self.printer.write_byte(self.print_latch)
                    self.ppi.notify_ack(PORT_A)

    # ============================================================ interrupts
    def irq_requested(self) -> int:
        """INT0/EXTRA interrupt lines currently raised by the board.

        INT0 is a **one-shot pulse per key event**, not a steady level: the
        CPU polls this method on *every instruction boundary*
        (``m8051/cpu.py::_poll_interrupts``), so a line that stayed high for
        ``INT0_HOLD_CYCLES`` would make the core re-vector to 0x0003 after
        each instruction and the ISR body would never execute its first
        instruction (level-triggered livlock - reproduced while regression
        sweeping the EA-gating change).  The first poll that observes the
        event consumes the request and the ISR runs exactly once per key
        event; ``tick()`` still decays a hold that was latched but never
        observed.  Only the CPU core and tests call this (``main.py`` does
        not), so consumption on observation cannot steal the event from a
        third-party reader.

        Hot path (tools/_bench.py): deliberately lock-free.  ``_int0_hold``
        and ``_seen_events`` are written only by the emulation thread (this
        method + ``tick``), every other read is an int/bool attribute or the
        wiring dict, which the GIL serves atomically; GUI threads only store
        ``keyboard.event_count`` (an int).
        """
        if (self.wiring["INT0_ON_KEYPRESS"]
                and self.keyboard.event_count != self._seen_events):
            self._seen_events = self.keyboard.event_count
            self._int0_hold = int(self.wiring["INT0_HOLD_CYCLES"])
        mask = 0
        if self._int0_hold > 0:
            mask |= IRQ_INT0
            self._int0_hold = 0            # pulse consumed by this poll
        if self.wiring["EXTRA_IRQ"]:
            mask |= int(self.wiring["EXTRA_IRQ"])
        return mask

    # ================================================================ serial
    def serial_write(self, byte: int) -> None:
        with self._lock:
            self.serial_out.append(byte & 0xFF)

    def serial_read(self) -> Optional[int]:
        with self._lock:
            return self.serial_in.popleft() if self.serial_in else None

    def serial_available(self) -> bool:
        with self._lock:
            return bool(self.serial_in)

    def feed_serial(self, data) -> None:
        """Test/UI hook: bytes the UART will receive."""
        with self._lock:
            for b in data:
                self.serial_in.append(int(b) & 0xFF)

    # ============================================================ self test
    def run_self_test(self) -> None:
        """Drive the *real* port interface so the emulated hardware is visible.

        Everything below goes through :meth:`ext_write`, i.e. exactly the path
        the CPU uses; nothing pokes ``display``/``printer`` directly.  Only run
        when explicitly requested (``CashRegisterBoard(self_test=True)``) so
        nothing is faked silently.

        Hardened corners: the digit loop stops at the display's real width
        (``display.digits == 0`` renders nothing instead of crashing), running
        the test twice rewrites every digit (the screen is idempotent), and
        the final latch write to the printer page is disarmed
        (``_print_pending`` cleared) so a later P3.4 edge from the firmware
        cannot print a phantom byte out of the self-test.
        """
        with self._lock:
            self.source = "self-test"
            base = int(self.wiring["PPI_BASE"])
            seg0 = int(self.wiring["DISPLAY_SEG0_PAGE"]) << 8
            grid = int(self.wiring["DISPLAY_GRID_PAGE"]) << 8
            prn = int(self.wiring["PRINTER_DATA_PAGE"]) << 8
            ctrl = base + CTRL

            self.ext_write(ctrl, int(self.wiring["PPI_MODE_WORD_DISPLAY"]))
            self.ext_write(seg0, 0)
            self.ext_write(grid, int(self.wiring["DISPLAY_GRID_BLANK"]))
            # digits only: a 7-segment font cannot render M/W/T faithfully
            for i, ch in enumerate("12345678"):
                if i >= self.display.digits:
                    break
                self.ext_write(base + PORT_A, SEG7.get(ch, 0x00))
                self.ext_write(base + PORT_B, 1 << i)
            self.ext_write(seg0, 0)

            self.ext_write(ctrl, int(self.wiring["PPI_MODE_WORD_PRINTER"]))
            for line in ("КАССА",
                         "--------------------",
                         "1 Х 12.34      12.34",
                         "ИТОГ           12.34",
                         "СКИДКА 0%  БЕЗНАЛИЧН",
                         "--------------------",
                         "СПАСИБО!"):
                for b in encode_text(line + "\n"):
                    self.ext_write(base + PORT_A, b)
            self.ext_write(ctrl, int(self.wiring["PPI_MODE_WORD_DISPLAY"]))
            self.ext_write(prn, 0)
            # The latch write above sets _print_pending; disarm it so a stale
            # P3.4 edge raised later by the firmware prints nothing new.
            self._print_pending = False
            self.print_latch = 0

    # ========================================================= diagnostics
    def _record(self, addr: int, value: int, kind: str) -> None:
        self.writes.append((self.cycles, kind, addr, value))
        # Пакетная усечка: трим по одному элементу после заполнения стоил
        # memmove всего списка (O(trace_limit)) на КАЖДУЮ запись — срезаем
        # пачкой, когда переполнение уже велико (бенчмарк tools/_bench.py).
        n = len(self.writes)
        if n > self.trace_limit + 512:
            del self.writes[: n - self.trace_limit]

    def status(self) -> Dict[str, object]:
        """State for the UI status bar (contract extension, optional)."""
        with self._lock:
            pc = self._last_pc
            if self._cpu is not None:
                try:
                    pc = int(self._cpu.pc) & 0xFFFF
                except Exception:            # pragma: no cover - CPU not ready
                    pc = self._last_pc
            return {
                "cycles": int(self.cycles),
                "pc": pc,
                "source": self.source,
                "ppi": self.ppi.control,
                "ppi_mode_a": self.ppi.mode_a,
                "grid": self.display.grid,
                "keys": self.keyboard.pressed_keys(),
                "printer_lines": len(self.printer.paper()),
                "motor": self.motor,
                "serial_out": len(self.serial_out),
                "ram_writes": len(self.ram),
                "text": self.display.text(),
            }

    def status_text(self) -> str:
        st = self.status()
        return (f"{st['source']} cyc={st['cycles']} pc={st['pc']:04X} "
                f"PPI=0x{st['ppi']:02X} grid={st['grid']} "
                f"'{st['text']}' keys={','.join(st['keys']) or '-'}")

    def describe(self) -> str:
        with self._lock:
            return (f"CashRegisterBoard: {self.display.describe()}; "
                    f"{self.keyboard.describe()}; {self.printer.describe()}; "
                    f"{self.ppi.describe()}")

    def reset(self) -> None:
        with self._lock:
            self.ppi.reset()
            self.display.clear()
            self.printer.clear()
            self.keyboard.clear()
            self.ram.clear()
            self.ext.clear()
            self.motor = 0
            self.print_latch = 0
            self._int0_hold = 0
            self._seen_events = self.keyboard.event_count
            self._port_latch = [0xFF] * 4
            self.source = "reset"
