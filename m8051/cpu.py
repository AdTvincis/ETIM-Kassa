"""Intel MCS-51 (8051) / Atmel AT89C55 processor core.

Design notes
------------
* 12 clocks per machine cycle is assumed (``XTAL / 12``), so every T-state in
  this file is one machine cycle and the natural clock is 1 MHz for a 12 MHz
  crystal.
* Code space is an external :class:`~m8051.rom.ROM`; there is no distinction
  between internal and external fetch, which matches the 8051's unified
  Harvard code space and lets 64 KiB images (27C512) run unmodified.
* Direct addressing above 0x7F hits the SFR space, indirect addressing always
  hits the 256-byte internal RAM - exactly as on real silicon.
* Port latches are kept here, pin levels come from the :class:`HardwareBus`.
"""

from __future__ import annotations

from typing import List, Optional

from .bus import HardwareBus, IRQ_INT0, IRQ_INT1, IRQ_RX, IRQ_T0, IRQ_T1, IRQ_TX, NullBus
from .rom import ROM

__all__ = ["CPU8051"]

# --------------------------------------------------------------------- SFR map
SFR_P0, SFR_SP, SFR_DPL, SFR_DPH, SFR_PCON = 0x80, 0x81, 0x82, 0x83, 0x87
SFR_TCON, SFR_TMOD, SFR_TL0, SFR_TL1, SFR_TH0, SFR_TH1 = 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D
SFR_P1 = 0x90
SFR_SCON, SFR_SBUF = 0x98, 0x99
SFR_P2 = 0xA0
SFR_IE = 0xA8
SFR_P3 = 0xB0
SFR_IP = 0xB8
SFR_PSW = 0xD0
SFR_ACC = 0xE0
SFR_B = 0xF0
# AT89C55 / AT89C55VD extras
SFR_T2CON, SFR_RCAP2L, SFR_RCAP2H = 0xC8, 0xCA, 0xCB
SFR_TL2, SFR_TH2 = 0xCC, 0xCD
SFR_CCON, SFR_CMOD, SFR_CCAPM0, SFR_CCAPM1 = 0xD8, 0xD9, 0xDA, 0xDB
SFR_CCAPM2, SFR_CCAPM3, SFR_CCAPM4 = 0xDC, 0xDD, 0xDE
SFR_CL, SFR_CH = 0xE9, 0xF9
SFR_CCAP0L, SFR_CCAP0H = 0xEA, 0xFA
SFR_CCAP1L, SFR_CCAP1H = 0xEB, 0xFB
SFR_CCAP2L, SFR_CCAP2H = 0xEC, 0xFC
SFR_CCAP3L, SFR_CCAP3H = 0xED, 0xFD
SFR_CCAP4L, SFR_CCAP4H = 0xEE, 0xFE
SFR_WDTRST = 0xA6
SFR_WDTPRG = 0xA7

# ---------------------------------------------------------------- batching
# Servicing the timers/board once per *instruction* dominated the profile
# (~33% of total time: 204K ``_do_peripherals`` calls for 266K instructions,
# each one crossing into ``bus.tick`` and the board's locks).  The timer math
# already takes a cycle delta, so the run loop may hold back up to
# ``_PERIPH_BATCH`` machine cycles and push them in one call: totals are
# preserved exactly, only the *visibility* of a freshly set TF0/TF1 (or a
# board edge) moves by at most ``_PERIPH_BATCH`` cycles - far below the
# 1844-cycle mux period the firmware tests assert on.  Every API boundary
# (``step``/``run``/``run_steps``) and every direct access to a timer or
# interrupt SFR flushes first, so software never observes stale state.
_PERIPH_BATCH = 8

#: Direct addresses whose *current* value software must observe: flush the
#: batched cycles before reading or writing any of them.  Ports, ACC, PSW and
#: plain RAM are deliberately absent - they do not depend on elapsed time.
_FLUSH_SFRS = frozenset((SFR_TCON, SFR_TMOD, SFR_TL0, SFR_TL1, SFR_TH0,
                         SFR_TH1, SFR_SCON, SFR_SBUF, SFR_IE, SFR_IP))

# Port bit masks
_PORT_MASKS = (-1, -1, -1, -1)

# TCON bits
TCON_IT0, TCON_IE0, TCON_IT1, TCON_IE1 = 0x01, 0x02, 0x04, 0x08
TCON_TR0, TCON_TF0, TCON_TR1, TCON_TF1 = 0x10, 0x20, 0x40, 0x80
# SCON bits
SCON_RI, SCON_TI, SCON_REN = 0x01, 0x02, 0x10

_PARITY = bytes(bin(i).count("1") & 1 for i in range(256))

_TABLES_READY = False
_OP_LEN = bytearray(256)
_OP_CYC = bytearray(256)
_VEC = (0x03, 0x0B, 0x13, 0x1B, 0x23, 0x2B, 0x33, 0x3B, 0x43, 0x4B, 0x53, 0x5B, 0x63, 0x6B, 0x73, 0x7B, 0x83)
_VEC_IRQ = (IRQ_INT0, IRQ_T0, IRQ_INT1, IRQ_T1, IRQ_RX, IRQ_TX)


def _init_tables() -> None:
    global _TABLES_READY
    if _TABLES_READY:
        return
    ln = _OP_LEN
    cy = _OP_CYC
    for i in range(256):
        ln[i] = 1
        cy[i] = 1
    # 2-byte immediates
    for op in (0x04, 0x05, 0x14, 0x15, 0x24, 0x25, 0x34, 0x35, 0x44, 0x45,
               0x54, 0x55, 0x64, 0x65, 0x74, 0x75, 0x90, 0xA3, 0xB4, 0xB5,
               0xD5, 0xE4, 0xE5, 0xF4, 0xF5):
        ln[op] = 2
    # 3-byte immediates (MOV direct,#imm)
    ln[0x75] = 3
    for op in (0x01, 0x21, 0x41, 0x61, 0x81, 0xA1, 0xC1, 0xE1):  # AJMP
        ln[op] = 2
    for op in (0x11, 0x31, 0x51, 0x71, 0x91, 0xB1, 0xD1, 0xF1):  # ACALL
        ln[op] = 2
    for op in (0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72,
               0x82, 0x92, 0xA2, 0xB2, 0xC2, 0xD2, 0xE2, 0xF2):  # LJMP/LCALL
        ln[op] = 3
    for op in (0x03, 0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73,
               0x83, 0x93, 0xA3, 0xB3, 0xC3, 0xD3, 0xE3, 0xF3):  # RR/RL a, imm
        ln[op] = 1
    for op in (0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
               0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0):  # bit + rel
        ln[op] = 3
    ln[0x30] = 3
    for op in (0xB6, 0xB7, 0xBE, 0xBF, 0xC6, 0xC7, 0xD6, 0xD7,
               0xDE, 0xDF, 0xE6, 0xE7, 0xEE, 0xEF, 0xF6, 0xF7,
               0xFE, 0xFF, 0x06, 0x07, 0x16, 0x17, 0x26, 0x27,
               0x36, 0x37, 0x46, 0x47, 0x56, 0x57, 0x66, 0x67,
               0x76, 0x77):
        ln[op] = 1
    for op in (0x86, 0x87, 0x96, 0x97, 0xA6, 0xA7, 0xB6, 0xB7,
               0xC6, 0xC7, 0xD6, 0xD7, 0xE6, 0xE7, 0xF6, 0xF7,
               0x06, 0x07, 0x16, 0x17, 0x26, 0x27, 0x36, 0x37,
               0x46, 0x47, 0x56, 0x57, 0x66, 0x67, 0x76, 0x77):
        ln[op] = 1
    for op in (0x96, 0x97, 0xA6, 0xA7, 0xB6, 0xB7, 0xC6, 0xC7,
               0xD6, 0xD7, 0xE6, 0xE7, 0xF6, 0xF7):  # MOV @Ri,direct
        ln[op] = 2
    for op in (0xA6, 0xA7):  # MOV direct,@Ri
        ln[op] = 2
    for op in (0x85,):  # MOV direct,direct
        ln[op] = 3
    # DJNZ direct,rel
    ln[0xD5] = 3
    ln[0xB5] = 3
    ln[0xB4] = 3
    # cycle counts
    for op in (0x00,):
        cy[op] = 1
    for op in (0x03, 0x04, 0x05, 0x13, 0x14, 0x15, 0x23, 0x24, 0x25,
               0x33, 0x34, 0x35, 0x43, 0x44, 0x45, 0x53, 0x54, 0x55,
               0x63, 0x64, 0x65, 0x73, 0x74, 0x75, 0x83, 0x84, 0x85,
               0x93, 0x94, 0x95, 0xA3, 0xA4, 0xA5, 0xB3, 0xB4, 0xB5,
               0xC3, 0xC4, 0xC5, 0xD3, 0xD4, 0xD5, 0xE3, 0xE4, 0xE5,
               0xF3, 0xF4, 0xF5):
        cy[op] = 2
    for op in (0x06, 0x07, 0x16, 0x17, 0x26, 0x27, 0x36, 0x37,
               0x46, 0x47, 0x56, 0x57, 0x66, 0x67, 0x76, 0x77):
        cy[op] = 1
    for op in (0x86, 0x87, 0x96, 0x97, 0xA6, 0xA7, 0xB6, 0xB7,
               0xC6, 0xC7, 0xD6, 0xD7, 0xE6, 0xE7, 0xF6, 0xF7):
        cy[op] = 2
    for op in (0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72,
               0x82, 0x92, 0xA2, 0xB2, 0xC2, 0xD2, 0xE2, 0xF2):
        cy[op] = 3 if op in (0x02, 0x12) else 2
    for op in (0x01, 0x21, 0x41, 0x61, 0x81, 0xA1, 0xC1, 0xE1,
               0x11, 0x31, 0x51, 0x71, 0x91, 0xB1, 0xD1, 0xF1,
               0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
               0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0):
        cy[op] = 2
    for op in (0x30, 0x10, 0x20, 0xB4, 0xB5, 0xB6, 0xB7, 0xBE, 0xBF,
               0xC0, 0xD0, 0xD5, 0xD6, 0xD7, 0xDE, 0xDF,
               0xE0, 0xE6, 0xE7, 0xEE, 0xEF, 0xF0, 0xF6, 0xF7, 0xFE, 0xFF):
        cy[op] = 2
    cy[0x10] = cy[0x20] = cy[0x30] = 2
    cy[0x40] = cy[0x50] = cy[0x60] = cy[0x70] = cy[0x80] = 2
    cy[0x90] = cy[0xA0] = cy[0xB0] = 2
    cy[0xC0] = cy[0xD0] = cy[0xE0] = cy[0xF0] = 2
    cy[0xB6] = cy[0xB7] = cy[0xBE] = cy[0xBF] = 2
    cy[0x00] = 1
    cy[0xA3] = cy[0x85] = cy[0x75] = 2
    cy[0x90] = 2
    cy[0x02] = cy[0x12] = 2
    cy[0xA4] = 4  # MUL AB
    cy[0x84] = 4  # DIV AB
    cy[0xC5] = 1  # XCH A,direct? no: 0xC5 is XCH A,direct (2 cyc)
    cy[0xC5] = 2
    cy[0xD5] = 2
    cy[0xE0] = 2
    cy[0xA5] = 1  # reserved
    _TABLES_READY = True


_init_tables()


class CPU8051:
    """A 12-clocks-per-machine-cycle MCS-51 core."""

    __slots__ = (
        "rom", "bus", "ram", "sfr", "pc", "cycles", "halted", "error",
        "in_isr", "irq_level", "last_op", "trace", "trace_limit",
        "watchdog", "wd_enabled", "pll_locked", "op_count", "idle",
        "serial_in", "t2_running", "pca_running", "_port_latch",
        "timers_on", "_serial_rx", "_pending_tick", "missing_pc",
        "_periph_pending", "_irq_scan",
    )

    def __init__(self, rom: ROM, bus: Optional[HardwareBus] = None) -> None:
        self.rom = rom
        self.bus: HardwareBus = bus if bus is not None else NullBus()
        self.ram = bytearray(256)          # internal RAM, banked + upper 128
        self.sfr = bytearray(256)          # SFR space (direct 0x80..0xFF)
        self.pc = 0
        self.cycles = 0                    # machine cycles since reset
        self.op_count = 0
        self.halted = False
        self.error: Optional[str] = None
        self.in_isr = 0
        self.irq_level = 0
        self.last_op = -1
        self.missing_pc: Optional[int] = None
        self.trace: Optional[List] = None
        self.trace_limit = 200_000
        self.watchdog = 0
        self.wd_enabled = False
        self.idle = False
        self.t2_running = False
        self.pca_running = False
        self.timers_on = False
        self._serial_rx = False
        self._pending_tick = 0
        self._periph_pending = 0
        self._port_latch = bytearray(4)
        self.reset()

    # ------------------------------------------------------------- lifecycle
    def reset(self) -> None:
        self.ram[:] = b"\x00" * 256
        self.sfr[:] = b"\x00" * 256
        self.sfr[SFR_SP] = 0x07
        self.sfr[SFR_P0] = 0xFF
        self.sfr[SFR_P1] = 0xFF
        self.sfr[SFR_P2] = 0xFF
        self.sfr[SFR_P3] = 0xFF
        self.sfr[SFR_PCON] = 0x00
        self._port_latch[:] = b"\xff\xff\xff\xff"
        self.pc = 0
        self.cycles = 0
        self.op_count = 0
        self.halted = False
        self.error = None
        self.missing_pc = None
        self.in_isr = 0
        self.irq_level = 0
        self.idle = False
        self.watchdog = 0
        self.wd_enabled = False
        self.timers_on = False
        self._serial_rx = False
        self._pending_tick = 0
        self._periph_pending = 0
        self._irq_scan = True          # после сброса первый опрос обязателен

    # ----------------------------------------------------------------- helpers
    @property
    def acc(self) -> int:
        return self.sfr[SFR_ACC]

    @acc.setter
    def acc(self, value: int) -> None:
        value &= 0xFF
        self.sfr[SFR_ACC] = value
        # PSW.P is a combinational function of the accumulator on silicon: it
        # must reflect the new ACC after *every* instruction that writes it,
        # including the ones that never call set_p() explicitly (CLR A,
        # MOV A,#imm, rotates, ANL/ORL/XRL A,..., XCH/XCHD, MOVC).  Updating
        # it here makes the whole family correct by construction; the set_p()
        # calls that follow some writes become redundant no-ops.
        self.sfr[SFR_PSW] = (self.sfr[SFR_PSW] & 0xFE) | _PARITY[value]

    @property
    def psw(self) -> int:
        return self.sfr[SFR_PSW]

    @psw.setter
    def psw(self, value: int) -> None:
        self.sfr[SFR_PSW] = value & 0xFF

    def set_p(self) -> None:
        p = _PARITY[self.sfr[SFR_ACC]]
        self.sfr[SFR_PSW] = (self.sfr[SFR_PSW] & 0xFE) | p

    @property
    def sp(self) -> int:
        return self.sfr[SFR_SP]

    @sp.setter
    def sp(self, value: int) -> None:
        self.sfr[SFR_SP] = value & 0xFF

    @property
    def dptr(self) -> int:
        return self.sfr[SFR_DPH] << 8 | self.sfr[SFR_DPL]

    @dptr.setter
    def dptr(self, value: int) -> None:
        self.sfr[SFR_DPH] = (value >> 8) & 0xFF
        self.sfr[SFR_DPL] = value & 0xFF

    # register bank helpers (indirect through PSW.RS0/RS1)
    def _r(self, n: int) -> int:
        return self.ram[((self.sfr[SFR_PSW] >> 3) & 3) * 8 + n]

    def _set_r(self, n: int, v: int) -> None:
        self.ram[((self.sfr[SFR_PSW] >> 3) & 3) * 8 + n] = v & 0xFF

    def _ri(self, n: int) -> int:
        """Address held in R0/R1 of the active bank."""
        return self.ram[((self.sfr[SFR_PSW] >> 3) & 3) * 8 + n]

    # ------------------------------------------------------------------- stack
    def push(self, value: int) -> None:
        sp = (self.sfr[SFR_SP] + 1) & 0xFF
        self.sfr[SFR_SP] = sp
        self.ram[sp] = value & 0xFF
        if sp <= 7:
            self.error = f"stack overflow (SP wrapped to 0x{sp:02X}) at PC=0x{self.pc:04X}"

    def pop(self) -> int:
        sp = self.sfr[SFR_SP]
        value = self.ram[sp]
        self.sfr[SFR_SP] = (sp - 1) & 0xFF
        return value

    def push_pc(self) -> None:
        """Push the return address the way silicon does: low byte, then high.

        ``RET``/``RETI`` pop the high byte first (see :meth:`pop_pc`), so pushing
        high first would byte-swap every return address and corrupt control flow
        for every ``LCALL``/``ACALL`` and every interrupt.
        """
        pc = self.pc
        self.push(pc & 0xFF)
        self.push(pc >> 8)
        if self.in_isr < 8:
            self.in_isr += 1

    def pop_pc(self) -> None:
        high = self.pop()
        low = self.pop()
        self.pc = (high << 8) | low
        if self.in_isr:
            self.in_isr -= 1

    # ------------------------------------------------------------- direct/bit
    def _dir_read(self, addr: int) -> int:
        if addr < 0x80:
            return self.ram[addr]
        if addr in _FLUSH_SFRS:
            # a timer/interrupt register: hand the software an exact value
            self._flush_peripherals()
        return self.sfr[addr]

    def _dir_write(self, addr: int, value: int) -> None:
        value &= 0xFF
        if addr < 0x80:
            self.ram[addr] = value
            return
        if addr == SFR_ACC:
            self.sfr[SFR_ACC] = value
            self.set_p()
            return
        if addr == SFR_PSW:
            self.sfr[SFR_PSW] = value
            return
        if SFR_P0 <= addr <= SFR_P3 and (addr & 0x0F) == 0:
            # ports need pin/latch interaction
            port = (addr - SFR_P0) >> 4
            self._port_latch[port] = value
            self.sfr[addr] = value
            self.bus.port_write(port, value)
            return
        if addr in _FLUSH_SFRS:
            # cycles still batched for the OLD timer/interrupt configuration
            # must be accounted before the new value takes effect (otherwise
            # they would be charged to a timer the firmware just stopped or
            # reloaded); the write may also ENABLE an IRQ source -> rescan
            self._flush_peripherals()
            self._irq_scan = True
        self.sfr[addr] = value
        if addr == SFR_SBUF:
            self.bus.serial_write(value)
            self.sfr[SFR_SCON] |= SCON_TI
        self._sfr_side_effect(addr, value)

    def _port_read(self, port: int) -> int:
        """Read a port: latch AND external pin levels (quasi-bidirectional)."""
        return self._port_latch[port] & self.bus.port_read(port)

    def _sfr_side_effect(self, addr: int, value: int) -> None:
        if addr == SFR_WDTRST:
            self.watchdog = 0
        elif addr == SFR_WDTPRG:
            self.wd_enabled = True
        elif addr == SFR_TCON:
            self.timers_on = (value & 0x50) != 0
        elif addr == SFR_SCON:
            self._serial_rx = bool(value & SCON_REN) and self.bus.serial_available()

    # -------------------------------------------------------------------- time
    def _advance(self, cycles: int) -> None:
        """Run timers/serial/peripherals for ``cycles`` machine cycles.

        While a timer (or the watchdog, or serial reception) is running the
        work is *batched*: cycles accumulate in ``_periph_pending`` until
        ``_PERIPH_BATCH`` of them are due, then one ``_do_peripherals`` call
        spends them all.  The arithmetic is identical - ``_tick_timer`` takes
        an arbitrary delta - so counters, overflows and ``bus.tick`` totals
        are unchanged; only flag/edge *visibility* moves by less than one
        batch.  Nothing leaves a ``run``/``run_steps``/``step`` call with a
        batch still pending (see :meth:`_flush_peripherals`).
        """
        self.cycles += cycles
        self.op_count += 1
        if self.timers_on or self.wd_enabled or self._serial_rx:
            pending = self._periph_pending + cycles
            if pending >= _PERIPH_BATCH:
                self._periph_pending = 0
                self._do_peripherals(pending)
            else:
                self._periph_pending = pending
        elif self._pending_tick:
            self._pending_tick += cycles
            if self._pending_tick >= 32:
                self.bus.tick(self._pending_tick)
                self._pending_tick = 0
                # без таймеров это единственная граница, на которой могло
                # появиться событие платы (нажатие) -> просим опрос
                self._irq_scan = True
        else:
            self._pending_tick = cycles

    def _flush_peripherals(self) -> None:
        """Push batched machine cycles into the timers/board immediately."""
        pending = self._periph_pending
        if pending:
            self._periph_pending = 0
            self._do_peripherals(pending)

    @staticmethod
    def _tick_timer(mode: int, th: int, tl: int, cycles: int):
        """Advance one 8051 timer by ``cycles`` machine cycles.

        Returns ``(th, tl, overflowed)``.

        On overflow the counter is **zeroed** and the overflow flag is set; any
        cycles already consumed by the overflow are discarded, exactly as on
        silicon (the flag is set once and the counter restarts from zero - the
        interrupt handler has to run before the next overflow matters).

        Each mode has its own arithmetic:

        * mode 0 - 13-bit timer (``TH`` holds 5 bits)
        * mode 1 - 16-bit timer
        * mode 2 - 8-bit auto-reload: ``TL`` counts, reloads from ``TH``
        * mode 3 - split: ``TL`` is an independent 8-bit timer, ``TH`` is
          stopped (it belongs to the other timer)

        Note that doing mode 1/0 as one big addition and keeping the remainder
        is wrong: 0xFFFE plus 2 cycles must give 0x0000, not 0x0000-plus-zeros
        carried over from a 32-bit sum.
        """
        if mode == 0:
            value = ((th & 0x1F) << 8 | tl) + cycles
            if value > 0x1FFF:
                return 0x00, 0x00, True
            return (value >> 8) & 0x1F, value & 0xFF, False
        if mode == 1:
            value = (th << 8 | tl) + cycles
            if value > 0xFFFF:
                return 0x00, 0x00, True
            return (value >> 8) & 0xFF, value & 0xFF, False
        if mode == 2:
            # TL counts up from its current value to 0xFF, overflows, reloads
            # from TH, then counts again.  One overflow takes ``256 - reload``
            # cycles, so the batch must be consumed overflow by overflow instead
            # of being added to the reloaded value in one go (doing the latter
            # corrupts TH, which is the reload register and must never change).
            reload = th & 0xFF
            period = 256 - reload
            remaining = tl + cycles
            overflowed = remaining > 0xFF
            if overflowed:
                remaining -= 0x100
                while remaining >= period:
                    remaining -= period
                value = reload + remaining
            else:
                value = remaining
            return reload, value & 0xFF, overflowed
        # mode 3: only the low half counts, the high half is stopped
        value = tl + cycles
        if value > 0xFF:
            return th & 0xFF, 0x00, True
        return th & 0xFF, value & 0xFF, False

    def _do_peripherals(self, cycles: int) -> None:
        bus = self.bus
        if self._pending_tick:
            bus.tick(self._pending_tick + cycles)
            self._pending_tick = 0
        else:
            bus.tick(cycles)
        sfr = self.sfr
        tmod = sfr[SFR_TMOD]
        tcon = sfr[SFR_TCON]
        if tcon & TCON_TR0:
            th, tl, overflowed = self._tick_timer(
                tmod & 0x03, sfr[SFR_TH0], sfr[SFR_TL0], cycles)
            sfr[SFR_TH0] = th
            sfr[SFR_TL0] = tl
            if overflowed:
                tcon |= TCON_TF0
        if tcon & TCON_TR1:
            th, tl, overflowed = self._tick_timer(
                (tmod >> 4) & 0x03, sfr[SFR_TH1], sfr[SFR_TL1], cycles)
            sfr[SFR_TH1] = th
            sfr[SFR_TL1] = tl
            if overflowed:
                tcon |= TCON_TF1
        sfr[SFR_TCON] = tcon
        self.timers_on = (tcon & 0x50) != 0
        # serial receive
        if self._serial_rx:
            chunk = bus.serial_read()
            if chunk is not None:
                sfr[SFR_SBUF] = chunk & 0xFF
                sfr[SFR_SCON] |= SCON_RI
        # watchdog: 8051 WDT overflows ~ 2**17 machine cycles on AT89C55
        if self.wd_enabled:
            self.watchdog += cycles
            if self.watchdog > 0x20000:
                self.watchdog = 0
        # Timer/serial flags may have just changed -> the run loops must poll.
        self._irq_scan = True

    # ------------------------------------------------------------ interrupts
    def _poll_interrupts(self) -> None:
        ie = self.sfr[SFR_IE]
        if not (ie & 0x80):            # EA
            return
        pending = 0
        tcon = self.sfr[SFR_TCON]
        if tcon & TCON_IE0:
            pending |= IRQ_INT0
        if tcon & TCON_TF0:
            pending |= IRQ_T0
        if tcon & TCON_IE1:
            pending |= IRQ_INT1
        if tcon & TCON_TF1:
            pending |= IRQ_T1
        if self.sfr[SFR_SCON] & SCON_RI:
            pending |= IRQ_RX
        if self.sfr[SFR_SCON] & SCON_TI:
            pending |= IRQ_TX
        pending |= self.bus.irq_requested()
        pending &= 0xFF
        if not pending:
            return
        ip = self.sfr[SFR_IP]
        chosen = -1
        chosen_pri = -1
        for bit, irq in zip(range(6), _VEC_IRQ):
            if not (pending & irq):
                continue
            if not (ie & irq):
                continue
            if (ip & irq) and self.irq_level and irq != self.irq_level:
                continue
            pri = 1 if (ip & irq) else 0
            if pri > chosen_pri:
                chosen_pri = pri
                chosen = bit
        if chosen < 0:
            return
        irq = _VEC_IRQ[chosen]
        if irq == IRQ_T0:
            self.sfr[SFR_TCON] &= ~TCON_TF0 & 0xFF
        elif irq == IRQ_T1:
            self.sfr[SFR_TCON] &= ~TCON_TF1 & 0xFF
        elif irq == IRQ_INT0:
            self.sfr[SFR_TCON] &= ~TCON_IE0 & 0xFF
        elif irq == IRQ_INT1:
            self.sfr[SFR_TCON] &= ~TCON_IE1 & 0xFF
        elif irq == IRQ_RX:
            self.sfr[SFR_SCON] &= ~SCON_RI & 0xFF
        elif irq == IRQ_TX:
            self.sfr[SFR_SCON] &= ~SCON_TI & 0xFF
        self.irq_level = irq if (ip & irq) else 0
        self._advance(2)
        self.push_pc()
        self.pc = _VEC[chosen]

    # ------------------------------------------------------------------- step
    def step(self) -> int:
        """Execute one instruction.  Returns the machine cycles consumed."""
        if self.halted:
            return 1
        if not self.rom.is_mapped(self.pc):
            # Fetching from an address that no code image covers.  On real
            # silicon this reads 0xFF (erased EPROM) and the CPU wanders; for
            # emulation that is useless, so we stop and report it.
            self.missing_pc = self.pc
            self.halted = True
            self.error = (f"fetch from unmapped code address 0x{self.pc:04X} "
                          f"- this part of the firmware image is missing")
            return 1
        if self.idle:
            self._advance(1)
            self._flush_peripherals()
            return 1
        self._poll_interrupts()
        cycles = self._execute()
        self._advance(cycles)
        self._flush_peripherals()      # single-step API: leave exact state
        return cycles

    def run_steps(self, max_steps: int) -> int:
        """Execute at most ``max_steps`` instructions; stop on halt/error."""
        executed = 0
        # Locals beat attribute lookups in the inner loop; the EA test inlines
        # the common case (interrupts globally disabled) so _poll_interrupts
        # is only entered when there is something to poll.
        sfr = self.sfr
        mem = self.rom._mem             # `pc in mem` инлайн, без вызова метода
        poll = self._poll_interrupts
        advance = self._advance
        execute = self._execute
        while executed < max_steps:
            if self.halted:
                break
            pc = self.pc
            if pc not in mem and (pc & 0xFFFF) not in mem:
                # семантика rom.is_mapped (маска на случай PC у верха)
                self.missing_pc = pc
                self.halted = True
                self.error = (f"fetch from unmapped code address 0x{pc:04X} "
                              f"- this part of the firmware image is missing")
                break
            if self.idle:
                advance(1)
            else:
                # Опрос по флагу _irq_scan: источники pending меняются только
                # на границе _do_peripherals/записи в SFR прерываний (там флаг
                # и выставляется) — опрос на каждую инструкцию стоил ~22%
                # recovered-пути (cProfile: 342K вызовов).  См. run().
                if self._irq_scan and sfr[SFR_IE] & 0x80:
                    self._irq_scan = False
                    poll()
                advance(execute())
            executed += 1
        self._flush_peripherals()      # the batch is owed to timers/board
        return executed

    def run(self, cycles: int) -> int:
        """Run for at most ``cycles`` machine cycles (or forever if <= 0)."""
        executed = 0
        target = self.cycles + cycles if cycles > 0 else -1
        execute = self._execute
        mem = self.rom._mem             # `pc in mem` инлайн, без вызова метода
        poll = self._poll_interrupts
        sfr = self.sfr
        batch = _PERIPH_BATCH
        # Тело _advance ИНЛАЙНено ниже (метод-вызов на каждой инструкции
        # стоил ~4%); держать в синхроне с _advance — run_steps его зовёт.
        while True:
            if self.halted:
                break
            if self.idle:
                self._advance(1)
            else:
                # Гейт по _irq_scan (см. run_steps): опрос только когда могло
                # появиться событие — таймерный флаг/связь/линия платы на
                # границе flush либо запись в SFR прерываний.
                if self._irq_scan and sfr[SFR_IE] & 0x80:
                    self._irq_scan = False
                    poll()
                c = execute()
                self.cycles += c
                self.op_count += 1
                if self.timers_on or self.wd_enabled or self._serial_rx:
                    pending = self._periph_pending + c
                    if pending >= batch:
                        self._periph_pending = 0
                        self._do_peripherals(pending)
                    else:
                        self._periph_pending = pending
                elif self._pending_tick:
                    self._pending_tick += c
                    if self._pending_tick >= 32:
                        self.bus.tick(self._pending_tick)
                        self._pending_tick = 0
                        self._irq_scan = True
                else:
                    self._pending_tick = c
            executed += 1
            if target >= 0 and self.cycles >= target:
                break
            if executed >= 400_000_000:
                break
            pc = self.pc
            if pc not in mem and (pc & 0xFFFF) not in mem:
                # семантика rom.is_mapped (маска на случай PC у верха)
                self.missing_pc = pc
                self.halted = True
                self.error = (f"fetch from unmapped code address 0x{pc:04X} "
                              f"- this part of the firmware image is missing")
                break
        self._flush_peripherals()      # the batch is owed to timers/board
        return executed

    # --------------------------------------------------------------- execution
    def _execute(self) -> int:
        # Фетч через плоский bytearray (зеркало +3 покрывает p..p+2 при PC у
        # верха пространства) вместо rom.byte(): метод-вызов + маска на каждый
        # операнд стоили ~2 вызова на инструкцию (cProfile demo51: 729K вызовов
        # rom.byte на 393K инструкций).  pc маскируется один AND'ом на входе.
        flat = self.rom.flat
        pc = self.pc & 0xFFFF
        self.last_op = flat[pc]
        trace = self.trace
        if trace is not None:
            if len(trace) < self.trace_limit:
                trace.append((pc, self.last_op, self.acc, self.psw,
                              self.sfr[SFR_SP], self.cycles))
            else:
                self.trace = None
        p = pc + 1
        op = self.last_op
        romb = flat.__getitem__
        sfr = self.sfr
        ram = self.ram
        bus = self.bus
        # ---- hot path ------------------------------------------------------
        # Measured on the demo firmware, these twelve opcode groups cover
        # ~84% of everything the firmware executes (MOV DPTR and MOVX @DPTR,A
        # alone are ~30%), so they must be tested before the long tail.
        # The sets are disjoint, so their relative order carries no meaning.
        if op == 0xD5:                                             # DJNZ direct,rel
            addr = romb(p)
            value = (self._dir_read(addr) - 1) & 0xFF
            self._dir_write(addr, value)
            self.pc = (p + 2 + _signed(romb(p + 1))) & 0xFFFF if value else p + 2
            return 2
        # ---- decode/execute -------------------------------------------------
        if op == 0x00:                                              # NOP
            self.pc = p
            return 1
        if op == 0x90:                                             # MOV DPTR,#imm16
            self.pc = p + 2
            self.sfr[SFR_DPH] = romb(p)
            self.sfr[SFR_DPL] = romb(p + 1)
            return 2
        if op == 0xE5:                                             # MOV A,direct
            self.pc = p + 1
            addr = romb(p)
            if addr < 0x80:
                self.acc = ram[addr]
            elif addr == SFR_ACC:
                pass
            elif SFR_P0 <= addr <= SFR_P3 and (addr & 0x0F) == 0:
                self.acc = self._port_read((addr - SFR_P0) >> 4)
            else:
                if addr in _FLUSH_SFRS:
                    # SBUF/TCON/... must not be served from a stale batch
                    self._flush_peripherals()
                self.acc = self.sfr[addr]
            return 1
        if 0xF8 <= op <= 0xFF:                                     # MOV Rn,A
            self.pc = p
            self._set_r(op & 7, self.sfr[SFR_ACC])
            return 1
        if op == 0xF0:                                             # MOVX @DPTR,A
            self.pc = p
            bus.ext_write(self.dptr, self.sfr[SFR_ACC])
            return 2
        if 0xE8 <= op <= 0xEF:                                     # MOV A,Rn
            self.pc = p
            self.acc = self._r(op & 7)
            return 1
        if op == 0xB4:                                             # CJNE A,#imm,rel
            left, right = self.sfr[SFR_ACC], romb(p)
            self.pc = p + 2
            self._cjne(left, right)
            if left != right:
                self.pc = (p + 2 + _signed(romb(p + 1))) & 0xFFFF
            return 2
        if op == 0x93:                                             # MOVC A,@A+DPTR
            self.pc = p
            self.acc = romb((self.sfr[SFR_ACC] + self.dptr) & 0xFFFF)
            return 2
        if op == 0x60:                                             # JZ
            self.pc = (p + 1 + _signed(romb(p))) & 0xFFFF if self.sfr[SFR_ACC] == 0 else p + 1
            return 2
        if op in (0xE6, 0xE7):                                     # MOV A,@Ri
            self.pc = p
            self.acc = ram[self._ri(op & 1)]
            return 1
        if op == 0xE4:                                              # CLR A
            self.pc = p
            self.acc = 0
            return 1
        if op == 0xA3:                                             # INC DPTR
            self.pc = p
            self.dptr = (self.dptr + 1) & 0xFFFF
            return 2
        if 0x28 <= op <= 0x2F:                                     # ADD A,Rn
            self.pc = p
            self._add(self._r(op & 7), 0)
            return 1
        if op == 0x34:                                             # ADDC A,#imm
            self.pc = p + 1
            self._add(romb(p), sfr[SFR_PSW] & 0x80)
            return 1
        if op == 0x50:                                             # JNC
            self.pc = p + 1 if (sfr[SFR_PSW] & 0x80) else (p + 1 + _signed(romb(p))) & 0xFFFF
            return 2
        if op in (0x04, 0x05, 0x06, 0x07):
            return self._inc_family(op, p, romb)
        if 0xD8 <= op <= 0xDF:                                     # DJNZ Rn,rel
            n = op & 7
            value = (self._r(n) - 1) & 0xFF
            self._set_r(n, value)
            self.pc = (p + 1 + _signed(romb(p))) & 0xFFFF if value else p + 1
            return 2
        if 0x08 <= op <= 0x0F:                                     # INC Rn
            self.pc = p
            n = op & 7
            self._set_r(n, (self._r(n) + 1) & 0xFF)
            return 1
        if op == 0x25:                                             # ADD A,direct
            self.pc = p + 1
            self._add(self._dir_read(romb(p)), 0)
            return 1
        if op == 0xE0:                                             # MOVX A,@DPTR
            self.pc = p
            self.acc = bus.ext_read(self.dptr) & 0xFF
            return 2
        if op == 0x64:                                             # XRL A,#imm
            self.pc = p + 1
            self.acc = self.sfr[SFR_ACC] ^ romb(p)
            return 1
        if op == 0x24:                                             # ADD A,#imm
            self.pc = p + 1
            self._add(romb(p), 0)
            return 1
        if op == 0x12:                                             # LCALL
            target = romb(p) << 8 | romb(p + 1)
            self.pc = p + 2
            self.push_pc()
            self.pc = target
            return 2
        if op == 0x22:                                             # RET
            self.pop_pc()
            return 2
        if op == 0x75:                                             # MOV direct,#imm
            self.pc = p + 2
            self._dir_write(romb(p), romb(p + 1))
            return 2
        if 0x78 <= op <= 0x7F:                                      # MOV Rn,#imm
            self.pc = p + 1
            self._set_r(op & 7, romb(p))
            return 1
        if op == 0xF5:                                              # MOV direct,A
            self.pc = p + 1
            self._dir_write(romb(p), self.sfr[SFR_ACC])
            return 1
        # ================================ MOV A, #imm / direct / @Ri / Rn / R
        if op == 0x74:                                              # MOV A,#imm
            self.pc = p + 1
            self.acc = romb(p)
            return 1
        if op == 0x80:                                             # SJMP
            self.pc = (p + 1 + _signed(romb(p))) & 0xFFFF
            return 2
        if op == 0x70:                                             # JNZ
            self.pc = p + 1 if self.sfr[SFR_ACC] == 0 else (p + 1 + _signed(romb(p))) & 0xFFFF
            return 2
        if op == 0xB5:                                             # CJNE A,direct,rel
            left, right = self.sfr[SFR_ACC], self._dir_read(romb(p))
            self.pc = p + 2
            self._cjne(left, right)
            if left != right:
                self.pc = (p + 2 + _signed(romb(p + 1))) & 0xFFFF
            return 2
        if op in (0xC2, 0xD2, 0xB2):                               # CLR/SETB/CPL bit
            self.pc = p + 1
            addr = romb(p)
            if op == 0xC2:
                self._bit_write(addr, 0)
            elif op == 0xD2:
                self._bit_write(addr, 1)
            else:
                self._bit_write(addr, 0 if self._bit(addr) else 1)
            return 2
        # ================================================================ PUSH/POP
        if op == 0xC0:
            self.pc = p + 1
            self.push(self._dir_read(romb(p)))
            return 2
        if op == 0xD0:
            self.pc = p + 1
            self._dir_write(romb(p), self.pop())
            return 2
        if op == 0x20:                                             # JB bit,rel
            bit = self._bit(romb(p))
            self.pc = (p + 2 + _signed(romb(p + 1))) & 0xFFFF if bit else p + 2
            return 2
        if op == 0x30:                                             # JNB bit,rel
            bit = self._bit(romb(p))
            self.pc = p + 2 if bit else (p + 2 + _signed(romb(p + 1))) & 0xFFFF
            return 2
        if op in (0xF6, 0xF7):                                      # MOV @Ri,A
            self.pc = p
            ram[self._ri(op & 1)] = self.sfr[SFR_ACC]
            return 1
        # ========================================================== logical ops
        if op == 0x54:                                             # ANL A,#imm
            self.pc = p + 1
            self.acc = self.sfr[SFR_ACC] & romb(p)
            return 1
        # ============================================================ bit ops
        if op in (0xC3, 0xD3, 0xB3):                               # CLR/SETB/CPL C
            self.pc = p
            if op == 0xC3:
                self.sfr[SFR_PSW] &= 0x7F
            elif op == 0xD3:
                self.sfr[SFR_PSW] |= 0x80
            else:
                self.sfr[SFR_PSW] ^= 0x80
            return 1
        # ============================================================== branches
        if op == 0x02:                                             # LJMP
            self.pc = romb(p) << 8 | romb(p + 1)
            return 2
        if 0x98 <= op <= 0x9F:
            self.pc = p
            self._sub(self._r(op & 7), sfr[SFR_PSW] & 0x80)
            return 1
        if op == 0x32:                                             # RETI
            self.pop_pc()
            self.irq_level = 0
            return 2
        if op in (0x01, 0x21, 0x41, 0x61, 0x81, 0xA1, 0xC1, 0xE1):  # AJMP
            # Page bits come from PC **after** the 2-byte instruction
            # (p + 1), matching disasm/asm51; taking them from p misroutes
            # every AJMP that sits on a 2 KiB boundary (0x...7FE).
            page = ((p + 1) & 0xFFFF) & 0xF800
            target = page | ((op >> 5) << 8) | romb(p)
            self.pc = target
            return 2
        if 0xB8 <= op <= 0xBF:                                     # CJNE Rn,#imm,rel
            left, right = self._r(op & 7), romb(p)
            self.pc = p + 2
            self._cjne(left, right)
            if left != right:
                self.pc = (p + 2 + _signed(romb(p + 1))) & 0xFFFF
            return 2
        if op == 0x13:                                             # RRC A
            self.pc = p
            a = self.sfr[SFR_ACC]
            carry = 0x80 if (self.sfr[SFR_PSW] & 0x80) else 0
            psw = self.sfr[SFR_PSW] & 0x7F
            if a & 1:
                psw |= 0x80
            self.sfr[SFR_PSW] = psw
            self.acc = (a >> 1) | carry
            return 1
        if op in (0xF2, 0xF3):                                     # MOVX @Ri,A
            self.pc = p
            addr = self._ri(op & 1)
            self._ext_write_banked(addr, self.sfr[SFR_ACC])
            return 2
        if op in (0x15, 0x16, 0x17):
            return self._dec_family(op, p, romb)
        if op == 0xC4:                                             # SWAP A
            self.pc = p
            a = self.sfr[SFR_ACC]
            self.acc = ((a << 4) | (a >> 4)) & 0xFF
            return 1
        if op == 0x95:
            self.pc = p + 1
            self._sub(self._dir_read(romb(p)), sfr[SFR_PSW] & 0x80)
            return 1
        # ================================================================ INC
        if op == 0x14:                                             # DEC A
            self.pc = p
            self.acc = (self.sfr[SFR_ACC] - 1) & 0xFF
            return 1
        if op == 0x44:                                             # ORL A,#imm
            self.pc = p + 1
            self.acc = self.sfr[SFR_ACC] | romb(p)
            return 1
        if op == 0xF4:                                              # CPL A
            self.pc = p
            self.acc = self.sfr[SFR_ACC] ^ 0xFF
            return 1
        if op in (0x76, 0x77):                                      # MOV @Ri,#imm
            self.pc = p + 1
            ram[self._ri(op & 1)] = romb(p)
            return 1
        if 0xA8 <= op <= 0xAF:                                      # MOV Rn,direct
            self.pc = p + 1
            self._set_r(op & 7, self._dir_read(romb(p)))
            return 1
        if 0x88 <= op <= 0x8F:                                      # MOV direct,Rn
            self.pc = p + 1
            self._dir_write(romb(p), self._r(op & 7))
            return 1
        if op == 0x85:                                             # MOV direct,direct
            self.pc = p + 2
            src = romb(p)
            dst = romb(p + 1)
            self._dir_write(dst, self._dir_read(src))
            return 2
        if op in (0x86, 0x87):                                     # MOV direct,@Ri
            self.pc = p + 1
            self._dir_write(romb(p), ram[self._ri(op & 1)])
            return 2
        if op in (0xA6, 0xA7):                                     # MOV @Ri,direct
            self.pc = p + 1
            ram[self._ri(op & 1)] = self._dir_read(romb(p))
            return 2
        # ============================== MOVC / MOVX
        if op == 0x83:                                             # MOVC A,@A+PC
            self.pc = p
            self.acc = romb((self.sfr[SFR_ACC] + p) & 0xFFFF)
            return 2
        if op in (0xE2, 0xE3):                                     # MOVX A,@Ri
            self.pc = p
            addr = self._ri(op & 1)
            if self.sfr[SFR_P2]:
                addr |= self.sfr[SFR_P2] << 8
            self.acc = bus.ext_read(addr) & 0xFF
            return 2
        # =============================================================== ADD
        if op in (0x26, 0x27):                                     # ADD A,@Ri
            self.pc = p
            self._add(ram[self._ri(op & 1)], 0)
            return 1
        if op == 0x35:                                             # ADDC A,direct
            self.pc = p + 1
            self._add(self._dir_read(romb(p)), sfr[SFR_PSW] & 0x80)
            return 1
        if op in (0x36, 0x37):
            self.pc = p
            self._add(ram[self._ri(op & 1)], sfr[SFR_PSW] & 0x80)
            return 1
        if 0x38 <= op <= 0x3F:
            self.pc = p
            self._add(self._r(op & 7), sfr[SFR_PSW] & 0x80)
            return 1
        # =============================================================== SUBB
        if op == 0x94:
            self.pc = p + 1
            self._sub(romb(p), sfr[SFR_PSW] & 0x80)
            return 1
        if op in (0x96, 0x97):
            self.pc = p
            self._sub(ram[self._ri(op & 1)], sfr[SFR_PSW] & 0x80)
            return 1
        if 0x18 <= op <= 0x1F:                                     # DEC Rn
            self.pc = p
            n = op & 7
            self._set_r(n, (self._r(n) - 1) & 0xFF)
            return 1
        # ================================================================ MUL/DIV
        if op == 0xA4:                                             # MUL AB
            self.pc = p
            result = self.sfr[SFR_ACC] * self.sfr[SFR_B]
            self.sfr[SFR_ACC] = result & 0xFF
            self.sfr[SFR_B] = (result >> 8) & 0xFF
            # Intel: CY is always cleared, and OV must be CLEARED here too -
            # only a 16-bit product sets it.  The old code kept any stale OV
            # bit from a previous operation (`& 0xFE` only touched P).
            psw = self.sfr[SFR_PSW] & 0x7B          # clear CY and OV
            if result > 0xFF:
                psw |= 0x04                          # OV: product > 255
            self.sfr[SFR_PSW] = psw
            self.set_p()
            return 4
        if op == 0x84:                                             # DIV AB
            self.pc = p
            a = self.sfr[SFR_ACC]
            b = self.sfr[SFR_B]
            # Intel: CY always cleared; OV set ONLY on division by zero and
            # explicitly cleared otherwise (again, no stale OV carried over).
            psw = self.sfr[SFR_PSW] & 0x7B          # clear CY and OV
            if b == 0:
                psw |= 0x04                          # OV: divide by zero
            else:
                self.sfr[SFR_ACC] = a // b
                self.sfr[SFR_B] = a % b
            self.sfr[SFR_PSW] = psw
            self.set_p()
            return 4
        if op == 0x55:
            self.pc = p + 1
            self.acc = self.sfr[SFR_ACC] & self._dir_read(romb(p))
            return 1
        if op in (0x56, 0x57):
            self.pc = p
            self.acc = self.sfr[SFR_ACC] & ram[self._ri(op & 1)]
            return 1
        if 0x58 <= op <= 0x5F:
            self.pc = p
            self.acc = self.sfr[SFR_ACC] & self._r(op & 7)
            return 1
        if op == 0x45:
            self.pc = p + 1
            self.acc = self.sfr[SFR_ACC] | self._dir_read(romb(p))
            return 1
        if op in (0x46, 0x47):
            self.pc = p
            self.acc = self.sfr[SFR_ACC] | ram[self._ri(op & 1)]
            return 1
        if 0x48 <= op <= 0x4F:
            self.pc = p
            self.acc = self.sfr[SFR_ACC] | self._r(op & 7)
            return 1
        if op == 0x65:
            self.pc = p + 1
            self.acc = self.sfr[SFR_ACC] ^ self._dir_read(romb(p))
            return 1
        if op in (0x66, 0x67):
            self.pc = p
            self.acc = self.sfr[SFR_ACC] ^ ram[self._ri(op & 1)]
            return 1
        if 0x68 <= op <= 0x6F:
            self.pc = p
            self.acc = self.sfr[SFR_ACC] ^ self._r(op & 7)
            return 1
        # ANL/ORL/XRL direct,A and direct,#imm
        if op in (0x52, 0x53):
            self.pc = p + (1 if op == 0x52 else 2)
            addr = romb(p)
            operand = self.sfr[SFR_ACC] if op == 0x52 else romb(p + 1)
            self._dir_write(addr, self._dir_read(addr) & operand)
            return 1 if op == 0x52 else 2
        if op in (0x42, 0x43):
            self.pc = p + (1 if op == 0x42 else 2)
            addr = romb(p)
            operand = self.sfr[SFR_ACC] if op == 0x42 else romb(p + 1)
            self._dir_write(addr, self._dir_read(addr) | operand)
            return 1 if op == 0x42 else 2
        if op in (0x62, 0x63):
            self.pc = p + (1 if op == 0x62 else 2)
            addr = romb(p)
            operand = self.sfr[SFR_ACC] if op == 0x62 else romb(p + 1)
            self._dir_write(addr, self._dir_read(addr) ^ operand)
            return 1 if op == 0x62 else 2
        # =========================================================== rotates
        if op == 0x03:                                             # RR A
            self.pc = p
            a = self.sfr[SFR_ACC]
            self.acc = (a >> 1) | ((a & 1) << 7)
            return 1
        if op == 0x23:                                             # RL A
            self.pc = p
            a = self.sfr[SFR_ACC]
            self.acc = ((a << 1) | (a >> 7)) & 0xFF
            return 1
        if op == 0x33:                                             # RLC A
            self.pc = p
            a = self.sfr[SFR_ACC]
            carry_in = 1 if (self.sfr[SFR_PSW] & 0x80) else 0
            result = (a << 1) | carry_in
            psw = self.sfr[SFR_PSW] & 0x7F
            if result > 0xFF:
                psw |= 0x80
            self.sfr[SFR_PSW] = psw
            self.acc = result & 0xFF
            return 1
        if op in (0xD4,):                                          # DA A
            self.pc = p
            return self._da(1)
        # ========================================================= XCH / XCHD
        if op == 0xC5:
            self.pc = p + 1
            addr = romb(p)
            tmp = self._dir_read(addr)
            self._dir_write(addr, self.sfr[SFR_ACC])
            self.acc = tmp
            return 1
        if op in (0xC6, 0xC7):
            self.pc = p
            ri = self._ri(op & 1)
            tmp = ram[ri]
            ram[ri] = self.sfr[SFR_ACC]
            self.acc = tmp
            return 1
        if 0xC8 <= op <= 0xCF:
            self.pc = p
            n = op & 7
            tmp = self._r(n)
            self._set_r(n, self.sfr[SFR_ACC])
            self.acc = tmp
            return 1
        if op in (0xD6, 0xD7):                                     # XCHD A,@Ri
            self.pc = p
            ri = self._ri(op & 1)
            a = self.sfr[SFR_ACC]
            # The memory nibble must be captured BEFORE the write-back,
            # otherwise A receives its own low nibble unchanged.
            old = ram[ri]
            ram[ri] = (old & 0xF0) | (a & 0x0F)
            self.acc = (a & 0xF0) | (old & 0x0F)
            return 1
        if op in (0x11, 0x31, 0x51, 0x71, 0x91, 0xB1, 0xD1, 0xF1):  # ACALL
            page = ((p + 1) & 0xFFFF) & 0xF800    # same PC+2 rule as AJMP
            target = page | ((op >> 5) << 8) | romb(p)
            self.pc = p + 1
            self.push_pc()
            self.pc = target
            return 2
        if op == 0x73:                                             # JMP @A+DPTR
            self.pc = (self.dptr + self.sfr[SFR_ACC]) & 0xFFFF
            return 2
        if op == 0x40:                                             # JC
            self.pc = (p + 1 + _signed(romb(p))) & 0xFFFF if (sfr[SFR_PSW] & 0x80) else p + 1
            return 2
        if op in (0xB6, 0xB7):                                     # CJNE @Ri,#imm,rel
            left, right = ram[self._ri(op & 1)], romb(p)
            self.pc = p + 2
            self._cjne(left, right)
            if left != right:
                self.pc = (p + 2 + _signed(romb(p + 1))) & 0xFFFF
            return 2
        if op == 0x10:                                             # JBC bit,rel
            addr = romb(p)
            bit = self._bit(addr)
            if bit:
                self._bit_write(addr, 0)
                self.pc = (p + 2 + _signed(romb(p + 1))) & 0xFFFF
            else:
                self.pc = p + 2
            return 2
        if op == 0x72:                                             # ORL C,bit
            self.pc = p + 1
            if self._bit(romb(p)):
                self.sfr[SFR_PSW] |= 0x80
            return 2
        if op == 0xA2:                                             # MOV C,bit
            self.pc = p + 1
            psw = self.sfr[SFR_PSW] & 0x7F
            self.sfr[SFR_PSW] = psw | (0x80 if self._bit(romb(p)) else 0)
            return 1
        if op == 0x92:                                             # MOV bit,C
            self.pc = p + 1
            self._bit_write(romb(p), 1 if (self.sfr[SFR_PSW] & 0x80) else 0)
            return 2
        if op == 0xA0:                                             # ORL C,/bit
            self.pc = p + 1
            if not self._bit(romb(p)):
                self.sfr[SFR_PSW] |= 0x80
            return 2
        if op == 0x82:                                             # ANL C,bit
            self.pc = p + 1
            if not self._bit(romb(p)):
                self.sfr[SFR_PSW] &= 0x7F
            return 2
        if op == 0xB0:                                             # ANL C,/bit
            self.pc = p + 1
            if self._bit(romb(p)):
                self.sfr[SFR_PSW] &= 0x7F
            return 2
        # ================================================================= misc
        if op == 0xA5:                                             # reserved
            self.pc = p
            self.error = f"reserved opcode 0xA5 at 0x{pc:04X}"
            return 1
        # ------------------------------------------------------------- unknown
        self.pc = p
        self.error = f"unimplemented opcode 0x{op:02X} at 0x{pc:04X}"
        return 1

    # -------------------------------------------------------------- helper ops
    def _ext_write_banked(self, addr: int, value: int) -> None:
        if self.sfr[SFR_P2]:
            addr |= self.sfr[SFR_P2] << 8
        self.bus.ext_write(addr, value)

    def _add(self, operand: int, carry_in: int) -> None:
        """ADD/ADDC.

        CY, AC and OV are *updated* (set or cleared) on every add, as on real
        silicon; only the register-bank and user bits (RS0, RS1, F0 = 0x38) are
        preserved.  Leaving the old flags in place makes them sticky, which
        breaks ``DA A`` and therefore every BCD money calculation.
        """
        a = self.sfr[SFR_ACC]
        carry = 1 if carry_in else 0
        result = a + operand + carry
        psw = self.sfr[SFR_PSW] & 0x38          # keep RS0, RS1, F0
        if ((a & 0x0F) + (operand & 0x0F) + carry) > 0x0F:
            psw |= 0x40                          # AC
        if result > 0xFF:
            psw |= 0x80                          # CY
        value = result & 0xFF
        if (a ^ value) & (operand ^ value) & 0x80:
            psw |= 0x04                          # OV
        self.sfr[SFR_ACC] = value
        self.sfr[SFR_PSW] = psw | _PARITY[value]

    def _sub(self, operand: int, carry_in: int) -> None:
        """SUBB - as :meth:`_add`, but with borrow instead of carry."""
        a = self.sfr[SFR_ACC]
        borrow = 1 if carry_in else 0
        result = a - operand - borrow
        psw = self.sfr[SFR_PSW] & 0x38          # keep RS0, RS1, F0
        if ((a & 0x0F) - (operand & 0x0F) - borrow) < 0:
            psw |= 0x40                          # AC
        if result < 0:
            psw |= 0x80                          # CY (borrow)
        value = result & 0xFF
        if (a ^ operand) & (a ^ value) & 0x80:
            psw |= 0x04                          # OV
        self.sfr[SFR_ACC] = value
        self.sfr[SFR_PSW] = psw | _PARITY[value]

    def _cjne(self, left: int, right: int) -> None:
        """Set CY for ``CJNE``: CY = 1 when the first operand is below the second.

        Note that ``CJNE`` *branches* on "operands differ", which is not the
        same condition - the branch is decided by the caller comparing the two
        operands directly.  This helper only maintains the flag.
        """
        psw = self.sfr[SFR_PSW] & 0x7F
        if left < right:
            psw |= 0x80
        self.sfr[SFR_PSW] = psw

    def _inc_family(self, op: int, p: int, romb) -> int:
        if op == 0x04:
            self.pc = p
            self.acc = (self.sfr[SFR_ACC] + 1) & 0xFF
            return 1
        if op == 0x05:
            self.pc = p + 1
            addr = romb(p)
            self._dir_write(addr, (self._dir_read(addr) + 1) & 0xFF)
            return 1
        self.pc = p
        ri = self._ri(op & 1)
        self.ram[ri] = (self.ram[ri] + 1) & 0xFF
        return 1

    def _dec_family(self, op: int, p: int, romb) -> int:
        if op == 0x15:
            self.pc = p + 1
            addr = romb(p)
            self._dir_write(addr, (self._dir_read(addr) - 1) & 0xFF)
            return 1
        self.pc = p
        ri = self._ri(op & 1)
        self.ram[ri] = (self.ram[ri] - 1) & 0xFF
        return 1

    def _da(self, cycles: int) -> int:
        """``DA A`` - decimal (BCD) adjust after an addition.

        The low nibble is adjusted first and then the **adjusted** value's high
        nibble is tested, exactly as Intel specifies.  Testing the
        pre-adjustment accumulator is wrong for 0x9A..0x9F: 0x9A would come out
        as 0xA0 instead of wrapping to 0x00 with CY set, which corrupts every
        multi-byte BCD total (i.e. all money arithmetic).
        """
        a = self.sfr[SFR_ACC]
        psw = self.sfr[SFR_PSW]
        carry = psw & 0x80
        if (a & 0x0F) > 9 or (psw & 0x40):
            a += 6
        if (a >> 4) > 9 or carry:
            a += 0x60
            carry = 0x80
        self.sfr[SFR_ACC] = a & 0xFF
        self.sfr[SFR_PSW] = (psw & 0x7F) | carry
        self.set_p()
        return cycles

    # -------------------------------------------------------------------- bits
    def _bit_addr(self, bit: int):
        if bit < 0x80:
            byte = (bit >> 3) + 0x20
            mask = 1 << (bit & 7)
            return byte, mask, False
        byte = bit & 0xF8
        mask = 1 << (bit & 7)
        if byte == SFR_P0 or byte == SFR_P1 or byte == SFR_P2 or byte == SFR_P3:
            return byte, mask, True
        return byte, mask, False

    def _bit(self, bit: int) -> int:
        byte, mask, is_port = self._bit_addr(bit)
        if is_port:
            return 1 if (self._port_read((byte - SFR_P0) >> 4) & mask) else 0
        if byte < 0x80:
            return 1 if (self.ram[byte] & mask) else 0
        if byte in _FLUSH_SFRS:
            # TF0/TF1/RI/TI/EA are time-dependent: never show them stale
            self._flush_peripherals()
        return 1 if (self.sfr[byte] & mask) else 0

    def _bit_write(self, bit: int, value: int) -> None:
        byte, mask, is_port = self._bit_addr(bit)
        if is_port:
            port = (byte - SFR_P0) >> 4
            latch = self._port_latch[port]
            latch = (latch | mask) if value else (latch & ~mask & 0xFF)
            self._port_latch[port] = latch
            self.sfr[byte] = latch
            self.bus.port_write(port, latch)
            return
        if byte < 0x80:
            if value:
                self.ram[byte] |= mask
            else:
                self.ram[byte] &= ~mask & 0xFF
            return
        if byte in _FLUSH_SFRS:
            # account the batched cycles before the flag/config bit changes;
            # the bit may ENABLE an interrupt source -> rescan IRQs
            self._flush_peripherals()
            self._irq_scan = True
        if value:
            self.sfr[byte] |= mask
            new = self.sfr[byte]
        else:
            self.sfr[byte] &= ~mask & 0xFF
            new = self.sfr[byte]
        if byte == SFR_SBUF:
            self.bus.serial_write(new)
        else:
            self._sfr_side_effect(byte, new)

    # ------------------------------------------------------------ diagnostics
    def state(self) -> dict:
        s = self.sfr
        return {
            "pc": self.pc,
            "op": self.last_op,
            "acc": s[SFR_ACC],
            "b": s[SFR_B],
            "psw": s[SFR_PSW],
            "sp": s[SFR_SP],
            "dptr": self.dptr,
            "p0": self._port_latch[0],
            "p1": self._port_latch[1],
            "p2": self._port_latch[2],
            "p3": self._port_latch[3],
            "cycles": self.cycles,
            "ops": self.op_count,
            "in_isr": self.in_isr,
            "error": self.error,
        }


def _signed(byte: int) -> int:
    return byte - 256 if byte > 127 else byte
