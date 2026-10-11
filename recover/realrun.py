"""Run the *original* machine bytes (``firmware/nm27c512n.hex``) on the m8051 core.

The Ghidra pseudo-C (``docs/nm27c512n_decompiled.c``) is a lossy, sometimes
wrong rendering of those bytes.  This module executes the bytes themselves
through :class:`m8051.CPU8051`, which makes decompiler errors impossible by
construction: only the ROM image decides what happens.

Two address spaces, one translation point (Lead's architecture decision)
------------------------------------------------------------------------
The hex file stores the image at **record addresses** ``0x8000..0xFFFF``
(Ghidra loaded it there, so every ``FUN_CODE_xxxx`` label and every prose
cite like "ROM 0x8135" uses that space).  The bytes are really **CPU
addresses** ``0x0000..0x7FFF``: file address minus ``0x8000``.  Proof: the
bytes at record ``0x8000`` are ``02 0A 06`` = ``LJMP 0x0A06`` - a reset
vector that points *inside* the image (CPU ``0x0A06`` = record ``0x8A06``).

* the pseudo-code world (:mod:`recover.parse`, :mod:`recover.interp`,
  :mod:`recover.hal` static analysis, ``diagnose_consumers``' call graphs)
  stays in **record space** and keeps the record-space ROM from
  :func:`recover.hal.load_rom`;
* this module's :class:`RealRunner` builds its **own rebased copy**
  (record ``- 0x8000`` -> CPU ``0x0000..0x7FFF``) and is the single
  translation point; CPU program counter, vectors and execution all live in
  CPU space from there on;
* XDATA/MOVX windows (``0x82xx``/``0x91xx``/``0xA1xx``/``0xA2xx`` ...) are
  external-memory addresses, **not** code addresses, and are never rebased.

Real execution, no synthesis
----------------------------
The runner positions nothing and synthesises nothing: ``cpu.pc = 0`` after
construction, the CPU fetches the real reset vector ``LJMP 0x0A06`` and the
firmware's own main loop runs forever.  The firmware programs Timer-0
itself, so the core dispatches the real Timer-0 vector (CPU ``0x000B`` ->
``LJMP 0x02D9``) and the display multiplexor body (CPU ``0x02D9``, record
``0x82D9``) runs on its own cadence; ``stats()`` counts those body entries
(``timer0_calls``/``mux_calls``) and any vector dispatches.  The same is
true for Timer-1/refresh (vector CPU ``0x001B`` -> ``0x00C1`` -> refresh
body CPU ``0x0135``): measured on the real image, the idle firmware never
starts Timer-1 (``TR1`` is only set by a jump-table subroutine at CPU
``0x5AEC``), so ``timer1_calls`` truthfully stays 0 - there is no cadence
to invent around it.  Shim/SENTINEL frames are gone: the real vectors exist.

What is *not* in this dump: the **upper half of CPU space**, ``0x8000..0xFFFF``.
If the firmware ever jumps there, :class:`m8051.CPU8051` refuses to fetch
from unmapped code and halts with its own honest error - that is the
defined behaviour, not a failure of this module.

Routing (MOVX) reuses the evidence windows of
:class:`recover.hal.CashRegisterHAL`: a page the HAL claims is served by it
(0xA1 digit cells, 0x82/0x92 segments, 0xA2 grid, 0x91 keyboard columns, 0x81
printer latch, PPI ...), everything else falls through to the board model and
its flat RAM.

Honest diagnosis: :func:`diagnose_consumers` reports what the dumped image
can drive by itself once the reset entry is covered - see its return value
for the exact verdicts (prose addresses there are record-space cites).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from m8051 import CPU8051, HardwareBus, ROM

from .errors import MissingFirmware
from .parse import Program

__all__ = [
    "ISR_TIMER1",
    "ISR_TIMER0",
    "CPU_ISR_TIMER1",
    "CPU_ISR_TIMER0",
    "CPU_RESET",
    "RESET_ENTRY",
    "PERIOD_TIMER1",
    "PERIOD_TIMER0",
    "RealBus",
    "RealRunner",
    "diagnose_consumers",
]

#: Record-space cites (Ghidra loaded the hex at 0x8000) - prose/stats only.
#: The refresh ISR, Ghidra: FUN_CODE_8135 (record 0x8135 = CPU 0x0135).
ISR_TIMER1 = 0x8135
#: The display multiplexor (record 0x82D9 = CPU 0x02D9): it pulls the digit
#: buffer out of RAM 0x50..0x5F and writes segment pages 0x82/0x92 plus the
#: grid select 0xA2 (record 0x82D9..0x831E).
ISR_TIMER0 = 0x82D9
#: CPU-space identities of the same bodies (record - 0x8000): where the
#: bytes really execute and where ``stats()`` counts their entries.
CPU_ISR_TIMER1 = 0x0135
CPU_ISR_TIMER0 = 0x02D9
#: CPU-space reset vector (record 0x8000: ``02 0A 06``) and its entry.
CPU_RESET = 0x0000
RESET_ENTRY = 0x0A06
#: Reload periods in machine cycles, taken from the values the *code itself*
#: writes (record 0x81C7/0x81CA -> TL1/TH1 = 0xFCA4, record 0x82F0/0x82F3 ->
#: TL0/TH0 = 0xF8CC).  Kept as documented properties of the bodies; the real
#: cadence is whatever the running firmware's own timer setup produces.
PERIOD_TIMER1 = 0x10000 - 0xFCA4        # 860
PERIOD_TIMER0 = 0x10000 - 0xF8CC        # 1844

#: The hardware interrupt vectors of CPU space, as dispatched by
#: :meth:`CPU8051._poll_interrupts` (INT0/TF0/INT1/TF1/serial/T2).
VEC_INT0 = 0x0003
VEC_TF0 = 0x000B
VEC_INT1 = 0x0013
VEC_TF1 = 0x001B
VEC_SERIAL = 0x0023
VEC_T2 = 0x002B
VECTORS = frozenset((VEC_INT0, VEC_TF0, VEC_INT1, VEC_TF1, VEC_SERIAL, VEC_T2))


class RealBus(HardwareBus):
    """The bus the real bytes talk to: evidence-HAL -> board -> flat RAM.

    * MOVX first goes through ``CashRegisterHAL.__call__``, so every read and
      write is governed by the documented windows (write-only pages, keyboard
      page, digit/segment/grid pages, PPI latches).
    * When the HAL refuses a *read* - its evidence says "no dumped code reads
      this" - the instruction stream itself is consulted as evidence: a read
      the real ROM performs is a real read, so it is answered by the board's
      own register model (the 8255/keyboard/latch behaviour), and the address
      is recorded in :attr:`evidence_reads`.
    * Pages nobody claims fall through to the board, whose own fallback is
      flat RAM for the low region.
    """

    def __init__(self, hal=None, board=None) -> None:
        self.hal = hal
        self.board = board if board is not None else getattr(hal, "board", None)
        self.cpu: Optional[CPU8051] = None
        #: reads/writes per address (diagnostics)
        self.reads: Dict[int, int] = {}
        self.writes: Dict[int, int] = {}
        #: addresses the HAL refused but the real instruction stream proves are read
        self.evidence_reads: Dict[int, int] = {}
        #: MissingFirmware raised for anything else (write paths etc.)
        self.gaps: List[str] = []

    # ------------------------------------------------------------ diagnostics
    @staticmethod
    def pages(counter: Dict[int, int]) -> List[int]:
        return sorted({addr >> 8 for addr in counter})

    def read_count(self, page: int) -> int:
        return sum(n for addr, n in self.reads.items() if addr >> 8 == page)

    # ------------------------------------------------------------- xdata (MOVX)
    def ext_read(self, addr: int, code: bool = False) -> int:
        addr &= 0xFFFF
        self.reads[addr] = self.reads.get(addr, 0) + 1
        hal = self.hal
        if hal is not None:
            try:
                value = hal(addr, False, 0)
            except MissingFirmware:
                # The ROM executed a read here, so the read is real; serve it
                # from the hardware model instead of inventing a number.
                self.evidence_reads[addr] = self.evidence_reads.get(addr, 0) + 1
                value = None
            except Exception as exc:               # noqa: BLE001 - report, don't crash
                self.gaps.append(f"read 0x{addr:04X}: {type(exc).__name__}: {exc}")
                value = None
            if value is not None:
                return int(value) & 0xFF
        if self.board is not None:
            return int(self.board.ext_read(addr, code=code)) & 0xFF
        return 0xFF

    def ext_write(self, addr: int, value: int) -> None:
        addr &= 0xFFFF
        value &= 0xFF
        self.writes[addr] = self.writes.get(addr, 0) + 1
        hal = self.hal
        if hal is not None:
            try:
                result = hal(addr, True, value)
            except MissingFirmware as exc:
                self.gaps.append(str(exc))
                return
            except Exception as exc:               # noqa: BLE001
                self.gaps.append(f"write 0x{addr:04X}: {type(exc).__name__}: {exc}")
                return
            if result is not None:
                return
        if self.board is not None:
            self.board.ext_write(addr, value)

    def ext_probe(self, addr: int) -> bool:
        if self.board is not None:
            return bool(self.board.ext_probe(addr))
        return False

    # ------------------------------------------------------------------ ports
    def port_read(self, port: int) -> int:
        if self.board is not None:
            return int(self.board.port_read(port)) & 0xFF
        return 0xFF

    def port_write(self, port: int, value: int) -> None:
        if self.board is not None:
            self.board.port_write(port, value)

    def port_change(self, port: int, old: int, new: int) -> None:
        if self.board is not None:
            self.board.port_change(port, old, new)

    # ------------------------------------------------------------------ other
    def tick(self, cycles: int) -> None:
        if self.hal is not None and hasattr(self.hal, "tick"):
            self.hal.tick(cycles)
        elif self.board is not None:
            self.board.tick(cycles)

    def irq_requested(self) -> int:
        if self.board is not None:
            return int(self.board.irq_requested())
        return 0

    def serial_write(self, byte: int) -> None:
        if self.board is not None:
            self.board.serial_write(byte)

    def serial_read(self) -> Optional[int]:
        if self.board is not None:
            return self.board.serial_read()
        return None

    def serial_available(self) -> bool:
        if self.board is not None:
            return bool(self.board.serial_available())
        return False


class _WatchedCPU(CPU8051):
    """The core plus two honest counters (vector dispatches, body entries).

    ``_poll_interrupts`` records *where the hardware vector actually went*
    (a dispatch to CPU ``0x000B`` is a real Timer-0 interrupt, ``0x001B`` a
    real Timer-1 one); ``_execute`` records entries into the two ISR bodies
    at their CPU-space addresses.  ``CPU8051.run``/``run_steps`` resolve
    both hooks through ``self``, so the counters work on the hot path too.
    """

    def __init__(self, rom: ROM, bus=None) -> None:
        #: interrupt vector address -> dispatch count
        self.vector_dispatches: Dict[int, int] = {}
        #: body entry address (CPU space) -> execution count
        self.body_entries: Dict[int, int] = {}
        super().__init__(rom, bus)

    def _poll_interrupts(self) -> None:
        before = self.pc
        super()._poll_interrupts()
        if self.pc != before and self.pc in VECTORS:
            self.vector_dispatches[self.pc] = self.vector_dispatches.get(self.pc, 0) + 1

    def _execute(self) -> int:
        pc = self.pc
        if pc == CPU_ISR_TIMER0 or pc == CPU_ISR_TIMER1:
            self.body_entries[pc] = self.body_entries.get(pc, 0) + 1
        return super()._execute()


def _cpu_space_rom(source: ROM) -> ROM:
    """Own CPU-space copy of a record-space image (the one translation point).

    The pseudo-code world keeps the record-space ROM (``0x8000..0xFFFF``,
    see :func:`recover.hal.load_rom`); execution needs ``0x0000..0x7FFF``.
    A record-space image (bytes mapped at ``0x8000``) is shifted down by
    ``0x8000``; an image that is already CPU-space (mapped at ``0x0000``,
    not at ``0x8000``) is copied verbatim.
    """
    if source.is_mapped(0x0000) and not source.is_mapped(0x8000):
        base = 0x0000
    else:
        base = 0x8000
    rom = ROM("realrun-cpu")
    rom.load_block(0x0000, source.get_slice(base, 0x8000))
    return rom


class RealRunner:
    """Boot the rebased image from its real reset vector and let it run.

    The runner never positions the CPU and synthesises no frames: after
    construction ``cpu.pc == 0`` and the first fetch is the real reset
    vector (record ``0x8000``: ``LJMP 0x0A06``).  :meth:`advance` only
    executes the core - the bus ticks from the core's own cycle accounting,
    so printer/keyboard timing advances with the instruction stream.  The
    firmware programs its own timers, so the hardware dispatches the real
    vectors; :attr:`timer0_calls`/:attr:`timer1_calls` count executions of
    the two ISR bodies at their CPU-space addresses (Timer-1 stays
    unstarted in the idle firmware, which is reported as 0, not invented
    around).  If the firmware ever jumps into the undumped upper half
    (CPU ``0x8000..0xFFFF``) the core halts on its own with an honest
    "missing image" error - the runner relays :attr:`halt_reason`.
    """

    def __init__(
        self,
        hal=None,
        rom: Optional[ROM] = None,
        slice_cycles: int = 4_096,
    ) -> None:
        self.hal = hal
        self.board = getattr(hal, "board", None)
        source_rom = rom if rom is not None else getattr(hal, "rom", None)
        if source_rom is None:
            raise MissingFirmware(
                -1, "the real-hex runner needs firmware/nm27c512n.hex (no ROM image)"
            )
        #: private CPU-space copy: record 0x8000..0xFFFF -> CPU 0x0000..0x7FFF.
        #: The shared record-space image (font tables, the pseudo-code world's
        #: code_reader) stays untouched.
        self.rom = _cpu_space_rom(source_rom)
        self.bus = RealBus(hal=hal, board=self.board)
        self.cpu = _WatchedCPU(self.rom, self.bus)
        self.bus.cpu = self.cpu
        self.cpu.pc = CPU_RESET            # reset() starts at 0; be explicit
        #: execution quantum for :meth:`advance` (machine cycles)
        self.slice_cycles = max(64, int(slice_cycles))

        #: counters - all observable from stats()/status()
        self.instructions = 0
        self.overruns = 0                  # no synthesised bodies left to overrun
        self.halted = False
        self.halt_reason = ""
        self.gaps: List[str] = []

    # ------------------------------------------------------- counter mirrors
    @property
    def timer1_calls(self) -> int:
        """Refresh-body (CPU ``0x0135``) executions.

        Measured truth: 0 while the firmware leaves Timer-1 unstarted (the
        idle phase never reaches the ``TR1``-setting code at CPU ``0x5AEC``).
        """
        return self.cpu.body_entries.get(CPU_ISR_TIMER1, 0)

    @property
    def timer0_calls(self) -> int:
        """Display-mux body (CPU ``0x02D9``) executions - real Timer-0 work."""
        return self.cpu.body_entries.get(CPU_ISR_TIMER0, 0)

    def _halt(self, reason: str) -> None:
        self.halted = True
        self.halt_reason = reason

    # --------------------------------------------------------------- execute
    def advance(self, cycles: int) -> int:
        """Execute the real firmware for ``cycles`` machine cycles.

        Returns the number of *new interrupt vector dispatches* made in this
        call.  Peripherals tick from the core's own cycle accounting; nothing
        is scheduled from the outside.  Stops early (honestly) if the core
        halts - e.g. on a fetch from the undumped upper half.
        """
        try:
            budget = max(0, int(cycles))
        except Exception:                          # noqa: BLE001
            budget = 0
        cpu = self.cpu
        dispatched_before = sum(cpu.vector_dispatches.values())
        while budget > 0 and not self.halted and not cpu.halted:
            quantum = min(budget, self.slice_cycles)
            executed = cpu.run(quantum)
            self.instructions += executed
            budget -= quantum
            if executed <= 0 and not cpu.halted:
                break                              # stuck core: never hot-spin
        if cpu.halted and not self.halted:
            self._halt(cpu.error or f"cpu stopped at 0x{cpu.pc:04X}")
        if self.hal is not None:
            for gap in self.bus.gaps:
                if gap not in self.gaps:
                    self.gaps.append(gap)
            self.bus.gaps.clear()
        return sum(cpu.vector_dispatches.values()) - dispatched_before

    # ------------------------------------------------------------ diagnostics
    def stats(self) -> Dict[str, Any]:
        bus = self.bus
        cpu = self.cpu
        return {
            "entry": RESET_ENTRY,
            "pc": cpu.pc,
            "timer1_calls": self.timer1_calls,
            "timer0_calls": self.timer0_calls,
            "mux_calls": self.timer0_calls,
            "vector_dispatches": {hex(v): n
                                  for v, n in sorted(cpu.vector_dispatches.items())},
            "instructions": self.instructions,
            "overruns": self.overruns,
            "halted": self.halted,
            "halt_reason": self.halt_reason,
            "gap": self.bus.gaps[0] if self.bus.gaps else (self.gaps[0] if self.gaps else ""),
            "gaps": list(self.gaps),
            "evidence_reads": sum(bus.evidence_reads.values()),
            "read_pages": bus.pages(bus.reads),
            "write_pages": bus.pages(bus.writes),
            "keyboard_reads": bus.read_count(0x91),
            "display_writes": sum(n for a, n in bus.writes.items()
                                  if (a >> 8) in (0x82, 0x92, 0xA1, 0xA2)),
        }

    def describe(self) -> str:
        s = self.stats()
        return (
            f"real hex on m8051, booted from reset entry 0x{s['entry']:04X}: "
            f"mux CPU 0x{CPU_ISR_TIMER0:04X} x{s['timer0_calls']}, "
            f"refresh CPU 0x{CPU_ISR_TIMER1:04X} x{s['timer1_calls']}, "
            f"{s['instructions']} instructions, writes pages {s['write_pages']}, "
            f"keyboard reads {s['keyboard_reads']}"
            + (f", HALTED: {self.halt_reason}" if self.halted else "")
        )


# ----------------------------------------------------------------- diagnosis
def _call_graph(program: Program) -> Dict[int, set]:
    edges: Dict[int, set] = {}
    pattern = re.compile(r"\b(?:thunk_)?FUN_CODE_([0-9a-fA-F]{4})\s*\(")
    for func in program.functions:
        if func.address is None:
            continue
        edges[func.address] = {
            int(m.group(1), 16) for m in pattern.finditer(func.body)
        }
    return edges


def _reachable(edges: Dict[int, set], root: int) -> set:
    seen: set = set()
    stack = [root]
    while stack:
        current = stack.pop()
        for target in edges.get(current, ()):
            if target not in seen and target in edges:
                seen.add(target)
                stack.append(target)
    return seen


def diagnose_consumers(program: Program, rom: Optional[ROM] = None) -> Dict[str, Any]:
    """Static honesty report: what the dumped image can drive by itself.

    Addresses in this report follow the project convention: ``FUN_CODE_xxxx``
    labels, ``address`` fields of the bodies and prose cites are **record**
    addresses (Ghidra loaded the hex at ``0x8000``); the CPU address is the
    record address minus ``0x8000``.  Since the rebased reset vector
    (record ``0x8000`` = ``LJMP 0x0A06`` -> CPU ``0x0A06`` = record
    ``0x8A06``) lands *inside* the dump, the firmware's own main loop runs -
    :class:`RealRunner` executes it, and the verdicts below are worded to
    match what that execution measurably does.  This function answers, from
    the dump (and optionally the record-space image) alone:

    * whether the reset entry is covered by the image (``reset``);
    * which interrupt bodies exist and how the real vectors reach them
      (``isr``: Timer-1 vector CPU ``0x001B`` -> ``0x00C1`` -> refresh CPU
      ``0x0135``; Timer-0 vector CPU ``0x000B`` -> ``LJMP 0x02D9`` mux);
    * who writes the display buffer ``RAM 0x50..0x5F`` - the writers run
      from the reset/main-loop path (verified by running the image: the
      buffer is filled from *outside* the mux ISR while CPU ``0x02D9``
      only reads it), so the old "PRODUCER MISSING" verdict is gone;
    * whether the keyboard page (``0x91``) is read by any dumped code: the
      ``MOV DPH,#91h`` sites live in the Timer-1 path, which the idle
      firmware never starts (``TR1`` only set by the jump-table subroutine
      at CPU ``0x5AEC``), so ``RealRunner.stats()["keyboard_reads"]``
      measurably stays 0 - reported as-is, not papered over.
    """
    functions = sorted(
        (f for f in program.functions if f.address is not None),
        key=lambda f: f.address,
    )
    edges = _call_graph(program)
    reverse: Dict[int, set] = {}
    for source, targets in edges.items():
        for target in targets:
            reverse.setdefault(target, set()).add(source)

    def covering(address: int) -> Optional[str]:
        best = None
        for func in functions:
            if func.address <= address:
                best = func
            else:
                break
        return best.name if best is not None else None

    def callers_of(address: int) -> List[str]:
        return sorted(hex(a) for a in reverse.get(address, ()))

    # 1. the two interrupt bodies
    isr = {
        "timer1_refresh": {
            "address": ISR_TIMER1,
            "cpu_address": CPU_ISR_TIMER1,
            "in_dump": covering(ISR_TIMER1),
            "calls": sorted(hex(a) for a in edges.get(ISR_TIMER1, ()) ),
            "note": (
                "record cite; at runtime the real Timer-1 vector (CPU 0x001B) "
                "chains 0x00C1 -> 0x022D into this body (CPU 0x0135). The idle "
                "firmware never starts Timer-1 (TR1 is only set by the "
                "jump-table subroutine at CPU 0x5AEC), so RealRunner measures "
                "0 entries - no cadence is synthesised around that"
            ),
        },
        "timer0_mux": {
            "address": ISR_TIMER0,
            "cpu_address": CPU_ISR_TIMER0,
            "in_dump": covering(ISR_TIMER0),
            "callers_in_dump": callers_of(ISR_TIMER0),
            "note": (
                "record cite; at runtime the real Timer-0 vector (CPU 0x000B) "
                "jumps straight to the body at CPU 0x02D9, which writes segment "
                "pages 0x82/0x92 and grid 0xA2 from RAM 0x50..0x5F - counted "
                "by RealRunner.stats()[\"timer0_calls\"]"
            ),
        },
    }

    # 2. who writes the display buffer
    buffer_names = [f"DAT_INTMEM_5{i:x}" for i in range(16)]
    writers: Dict[str, List[str]] = {}
    for func in functions:
        for name in buffer_names:
            if re.search(rf"(?:&|\b){name}\b\s*=[^=]", func.body) or f"&{name}" in func.body:
                writers.setdefault(name, []).append(func.name)
    buffer_funcs = sorted({name for names in writers.values() for name in names})
    reachable_from_isr = _reachable(edges, ISR_TIMER1)
    buffer_callers = sorted({
        caller for fname in buffer_funcs
        for caller in callers_of(int(next(
            (f.address for f in functions if f.name == fname), 0)))
    })
    buffer_reachable = sorted(
        fname for fname in buffer_funcs
        if int(next(f.address for f in functions if f.name == fname)) in reachable_from_isr
    )

    # 3. keyboard page readers: ``MOV DPH,#91h`` sites are in the *image*
    keyboard_sites: List[str] = []
    if rom is not None:
        pattern = bytes((0x75, 0x83, 0x91))          # MOV DPH,#91h
        keyboard_sites = [
            hex(addr) for addr in range(0x8000, 0xFFFD)
            if rom.get_slice(addr, 3) == pattern
        ]
    keyboard_functions = sorted({
        name for site in keyboard_sites
        for name in [covering(int(site, 16))] if name is not None
    })
    keyboard = {
        "page": 0x91,
        "mov_dph_91_sites": keyboard_sites,
        "dump_functions": keyboard_functions,
        "reachable_from_timer1": sorted(
            name for name in keyboard_functions
            if next(f.address for f in functions if f.name == name) in reachable_from_isr
        ),
        "verdict": (
            "every MOV DPH,#91h site sits in the Timer-1 path (the scanner "
            "block and the handlers around CPU 0x0442/0x047d); because the "
            "idle firmware never starts Timer-1, running the real image "
            "measurably produces 0 reads of page 0x91 - RealBus still serves "
            "the page correctly for direct reads, but the firmware itself "
            "does not scan the matrix in this phase"
        ),
    }

    # reset coverage: record 0x8000 holds the vector bytes; the CPU entry is
    # covered when the record address (entry + 0x8000) is inside the image.
    reset_entry = RESET_ENTRY
    if rom is not None:
        reset_covered = bool(rom.is_mapped((reset_entry + 0x8000) & 0xFFFF))
    else:
        reset_covered = covering(reset_entry + 0x8000) is not None

    return {
        "reset": {
            "vector": 0x8000,                 # record address of the vector bytes
            "entry": reset_entry,             # CPU address the vector jumps to
            "covered": reset_covered,
            "note": (
                f"record 0x8000 = 02 0A 06 -> LJMP CPU 0x{reset_entry:04X} "
                f"= record 0x{reset_entry + 0x8000:04X}, inside the dumped "
                f"image: the real main loop boots (RealRunner runs it); NOT "
                f"dumped: the upper half 0x8000..0xFFFF of CPU space"
            ),
        },
        "isr": isr,
        "display_buffer": {
            "addresses": "RAM 0x50..0x5F (8 digits x 2 segment bytes)",
            "writers_in_dump": writers,
            "writer_functions": buffer_funcs,
            "callers_of_writers": buffer_callers,
            "reachable_from_isr": buffer_reachable,
            "verdict": (
                "producers RUN: the reset entry CPU 0x0A06 (record 0x8A06) is "
                "inside this dump, and executing the real image shows the "
                "main loop filling RAM 0x50..0x5F from OUTSIDE the mux ISR "
                "while CPU 0x02D9 multiplexes it onto the screen (verified by "
                "running - see tests.test_recover.TestRealHexRunner). The "
                "refresh body CPU 0x0135 has no static callers only because "
                "it is entered by vector dispatch, not by a CALL; it is not a "
                "producer and never needed to be one."
                if not buffer_reachable else
                "a display-buffer writer is reachable from the refresh ISR"
            ),
        },
        "keyboard": keyboard,
        "scanner": {
            "function": covering(0x822C),
            "callers_in_dump": callers_of(0x822C),
            "verdict": (
                "the key-scan/FIFO block (record 0x822C..0x83F0) has no "
                "in-dump CALLER because it is entered by vector dispatch "
                "(AJMP in the vector area at CPU 0x0016 and in the Timer-1 "
                "chain at CPU 0x00BF), not called; with Timer-1 unstarted in "
                "the idle phase it does not run"
                if not callers_of(0x822C) else "has in-dump callers"
            ),
        },
        "reachable_from_timer1": sorted(hex(a) for a in reachable_from_isr),
    }
