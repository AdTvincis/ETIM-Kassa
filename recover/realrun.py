"""Run the *original* machine bytes (``firmware/nm27c512n.hex``) on the m8051 core.

The Ghidra pseudo-C (``docs/nm27c512n_decompiled.c``) is a lossy, sometimes
wrong rendering of those bytes.  This module executes the bytes themselves
through :class:`m8051.CPU8051`, which makes decompiler errors impossible by
construction: only the ROM image decides what happens.

What is synthesised here is *glue only* - the same glue the missing half of
the ROM used to provide:

* **the reset vector is unusable**: the image's own ``LJMP 0x0A06`` lands in
  ``0x0000..0x7FFF``, which was a second device (the AT89C55's internal ROM)
  and was never dumped.  Instead of pretending to boot, the scheduler invokes
  the two *real* interrupt bodies out of the image on their own timer
  cadences, exactly as the Timer-0/Timer-1 vectors would have:

  ``0x8135``  the refresh ISR (``FUN_CODE_8135``) - reload cadence
              ``0x10000 - 0xFCA4 = 0x35C`` cycles, which is the value the ISR
              itself writes at ROM 0x81C7/0x81CA;
  ``0x82D9``  the display multiplexor (digit buffer RAM 0x50..0x5F -> segment
              pages 0x82/0x92 + grid 0xA2) - cadence ``0x10000 - 0xF8CC =
              0x734`` cycles, the reload the block writes at ROM 0x82F0/0x82F3.

  Each call is a real call: the return frame the epilogues expect is pushed,
  the core executes real instructions, and the return lands in the RETI stub
  of :mod:`m8051.shim` (the shim also backs stray vectors, e.g. the INT0 pulse
  the board raises on a key press).

* **no business logic**: nothing here decides what the firmware *should* do.
  Every byte executed comes from the image; the only invented state is the
  call frame and the cadence above.

Routing (MOVX) reuses the evidence windows of
:class:`recover.hal.CashRegisterHAL`: a page the HAL claims is served by it
(0xA1 digit cells, 0x82/0x92 segments, 0xA2 grid, 0x91 keyboard columns, 0x81
printer latch, PPI ...), everything else falls through to the board model and
its flat RAM.

Honest diagnosis: :func:`diagnose_consumers` reports which of the firmware's
event consumers exist in the dumped half and which are only reachable from the
missing low ROM - see its return value for the exact verdicts.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from m8051 import CPU8051, HardwareBus, ROM
from m8051.shim import SHIM_BASE, build_shim, shim_summary

from .errors import MissingFirmware
from .parse import Program

__all__ = [
    "ISR_TIMER1",
    "ISR_TIMER0",
    "PERIOD_TIMER1",
    "PERIOD_TIMER0",
    "RealBus",
    "RealRunner",
    "diagnose_consumers",
]

#: The refresh ISR the Timer-1 vector must have dispatched (Ghidra: FUN_CODE_8135).
ISR_TIMER1 = 0x8135
#: The display multiplexor the Timer-0 vector must have dispatched: it pulls the
#: digit buffer out of RAM 0x50..0x5F and writes segment pages 0x82/0x92 plus
#: the grid select 0xA2 (ROM 0x82D9..0x831E).
ISR_TIMER0 = 0x82D9
#: Cadences in machine cycles, taken from the reload values the *code itself*
#: writes: 0x81C7/0x81CA -> TL1/TH1 = 0xFCA4, 0x82F0/0x82F3 -> TL0/TH0 = 0xF8CC.
PERIOD_TIMER1 = 0x10000 - 0xFCA4        # 860
PERIOD_TIMER0 = 0x10000 - 0xF8CC        # 1844
#: Return stub of the shim (``RETI``): every synthesised call returns here.
SENTINEL = SHIM_BASE + 0x20

#: The register frame the Timer-1 epilogue (0x83F0) pops: ``POP DPH; POP PSW;
#: POP ACC; SETB EA; CLR P3.4; RETI``.  Push order is therefore PCL, PCH, ACC,
#: PSW, DPH - the top of the stack must hold DPH, and ``RETI`` reads PCH first.
FRAME_TIMER1: Tuple[str, ...] = ("acc", "psw", "dph")
#: The Timer-0 block pushes PSW/DPH/DPL itself (0x82D9..0x82DD) and exits via
#: the four-pop epilogue at 0x83EC, so the caller only owes one spare slot
#: (popped into ACC) below the return address.
FRAME_TIMER0: Tuple[str, ...] = ("acc_slot",)


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


class RealRunner:
    """Schedule the two real interrupt bodies of the image on their cadences.

    The runner never invents an instruction: it positions the CPU at a real
    entry point (``0x8135`` / ``0x82D9``), pushes the frame their epilogues
    pop, executes until the core reaches the shim's ``RETI`` stub, and restores
    the stack.  Everything in between is the firmware's own bytes.
    """

    def __init__(
        self,
        hal=None,
        rom: Optional[ROM] = None,
        timer1_period: int = PERIOD_TIMER1,
        timer0_period: int = PERIOD_TIMER0,
        step_budget: int = 30_000,
    ) -> None:
        self.hal = hal
        self.board = getattr(hal, "board", None)
        source_rom = rom if rom is not None else getattr(hal, "rom", None)
        if source_rom is None:
            raise MissingFirmware(
                -1, "the real-hex runner needs firmware/nm27c512n.hex (no ROM image)"
            )
        #: private copy: the shim lives in *our* low half, the shared image
        #: (font tables, the pseudocode path's code_reader) stays untouched
        self.rom = ROM("realrun")
        self.rom.load_block(0x8000, source_rom.get_slice(0x8000, 0x8000))
        self.bus = RealBus(hal=hal, board=self.board)
        self.cpu = CPU8051(self.rom, self.bus)
        self.bus.cpu = self.cpu
        self.shim = self._install_shim()

        self.timer1_period = max(1, int(timer1_period))
        self.timer0_period = max(1, int(timer0_period))
        self.step_budget = int(step_budget)
        self._due_timer1 = 0
        self._due_timer0 = 0

        #: counters - all observable from status()
        self.timer1_calls = 0
        self.timer0_calls = 0
        self.instructions = 0
        self.overruns = 0
        self.halted = False
        self.halt_reason = ""
        self.gaps: List[str] = []

    # ------------------------------------------------------------------ setup
    def _install_shim(self) -> Dict[int, int]:
        """Put the transparent vectors/RETI stub into *our* low half."""
        mem = build_shim(reset_target=0x8000)
        for address, byte in mem.items():
            self.rom.load_block(address, bytes((byte & 0xFF,)))
        return mem

    # ------------------------------------------------------------------ calls
    def _call(self, entry: int, frame: Sequence[str]) -> bool:
        """Execute one real function body: set PC, run to the RETI stub."""
        cpu = self.cpu
        if self.halted:
            return False
        saved_sp = cpu.sfr[0x81]
        # return frame: PCL first, then PCH (RETI reads the high byte from the
        # top of the stack), then the registers the epilogue pops
        cpu.push(SENTINEL & 0xFF)
        cpu.push((SENTINEL >> 8) & 0xFF)
        for slot in frame:
            if slot == "acc_slot":
                cpu.push(cpu.sfr[0xE0])       # popped back into ACC: no state loss
            elif slot == "acc":
                cpu.push(cpu.sfr[0xE0])
            elif slot == "psw":
                cpu.push(cpu.sfr[0xD0])
            elif slot == "dph":
                cpu.push(cpu.sfr[0x83])
            elif slot == "dpl":
                cpu.push(cpu.sfr[0x82])
        cpu.pc = entry
        executed = 0
        while executed < self.step_budget:
            if cpu.halted or cpu.pc == SENTINEL:
                break
            cpu.step()
            executed += 1
        completed = (not cpu.halted) and cpu.pc == SENTINEL
        cpu.sfr[0x81] = saved_sp          # the frame is ours: balance it always
        self.instructions += executed
        if not completed and not cpu.halted:
            self.overruns += 1            # the body did not return in budget
        if cpu.halted and not self.halted:
            self._halt(cpu.error or f"cpu stopped at 0x{cpu.pc:04X}")
        return completed

    def _halt(self, reason: str) -> None:
        self.halted = True
        self.halt_reason = reason

    # --------------------------------------------------------------- schedule
    def advance(self, cycles: int) -> int:
        """Advance the hardware by ``cycles`` and dispatch the real ISRs.

        Returns the number of ISR bodies executed in this call.  Peripherals
        (printer/keyboard timing) tick in real time; each timer fires its body
        on the cadence the firmware's own reload values define.
        """
        try:
            budget = max(0, int(cycles))
        except Exception:                          # noqa: BLE001
            budget = 0
        calls = 0
        while budget > 0 and not self.halted:
            slice_cycles = min(self.timer1_period, budget)
            self.bus.tick(slice_cycles)
            self._due_timer1 += slice_cycles
            self._due_timer0 += slice_cycles
            budget -= slice_cycles
            while self._due_timer1 >= self.timer1_period and not self.halted:
                self._due_timer1 -= self.timer1_period
                self.timer1_calls += 1
                calls += 1
                self._call(ISR_TIMER1, FRAME_TIMER1)
            while self._due_timer0 >= self.timer0_period and not self.halted:
                self._due_timer0 -= self.timer0_period
                self.timer0_calls += 1
                self._call(ISR_TIMER0, FRAME_TIMER0)
        if self.hal is not None:
            for gap in self.bus.gaps:
                if gap not in self.gaps:
                    self.gaps.append(gap)
            self.bus.gaps.clear()
        return calls

    # ------------------------------------------------------------ diagnostics
    def stats(self) -> Dict[str, Any]:
        bus = self.bus
        return {
            "timer1_calls": self.timer1_calls,
            "timer0_calls": self.timer0_calls,
            "instructions": self.instructions,
            "overruns": self.overruns,
            "halted": self.halted,
            "halt_reason": self.halt_reason,
            "gap": self.bus.gaps[0] if self.bus.gaps else (self.gaps[0] if self.gaps else ""),
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
            f"real hex on m8051: ISR 0x8135 x{s['timer1_calls']}, "
            f"mux 0x82D9 x{s['timer0_calls']}, {s['instructions']} instructions, "
            f"writes pages {s['write_pages']}, keyboard reads {s['keyboard_reads']}"
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
    """Static honesty report: what the dumped half can drive *by itself*.

    The reset vector of the real image is ``LJMP 0x0A06`` and ``0x0A06`` lives
    in the missing low ROM, so nothing in the dumped half ever *starts* the
    firmware's tasks.  This function answers, from the dump (and optionally the
    image) alone:

    * which interrupt bodies exist (``0x8135`` refresh, ``0x82D9`` mux);
    * whether the keyboard page (``0x91``) is read by any dumped code, and
      whether that code is reachable from the ISRs;
    * who writes the display buffer ``RAM 0x50..0x5F`` - and whether anything
      in the dumped half calls those writers.  When the answer is "no callers
      below 0x8000 only", the honest verdict is that the consumer of key
      events lives in the missing half.
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
            "in_dump": covering(ISR_TIMER1),
            "calls": sorted(hex(a) for a in edges.get(ISR_TIMER1, ()) ),
            "note": "invoked by the scheduler (the real Timer-1 vector is in the missing half)",
        },
        "timer0_mux": {
            "address": ISR_TIMER0,
            "in_dump": covering(ISR_TIMER0),
            "callers_in_dump": callers_of(ISR_TIMER0),
            "note": "writes segment pages 0x82/0x92 and grid 0xA2 from RAM 0x50..0x5F",
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
            "the image reads the keyboard page itself - RealBus counts those "
            "reads; which function does it, and is that function reachable from "
            "the refresh ISR (see reachable_from_timer1)"
        ),
    }

    return {
        "reset": {
            "vector": 0x8000,
            "entry": 0x0A06,
            "covered": False,
            "note": "LJMP 0x0A06 -> missing half: the firmware's main loop never starts",
        },
        "isr": isr,
        "display_buffer": {
            "addresses": "RAM 0x50..0x5F (8 digits x 2 segment bytes)",
            "writers_in_dump": writers,
            "writer_functions": buffer_funcs,
            "callers_of_writers": buffer_callers,
            "reachable_from_isr": buffer_reachable,
            "verdict": (
                "PRODUCER MISSING: every writer of the display buffer is called "
                "only from 0x0000..0x7FFF (the missing main loop). The real ISRs "
                "can multiplex whatever is in RAM, but nothing in the dumped half "
                "puts characters there - so the screen shows the contents of the "
                "power-on registers during the first sweep and then goes blank."
                if not buffer_reachable else
                "a display-buffer writer is reachable from the refresh ISR"
            ),
        },
        "keyboard": keyboard,
        "scanner": {
            "function": covering(0x822C),
            "callers_in_dump": callers_of(0x822C),
            "verdict": (
                "the key-scan/FIFO block at 0x822C..0x83F0 has no caller in the "
                "dumped half: it is entered from the missing main loop"
                if not callers_of(0x822C) else "has in-dump callers"
            ),
        },
        "reachable_from_timer1": sorted(hex(a) for a in reachable_from_isr),
    }
