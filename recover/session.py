"""High-level driver: recovered firmware + HAL behind one thread-safe object.

The UI (``main.py``) owns a :class:`RecoveredFirmwareSession` and calls:

* :meth:`RecoveredFirmwareSession.boot` once,
* :meth:`RecoveredFirmwareSession.run` from a background daemon thread,
* ``display`` / ``keyboard`` / ``printer`` / :meth:`status` from the Tk thread.

Everything is guarded by one :class:`threading.RLock`, and the display/receipt
accessors snapshot strings inside that lock, so a torn read is impossible.

Honesty rules
-------------
* ``boot()`` never raises and never invents a program.  The reset vector of
  ``firmware/nm27c512n.hex`` (record ``0x8000``: ``LJMP 0x0A06``) points at
  CPU ``0x0A06`` = record ``0x8A06``, which **is** inside the dumped image -
  the lower half ``0x0000..0x7FFF`` of CPU space (the hex's record addresses
  ``0x8000..0xFFFF`` are exactly that half).  So the original bytes boot from
  the real reset vector through :mod:`recover.realrun` and
  ``status()["entry_covered"]`` is ``True``.  What the dump does *not* have
  is the **upper half** ``0x8000..0xFFFF`` of CPU space; if execution ever
  fetches there, the core halts honestly with a "missing image" error.
* ``status()["source"]`` is ``"recovered"`` when the real recovered machine
  bytes are driving the peripherals (the default path), and ``"demo"`` when
  the deterministic built-in sequence is (explicit ``demo=True`` opt-in
  only).  The demo path uses the *same* HAL windows as the recovered path.
* ``run(cycles)`` returns promptly (bounded work per call) and never raises:
  failures are recorded into ``status()["reason"]``.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .errors import MissingFirmware
from .hal import CashRegisterHAL, bind_recovered_aliases, load_rom
from .interp import FunctionLibrary, Interpreter
from .namespace import Machine
from .parse import parse_dump
from .runtime import RuntimeHelpers

__all__ = ["RecoveredFirmwareSession", "DEFAULT_DUMP", "DEFAULT_ROM"]

DEFAULT_DUMP = "docs/nm27c512n_decompiled.c"
DEFAULT_ROM = "firmware/nm27c512n.hex"

#: The reset vector's **record** address - the file stores the image at
#: record 0x8000..0xFFFF (Ghidra's load address), and the bytes there are
#: ``02 0A 06`` = LJMP.  CPU address = record - 0x8000, so the vector bytes
#: really live at CPU 0x0000, the true 8051 reset address.
RESET_VECTOR = 0x8000

#: The CPU address the reset vector jumps to (record 0x8A06 = 0x0A06+0x8000).
RESET_ENTRY = 0x0A06

#: Offset translating record space <-> CPU space (record - 0x8000 = CPU).
REBASE = 0x8000

#: The recovered interrupt handler that drives the display and samples P1.3.
#: ROM 0x8135: JBC 17h / JNB 19h / JNB P1.3 / ... (see docs/hardware_evidence.md).
REFRESH_ISR = "FUN_CODE_8135"

#: The recovered routine that writes xdata 0xA100|digit (ROM 0x810F).
DISPLAY_WRITER = "FUN_CODE_810f"

#: Safety caps so a background ``run()`` can never spin.
MAX_ISR_PER_RUN = 32
MAX_STEPS_PER_RUN = 200_000


class RecoveredInterpreter(Interpreter):
    """Compatibility name for this session's statement runner.

    This class used to carry a private, corrected copy of ``Interpreter._run``:
    the original one never advanced ``frame.i`` for straight-line statements,
    so every recovered function spun to the 2,000,000-step cap.  The real
    interpreter has since been fixed where it lives (``recover/interp.py``):
    the cursor advances before dispatch, ``while``/``for`` test their condition
    before the first iteration *and* again in the loop tail, ``break``/
    ``continue`` unwind to the innermost loop or switch, and labels are
    recorded as ``(statement list, index)`` pairs so ``goto`` can rebuild the
    block chain instead of writing an unrelated cursor.

    Nothing needs overriding any more; the class remains so that this module's
    own construction site (``library.interpreter = RecoveredInterpreter(...)``)
    and older references keep working, with the session getting the fixed
    behaviour.
    """

DEMO_DIGITS = "12345678"
DEMO_RECEIPT = (
    "KASSA ETIM",
    "PRODAZHA",
    "ITOG  1234.56",
)


def _resolve(path: str) -> str:
    """Resolve ``path`` against cwd, the repo root and this package."""
    if os.path.isabs(path) and os.path.isfile(path):
        return path
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    for base in (os.getcwd(), root, here):
        candidate = os.path.join(base, path)
        if os.path.isfile(candidate):
            return candidate
    return path


class _LockedDisplay:
    """Thread-safe view of the board display (``docs/board_contract.md`` 2)."""

    def __init__(self, session: "RecoveredFirmwareSession", obj) -> None:
        self._session = session
        self._obj = obj

    @property
    def columns(self) -> int:
        return int(getattr(self._obj, "columns", 8))

    @property
    def lines(self) -> int:
        return int(getattr(self._obj, "lines", 1))

    def text(self) -> str:
        with self._session._lock:
            return str(self._obj.text())

    def cell_segments(self, index: int) -> int:
        with self._session._lock:
            getter = getattr(self._obj, "cell_segments", None)
            return int(getter(index)) if getter else 0

    def render_rows(self, scale: int = 1) -> List[str]:
        with self._session._lock:
            getter = getattr(self._obj, "render_rows", None)
            if getter is None:
                return [""]
            return list(getter(scale))

    def __repr__(self) -> str:                    # pragma: no cover
        return f"<display {self.columns}x{self.lines} {self.text()!r}>"


class _LockedKeyboard:
    """Thread-safe view of the board keyboard (``docs/board_contract.md`` 3)."""

    def __init__(self, session: "RecoveredFirmwareSession", obj) -> None:
        self._session = session
        self._obj = obj

    @property
    def keys(self) -> List[str]:
        with self._session._lock:
            return list(getattr(self._obj, "keys", []))

    def press(self, name: str) -> None:
        with self._session._lock:
            self._obj.press(name)

    def release(self, name: str) -> None:
        with self._session._lock:
            self._obj.release(name)

    def tap(self, name: str) -> None:
        with self._session._lock:
            self._obj.tap(name)

    def is_pressed(self, name: str) -> bool:
        with self._session._lock:
            return bool(self._obj.is_pressed(name))

    def __repr__(self) -> str:                    # pragma: no cover
        return f"<keyboard {len(self.keys)} keys>"


class _LockedPrinter:
    """Thread-safe view of the board printer (``docs/board_contract.md`` 4)."""

    def __init__(self, session: "RecoveredFirmwareSession", obj) -> None:
        self._session = session
        self._obj = obj

    def paper(self) -> List[str]:
        with self._session._lock:
            return list(self._obj.paper())

    def text(self) -> str:
        with self._session._lock:
            return "\n".join(self._obj.paper())

    def clear(self) -> None:
        with self._session._lock:
            self._obj.clear()

    def feed(self, lines: int = 1) -> None:
        with self._session._lock:
            self._obj.feed(lines)

    def is_busy(self) -> bool:
        with self._session._lock:
            return bool(self._obj.is_busy())

    def __repr__(self) -> str:                    # pragma: no cover
        return f"<printer {len(self.paper())} lines>"


class RecoveredFirmwareSession:
    """Run the recovered firmware against the emulated cash register.

    Parameters
    ----------
    dump_path:
        Ghidra pseudo-C dump (``docs/nm27c512n_decompiled.c``).
    hardware:
        Optional pre-built board (``board.cashboard.CashRegisterBoard``).  When
        omitted the HAL builds one.
    demo:
        ``False`` (default): **never invent a program**.  The session runs the
        original machine bytes (``firmware/nm27c512n.hex``) on the m8051 core
        through :mod:`recover.realrun`, reporting ``source == "recovered"``.
        ``True`` (explicit opt-in only): when the real entry point is
        unreachable, drive a deterministic built-in sequence through the same
        HAL so the UI has something to show, and report ``source == "demo"``.
        The flag is kept for demonstrations; the GUI path no longer uses it.
    rom_path:
        Intel-HEX image used for the reset vector, ROM tables and the real
        execution path.
    strict:
        Forwarded to :class:`~recover.hal.CashRegisterHAL`: reading a window the
        dump never reads reports :class:`MissingFirmware`.
    """

    def __init__(
        self,
        dump_path: str = DEFAULT_DUMP,
        hardware=None,
        demo: bool = False,
        rom_path: str = DEFAULT_ROM,
        strict: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self.dump_path = dump_path
        self.rom_path = rom_path
        self.demo_enabled = bool(demo)
        self.strict = bool(strict)

        self.machine: Optional[Machine] = None
        self.helpers: Optional[RuntimeHelpers] = None
        self.library: Optional[FunctionLibrary] = None
        self.hal: Optional[CashRegisterHAL] = None
        self.rom = None
        #: real-hex executor (recover.realrun); None when the ROM is absent
        self.runner = None
        #: static diagnosis of the firmware's event consumers (recover.realrun)
        self.consumer_report: Dict[str, Any] = {}

        #: set by boot()/run(); never touched outside the lock
        self._booted = False
        self._source = "demo" if self.demo_enabled else "recovered"
        self._running = False
        self._halted = True
        self._reason = "not booted yet"
        self._steps = 0
        self._entry = 0x0A06
        self._entry_covered = False
        self._isr_active = False
        self._demo_index = 0
        self._demo_log: List[str] = []
        self._functions_loaded = 0
        self._functions_failed = 0
        self._globals = 0
        self._boot_error = ""
        self.alias_report: Dict[str, object] = {}

        self._hardware = hardware
        self._display_facade: Any = None
        self._keyboard_facade: Any = None
        self._printer_facade: Any = None
        self._refresh_facades()

    # ------------------------------------------------------------- internals
    def _refresh_facades(self) -> None:
        board = getattr(self.hal, "board", None)
        if board is None:
            self._display_facade = _EmptyDisplay()
            self._keyboard_facade = _EmptyKeyboard()
            self._printer_facade = _EmptyPrinter()
            return
        self._display_facade = _LockedDisplay(self, board.display)
        self._keyboard_facade = _LockedKeyboard(self, board.keyboard)
        self._printer_facade = _LockedPrinter(self, board.printer)

    # ------------------------------------------------------------ public view
    @property
    def display(self):
        return self._display_facade

    @property
    def keyboard(self):
        return self._keyboard_facade

    @property
    def printer(self):
        return self._printer_facade

    # ------------------------------------------------------------------- boot
    def boot(self) -> None:
        """Load the dump, install the HAL, decide what can honestly run.

        Idempotent and never raises: a failure is recorded in ``status()``.
        """
        with self._lock:
            if self._booted:
                return
            try:
                self._boot_locked()
            except Exception as exc:                       # noqa: BLE001 - by contract
                self._boot_error = f"{type(exc).__name__}: {exc}"
                self._reason = f"boot failed: {self._boot_error}"
                self._running = False
                self._halted = True
                self._booted = True
            else:
                self._booted = True

    def _boot_locked(self) -> None:
        dump_file = _resolve(self.dump_path)
        with open(dump_file, encoding="utf-8", errors="replace") as fh:
            text = fh.read()

        self.rom = load_rom((self.rom_path, DEFAULT_ROM))
        machine = Machine()

        def code_reader(addr: int) -> int:
            addr &= 0xFFFF
            if self.rom is not None and self.rom.is_mapped(addr):
                return self.rom.byte(addr)
            raise MissingFirmware(addr, "code read outside the dumped half of ROM")

        machine.rom_reader = code_reader
        self.machine = machine

        helpers = RuntimeHelpers(machine)
        self.helpers = helpers
        library = FunctionLibrary(machine, helpers)
        # replace the library's interpreter with the cursor-corrected subclass
        # *before* load(), so every RecoveredFunction binds to it
        library.interpreter = RecoveredInterpreter(machine, helpers)
        library.interpreter.globals = library.globals
        self.library = library

        program = parse_dump(text, dump_file)
        library.register_globals(program.globals)
        # Bind the decompiler's dangling aliases (_7_4 -> RAM 0x27 bit 4, P1_3,
        # DAT_CODE_xxxx, ...) before loading: see recover.hal.bind_recovered_aliases
        self.alias_report = bind_recovered_aliases(machine, program.globals)
        library.load(program)
        stats = library.stats()
        self._functions_loaded = stats["loaded"]
        self._functions_failed = stats["failed"]
        self._globals = stats["globals"]

        self.hal = CashRegisterHAL(board=self._hardware, rom=self.rom, strict=self.strict)
        self.hal.install(machine)
        self._refresh_facades()

        # ---- the real-hex executor: original bytes on the m8051 core -------
        # The runner owns a rebased CPU-space copy (record - 0x8000) and boots
        # from the real reset vector; the session's ROM stays record-space for
        # the pseudo-code world (the single translation boundary lives in
        # recover.realrun).  Anything that goes wrong here must not fail the
        # boot - it is recorded and the session falls back.
        self.runner = None
        self.consumer_report = {}
        if self.rom is not None:
            try:
                from .realrun import (
                    PERIOD_TIMER0,
                    PERIOD_TIMER1,
                    RealRunner,
                    diagnose_consumers,
                )

                self.runner = RealRunner(hal=self.hal, rom=self.rom)
                self.consumer_report = diagnose_consumers(program, self.rom)
                # documented reload values of the two ISR bodies (record cites)
                self.consumer_report["periods"] = {
                    "timer1": PERIOD_TIMER1,
                    "timer0": PERIOD_TIMER0,
                }
            except Exception as exc:                       # noqa: BLE001 - by contract
                self.runner = None
                self.consumer_report = {"error": f"{type(exc).__name__}: {exc}"}

        # ---- what does the ROM's reset vector say, and is it covered? -----
        # Record space: the vector bytes sit at record RESET_VECTOR (0x8000).
        # CPU space: the entry is the word after it, and it is covered when
        # its record address (entry + REBASE) is inside the dumped image.
        entry = RESET_ENTRY
        if self.rom is not None and self.rom.byte(RESET_VECTOR) == 0x02:
            entry = self.rom.word(RESET_VECTOR + 1)
        self._entry = entry
        self._entry_covered = bool(
            self.rom is not None and self.rom.is_mapped((entry + REBASE) & 0xFFFF)
        )

        # demo exists as an explicit opt-in only; the default never invents.
        # Checked first so opting in always wins over the covered reset path.
        if self.demo_enabled:
            self._source = "demo"
            self._halted = False
            self._running = True
            self._demo_index = 0
            self._demo_log = []
            # one step right away, so the UI is never blank after boot()
            self._run_demo_step_locked()
            return

        verdict = str(self.consumer_report.get("display_buffer", {}).get("verdict", ""))

        if self._entry_covered and self.runner is not None:
            # DEFAULT: execute the original hex on the m8051 core, from the
            # REAL reset vector.  Nothing is scheduled from outside: the
            # firmware's own main loop boots and its own Timer-0 dispatches
            # the display mux (CPU 0x02D9).  Timer-1 is never started by the
            # idle firmware, which the stats report truthfully as 0.
            self._source = "recovered"
            self._isr_active = False              # real vectors, no pseudo ISR
            self._reason = (
                f"reset vector record 0x{RESET_VECTOR:04X} = LJMP 0x{entry:04X}; "
                f"CPU 0x{entry:04X} (record 0x{(entry + REBASE) & 0xFFFF:04X}) is "
                f"covered by the dump, so the ORIGINAL bytes boot from the real "
                f"reset vector on the m8051 core (recover.realrun): the "
                f"firmware's own timers dispatch its ISRs (display mux CPU "
                f"0x02D9); no pseudo-code interpreter involved; NOT dumped: the "
                f"upper half 0x8000..0xFFFF of CPU space - execution halts "
                f"honestly if it ever fetches there"
            )
            if verdict:
                self._reason += f"; consumer: {verdict}"
            self._halted = False
            self._running = True
            return

        if self._entry_covered:
            self._reason = (
                f"reset vector record 0x{RESET_VECTOR:04X} = LJMP 0x{entry:04X} is "
                f"covered by the dump, but the real-hex executor is unavailable: "
                f"{self.consumer_report.get('error', 'no ROM image')}"
            )
        else:
            self._reason = (
                f"reset vector record 0x{RESET_VECTOR:04X} = LJMP 0x{entry:04X}; "
                f"CPU 0x{entry:04X} (record 0x{(entry + REBASE) & 0xFFFF:04X}) is "
                f"not in this dump - only the lower half 0x0000..0x7FFF of CPU "
                f"space survived - so the recovered program cannot start"
            )

        # no ROM image (or executor failure): drive the pseudo-code refresh
        # ISR when present
        isr = library.functions.get(REFRESH_ISR)
        self._isr_active = isr is not None and not isr.is_stub
        if self._isr_active:
            self._reason += (
                f"; driving the recovered Timer-1 refresh ISR {REFRESH_ISR} "
                f"(ROM 0x8135) instead (no ROM image for the real-hex path)"
            )
            self._halted = False
            self._running = True
        else:
            self._reason += "; the recovered refresh ISR is not available either"
            self._halted = True
            self._running = False

    # -------------------------------------------------------------------- run
    def run(self, cycles: int) -> None:
        """Advance the recovered program / hardware by ``cycles`` machine cycles.

        Called from a background thread.  Bounded work per call; never raises.
        """
        with self._lock:
            if not self._booted:
                self.boot()
            if not self._booted or self.machine is None:
                return
            try:
                budget = max(0, int(cycles))
            except Exception:
                budget = 0
            if budget <= 0:
                return
            try:
                if self._source == "demo":
                    self._run_demo_locked(budget)
                else:
                    self._run_recovered_locked(budget)
            except Exception as exc:                       # noqa: BLE001 - by contract
                self._halted = True
                self._running = False
                self._reason = f"run failed: {type(exc).__name__}: {exc}"

    # ---------------------------------------------------------------- recovered
    def _run_recovered_locked(self, cycles: int) -> None:
        # DEFAULT: the original hex on the m8051 core (recover.realrun).
        # The pseudo-code interpreter below stays only as the fallback for a
        # session that has no ROM image to execute.
        runner = self.runner
        if runner is not None:
            runner.advance(cycles)
            self._steps = runner.timer1_calls + runner.timer0_calls
            if runner.halted:
                self._halted = True
                self._running = False
                self._reason = f"real hex stopped: {runner.halt_reason}"
            return

        machine, library, hal = self.machine, self.library, self.hal
        if hal is not None:
            hal.sync_inputs(machine)
            period = hal.reload_period(machine)
        else:
            period = 0x35C
        calls = max(1, min(int(cycles) // max(1, period), MAX_ISR_PER_RUN))

        if self._isr_active or self.demo_enabled is False:
            pass
        isr = library.functions.get(REFRESH_ISR) if library else None
        if isr is None or isr.is_stub:
            # nothing recovered can be driven
            self._running = False
            self._halted = True
            return
        self._isr_active = True

        for _ in range(calls):
            try:
                isr.invoke(library.interpreter, [])
                self._steps += 1
            except MissingFirmware as exc:
                self._halted = True
                self._running = False
                self._reason = (f"recovered code needs the missing half: {exc}")
                break
            except RuntimeError as exc:
                self._halted = True
                self._running = False
                self._reason = f"recovered code stopped: {exc}"
                break
            if hal is not None:
                hal.sync_inputs(machine)
        if hal is not None:
            hal.tick(cycles)
        machine.steps += calls

    # ------------------------------------------------------------------- demo
    def _demo_steps(self) -> List[Tuple[str, Callable[[], None]]]:
        hal = self.hal
        machine = self.machine
        assert hal is not None and machine is not None

        def show_digits() -> None:
            for index, char in enumerate(DEMO_DIGITS):
                hal.write_display_char(index, char)

        def blank_select() -> None:
            # ROM 0x8319-0x831E: ANL A,#07h / MOV DPH,#0A2h / MOVX @DPTR,A
            hal.xdata_write(0xA200, 0x00)

        def present_status() -> None:
            # 0x00D3 is waited for 0x5A (C L12632); the peer presents it here.
            hal.status_byte.present(0x5A)
            hal.mailbox_b.peer_ready(True)

        def control_latches() -> None:
            # ROM 0xB2A9: the two control words, exactly as the firmware writes
            hal.xdata_write(0x0009, 0x89)
            hal.xdata_write(0x000B, 0x89)

        def key_event() -> None:
            keyboard = hal.board.keyboard
            row = 0
            try:
                row = int(keyboard.row_of("5"))
            except Exception:
                row = 0
            keyboard.press("5")
            try:
                columns = hal.xdata_read(0x9130 + (row & 0x07))   # ROM 0x8398
            finally:
                keyboard.release("5")
            hal.print_char(ord("5"))
            self._demo_log.append(f"key row={row} columns=0x{columns:02X}")

        def print_receipt() -> None:
            for line in DEMO_RECEIPT:
                hal.print_text(line)
            hal.printer.feed(2)

        return [
            ("display", show_digits),
            ("blank", blank_select),
            ("status", present_status),
            ("latches", control_latches),
            ("key", key_event),
            ("receipt", print_receipt),
        ]

    def _run_demo_step_locked(self) -> bool:
        steps = self._demo_steps()
        if self._demo_index >= len(steps):
            return False
        name, action = steps[self._demo_index]
        action()
        self._demo_index += 1
        self._demo_log.append(name)
        self._steps += 1
        return True

    def _run_demo_locked(self, cycles: int) -> None:
        if self.hal is None:
            return
        steps = self._demo_steps()
        if self._demo_index >= len(steps):
            self._running = False
            self._halted = True
            if "demo sequence finished" not in self._reason:
                self._reason += "; demo sequence finished (source=demo)"
            self.hal.tick(cycles)
            return
        # one scripted step per run() call keeps run() prompt
        try:
            self._run_demo_step_locked()
        except MissingFirmware as exc:
            self._halted = True
            self._running = False
            self._reason = f"demo hit an unmodelled address: {exc}"
            return
        if self.hal is not None:
            self.hal.tick(cycles)
        if self._demo_index >= len(steps):
            self._halted = True
            self._running = False
            self._reason += "; demo sequence finished (source=demo)"

    # ----------------------------------------------------------------- status
    def status(self) -> Dict[str, Any]:
        """Truthful snapshot; safe to call from any thread."""
        with self._lock:
            machine = self.machine
            missing = 0
            if machine is not None:
                missing = sum(machine.missing_calls.values())
            return {
                "running": bool(self._running),
                "halted": bool(self._halted),
                "reason": str(self._reason),
                "steps": int(self._steps),
                "missing_calls": int(missing),
                "source": self._source,
                "entry": f"0x{self._entry:04X}",
                "entry_covered": bool(self._entry_covered),
                "isr": REFRESH_ISR if self._isr_active else "",
                "boot_error": self._boot_error,
                "functions_loaded": int(self._functions_loaded),
                "functions_failed": int(self._functions_failed),
                "globals": int(self._globals),
                "aliases": dict(self.alias_report),
                "demo_steps_done": int(self._demo_index),
                "display": self._display_facade.text(),
                "receipt_lines": len(self._printer_facade.paper()),
                # what is actually executing (real hex vs pseudo-code vs demo)
                "real_hex": self.runner is not None,
                "isr_calls": int(self.runner.timer1_calls) if self.runner else 0,
                "mux_calls": int(self.runner.timer0_calls) if self.runner else 0,
                "cpu_instructions": int(self.runner.instructions) if self.runner else 0,
                "consumer": str(
                    self.consumer_report.get("display_buffer", {}).get("verdict", "")
                ),
            }

    # ------------------------------------------------------------------ reset
    def reset(self) -> None:
        """Drop all state and boot again (idempotent, never raises)."""
        with self._lock:
            board = getattr(self.hal, "board", None)
            if board is not None:
                try:
                    board.reset()
                except Exception:
                    pass
            self._booted = False
            self._running = False
            self._halted = True
            self._reason = "reset"
            self._steps = 0
            self._demo_index = 0
            self._demo_log = []
            self._isr_active = False
            self.machine = None
            self.helpers = None
            self.library = None
            self.hal = None
            self.runner = None
            self.consumer_report = {}
            self._boot_error = ""
            self._refresh_facades()
            self.boot()

    # ------------------------------------------------------- diagnostic extra
    def invoke(self, name: str, *args) -> Dict[str, Any]:
        """Call one recovered function directly (diagnostics / tests).

        Returns a dict instead of raising, and records the missing-firmware
        calls the invocation made.  This is the pseudo-code world's direct
        entry into a single ``FUN_CODE_xxxx`` body - independent of the
        real-hex path, which boots from the reset vector instead.
        """
        with self._lock:
            if not self._booted:
                self.boot()
            if self.library is None or self.machine is None:
                return {"ok": False, "error": self._reason, "result": None}
            fn = self.library.functions.get(name)
            if fn is None:
                return {"ok": False, "error": f"{name} is not in the dump", "result": None}
            try:
                result = fn.invoke(self.library.interpreter, list(args))
                self._steps += 1
                return {
                    "ok": True,
                    "error": "",
                    "result": int(result) & 0xFFFF if isinstance(result, int) else result,
                    "missing_calls": sum(self.machine.missing_calls.values()),
                }
            except MissingFirmware as exc:
                return {"ok": False, "error": str(exc), "missing": True,
                        "result": None,
                        "missing_calls": sum(self.machine.missing_calls.values())}
            except Exception as exc:                       # noqa: BLE001
                return {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                        "result": None,
                        "missing_calls": sum(self.machine.missing_calls.values())}

    def invoke_display(self, value: int, digit: int) -> Dict[str, Any]:
        """Call the recovered display writer (ROM 0x810F) - the smallest proof.

        ``FUN_CODE_810f(0x3F, 0)`` writes the "0" segment byte into xdata
        0xA100 through the HAL's display window.
        """
        return self.invoke(DISPLAY_WRITER, value, digit)

    # ------------------------------------------------------------------ misc
    def describe(self) -> str:
        with self._lock:
            return (f"RecoveredFirmwareSession(source={self._source}, "
                    f"steps={self._steps}, halted={self._halted}, "
                    f"functions={self._functions_loaded}/{self._functions_failed} failed)")


# ---------------------------------------------------------------------------
# empty facades (before boot / if a board could not be created)
# ---------------------------------------------------------------------------
class _EmptyDisplay:
    columns = 8
    lines = 1

    def text(self) -> str:
        return " " * 8

    def cell_segments(self, index: int) -> int:
        return 0

    def render_rows(self, scale: int = 1) -> List[str]:
        return [" " * 40 for _ in range(7)]


class _EmptyKeyboard:
    keys: List[str] = []

    def press(self, name: str) -> None:
        return None

    def release(self, name: str) -> None:
        return None

    def tap(self, name: str) -> None:
        return None

    def is_pressed(self, name: str) -> bool:
        return False


class _EmptyPrinter:
    def paper(self) -> List[str]:
        return []

    def text(self) -> str:
        return ""

    def clear(self) -> None:
        return None

    def feed(self, lines: int = 1) -> None:
        return None

    def is_busy(self) -> bool:
        return False
