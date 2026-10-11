"""The hardware bus contract between the CPU core and the emulated board.

Everything the processor can touch outside of its own registers and code
memory goes through this interface.  Keeping it narrow means the CPU core can
be tested standalone (see :class:`NullBus`) and the cash-register board can be
rewritten without touching the core.

Port semantics
--------------
* ``port_read(port)``   - the *pin* levels the outside world drives.
* ``port_write(port, value)`` - the value latched by the CPU (P0..P3 latches).
* ``port_change(port, old, new)`` - called after the latch changed, so a board
  can react to edges (strobes, clock lines, chip selects).
* ``ext_read``/``ext_write`` - ``MOVX`` external data memory (XDATA), also used
  for memory-mapped peripherals such as an 8255 PPI.
* ``irq_requested()`` - boards raise INT0/INT1/T0/T1/RX/TX by returning a
  bitmask of :data:`IRQ_*` flags; the CPU polls this once per instruction.
"""

from __future__ import annotations

from typing import Optional

__all__ = [
    "HardwareBus",
    "NullBus",
    "IRQ_INT0",
    "IRQ_T0",
    "IRQ_INT1",
    "IRQ_T1",
    "IRQ_RX",
    "IRQ_TX",
]

# Bit positions matching the 8051 interrupt priority table.
IRQ_INT0 = 0x01
IRQ_T0 = 0x02
IRQ_INT1 = 0x04
IRQ_T1 = 0x08
IRQ_RX = 0x10
IRQ_TX = 0x20


class HardwareBus:
    """Base class; the default implementations are inert."""

    # ------------------------------------------------------------------ time
    def tick(self, cycles: int) -> None:
        """Advance peripherals by ``cycles`` machine cycles (1 MHz @ 12 MHz xtal)."""

    # ------------------------------------------------------- external memory
    def ext_read(self, addr: int, code: bool = False) -> int:
        return 0xFF

    def ext_write(self, addr: int, value: int) -> None:
        pass

    def ext_probe(self, addr: int) -> bool:
        """True when ``addr`` is handled by a peripheral (used for tracing)."""
        return False

    # ---------------------------------------------------------------- ports
    def port_read(self, port: int) -> int:
        return 0xFF

    def port_write(self, port: int, value: int) -> None:
        pass

    def port_change(self, port: int, old: int, new: int) -> None:
        pass

    # -------------------------------------------------------------- serial
    def serial_write(self, byte: int) -> None:
        pass

    def serial_read(self) -> Optional[int]:
        return None

    def serial_tx_ready(self) -> bool:
        return True

    def serial_available(self) -> bool:
        """True when the board has a byte for the CPU's UART to receive."""
        return False

    # ----------------------------------------------------------- interrupts
    def irq_requested(self) -> int:
        return 0

    # ---------------------------------------------------------- diagnostics
    def describe(self) -> str:
        return self.__class__.__name__


class NullBus(HardwareBus):
    """A bus where every pin floats high - handy for unit tests."""

    def __init__(self) -> None:
        self.ext = bytearray(0x10000)
        self.writes = []

    def ext_read(self, addr: int, code: bool = False) -> int:
        return self.ext[addr & 0xFFFF]

    def ext_write(self, addr: int, value: int) -> None:
        self.ext[addr & 0xFFFF] = value & 0xFF
        self.writes.append((addr & 0xFFFF, value & 0xFF))

    def port_read(self, port: int) -> int:
        return 0xFF
