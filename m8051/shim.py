"""Low-ROM shims for the cash-register firmware image.

``nm27c512n.hex`` covers ``0x8000..0xFFFF`` and its reset vector does
``LJMP 0x0A06`` - the lower half of the program (``0x0000..0x7FFF``) lived in
a second device (the AT89C55's internal ROM) and was never dumped.

A shim here is *transparent*: it never pretends to be firmware.  It only
supplies the reset/vector trampolines that the missing low ROM would contain,
so the real code that *is* present gets to execute on the emulated board.
Everything still runs as genuine MCS-51 machine code through the core.
"""

from __future__ import annotations

from typing import Dict, Optional

__all__ = ["VECTORS", "IRQ_NAMES", "SHIM_BASE", "build_shim", "shim_summary"]

# Interrupt vector addresses (0x0003, 0x000B, ...) each hold a 3-byte LJMP.
VECTORS = (0x03, 0x0B, 0x13, 0x1B, 0x23, 0x2B, 0x33, 0x3B, 0x43, 0x4B)
IRQ_NAMES = (
    "EXT0", "TIMER0", "EXT1", "TIMER1", "SERIAL", "TIMER2",
    "PCA", "LVD", "SPI", "UART1",
)

# The shim's own code lives here, well clear of the vector table.
SHIM_BASE = 0x0080


def _ljmp(target: int) -> bytes:
    return bytes((0x02, (target >> 8) & 0xFF, target & 0xFF))


def build_shim(
    reset_target: int = 0x8000,
    irq_target: Optional[int] = None,
) -> Dict[int, int]:
    """Build the shim as an ``{address: byte}`` mapping.

    ``reset_target`` is where the 8051 reset vector (``0x0000``) jumps.  Every
    interrupt vector jumps either to ``irq_target`` or to a shared ``RETI``
    stub, because interrupts are only raised when the emulated board asks for
    them and an unhandled one must not be fatal.
    """
    mem: Dict[int, int] = {}

    for i, b in enumerate(_ljmp(reset_target)):
        mem[0x0000 + i] = b

    reti_stub = SHIM_BASE + 0x20
    for vector in VECTORS:
        target = irq_target if irq_target is not None else reti_stub
        for i, b in enumerate(_ljmp(target)):
            mem[vector + i] = b
    mem[reti_stub] = 0x32                     # RETI
    return mem


def shim_summary(mem: Dict[int, int]) -> str:
    """Human-readable one-liner describing what a shim installs."""
    reset = 0
    if mem.get(0x00) == 0x02:
        reset = (mem.get(0x01, 0) << 8) | mem.get(0x02, 0)
    vectors = []
    for vector in VECTORS[:6]:
        if mem.get(vector) == 0x02:
            target = (mem.get(vector + 1, 0) << 8) | mem.get(vector + 2, 0)
            vectors.append(f"0x{vector:02X}->0x{target:04X}")
    return f"reset(0x0000) -> 0x{reset:04X}; vectors: " + ", ".join(vectors)
