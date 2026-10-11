"""m8051 - a cycle-aware Intel MCS-51 (8051) / AT89C55 emulator written in Python.

Public API
----------
ROM        - code memory images (internal flash / external EPROM)
HardwareBus- abstract peripheral bus the CPU talks to
CPU8051    - the processor core
"""

from .rom import ROM, load_intel_hex  # noqa: F401
from .bus import HardwareBus, NullBus  # noqa: F401
from .cpu import CPU8051  # noqa: F401

__all__ = ["ROM", "load_intel_hex", "HardwareBus", "NullBus", "CPU8051"]
__version__ = "1.0.0"
