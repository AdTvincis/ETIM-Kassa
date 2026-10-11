"""Recovery of the Ghidra pseudo-C dump into runnable Python.

The file ``docs/nm27c512n_decompiled.c`` is decompiler *pseudocode*: it is not
C that any compiler will accept, and it is not a complete program either.  This
package turns the parts that are genuinely backed by bytes in the dump
(records ``0x8000..0xFFFF``; on the chip those bytes are CPU
``0x0000..0x7FFF`` - see :mod:`m8051.firmware_profile`) into executable
Python, and makes every place where the decompiler had no bytes and invented
code explicit at runtime instead of silently producing nonsense.

Modules
-------
``parse``
    Splits the dump into global declarations and function definitions.
``namespace``
    The 8051 machine model the generated code runs against: SFRs, bit
    addresses, internal RAM, external memory, and the hardware calls.
``transpile``
    Ghidra-C -> Python source translation.
``recovered``
    Generated module (created by ``tools/recover_firmware.py``).
``hal``
    Bridges the recovered code to the emulated cash-register hardware.

Honesty rules this package follows
----------------------------------
1. Nothing is invented to make a number "look right".
2. Every register/memory address the recovered code touches is either backed by
   real data or reports ``MissingFirmware``.
3. Callers can ask ``provenance(addr)`` whether a location came from the real
   ROM, from the other dump, from a generated stub, or is simply absent.
"""

from .parse import Function, Program, parse_dump  # noqa: F401
from .namespace import (  # noqa: F401
    BitAddress,
    Machine,
    RAMCell,
    SFR,
    XdataCell,
)
from .errors import BadDecompilation, MissingFirmware, XdataUnmapped  # noqa: F401

__all__ = [
    "parse_dump",
    "Program",
    "Function",
    "Machine",
    "SFR",
    "BitAddress",
    "RAMCell",
    "XdataCell",
    "MissingFirmware",
    "XdataUnmapped",
    "BadDecompilation",
]
