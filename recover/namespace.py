"""The 8051 machine model that recovered pseudo-C executes against.

The decompiled dump names every location twice over: as a *global variable*
(``DAT_INTMEM_3e``, ``DAT_EXTMEM_0c7a``, ``P1``, ``TCON``) and implicitly by its
address.  Recovered code therefore does not read memory - it reads and writes
globals.  This module provides those globals as live proxies onto a machine
state, so the recovered logic observes and drives a coherent 8051.

Three address spaces exist on an 8051, and the dump distinguishes them by
prefix:

``DAT_INTMEM_xx``   internal RAM, 256 bytes (direct + indirect)
``DAT_EXTMEM_xxxx`` external data memory (``MOVX``) - this is where the cash
                    register's peripherals live
``DAT_SFR_xx``      SFR whose name the decompiler did not recognise

Bit-addressable locations are modelled by :class:`BitAddress`, so the
decompiler's ``undefined 22.1;`` declarations become real bit cells at
``0x22`` bit 1.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, Iterable, Optional

from .errors import MissingFirmware

__all__ = ["SFR", "BitAddress", "Machine", "SFR_NAMES", "RAMCell", "XdataCell", "CodeCell"]

#: ``bINTMEM80`` / ``cINTMEMea`` / ``cCODEb46c`` - the decompiler's name for a
#: single byte: a 1-3 letter type prefix, the address space, then the hex
#: address.  The dump uses these four without ever declaring them, so they used
#: to die with a generic ``KeyError`` instead of resolving to their space.
_TYPED_ALIAS_RE = re.compile(r"[a-z]{1,3}(INTMEM|EXTMEM|XDATA|CODE|SFR)([0-9a-fA-F]{1,4})")

# --------------------------------------------------------------------- SFR map
# Names as they appear in the decompiled dump, with their addresses.
SFR_NAMES: Dict[str, int] = {
    "P0": 0x80, "SP": 0x81, "DPL": 0x82, "DPH": 0x83, "PCON": 0x87,
    "TCON": 0x88, "TMOD": 0x89, "TL0": 0x8A, "TL1": 0x8B, "TH0": 0x8C, "TH1": 0x8D,
    "P1": 0x90,
    "SCON": 0x98, "SBUF": 0x99,
    "P2": 0xA0,
    "IE": 0xA8, "WDTRST": 0xA6,
    "P3": 0xB0,
    "IP": 0xB8,
    "T2CON": 0xC8, "RCAP2L": 0xCA, "RCAP2H": 0xCB, "TL2": 0xCC, "TH2": 0xCD,
    # 8xC51Rx2-style extensions that the dump actually names
    "DPX": 0x93, "AUXR": 0x8E, "AUXR1": 0xA2, "CKCON": 0x8F,
    "SADDR": 0xA9, "SADEN": 0xB9, "PCON1": 0x87, "PSW1": 0xD0,
    "IPL1": 0xF8, "IPH1": 0xF7, "IEN1": 0xB1, "FIE": 0xE8, "FIE1": 0xE8,
    "UD": 0xC5, "WCON": 0x97,
    "PSW": 0xD0, "CCON": 0xD8, "CMOD": 0xD9,
    "CCAPM0": 0xDA, "CCAPM1": 0xDB, "CCAPM2": 0xDC, "CCAPM3": 0xDD, "CCAPM4": 0xDE,
    "ACC": 0xE0, "CL": 0xE9,
    "CCAP0L": 0xEA, "CCAP1L": 0xEB, "CCAP2L": 0xEC, "CCAP3L": 0xED, "CCAP4L": 0xEE,
    "B": 0xF0, "CH": 0xF9,
    "CCAP0H": 0xFA, "CCAP1H": 0xFB, "CCAP2H": 0xFC, "CCAP3H": 0xFD, "CCAP4H": 0xFE,
}

# Bit names the decompiler resolved, mapped to (byte_address, bit_index).
SFR_BITS: Dict[str, tuple] = {
    # PSW
    "CY": (0xD0, 7), "AC": (0xD0, 6), "F0": (0xD0, 5), "RS1": (0xD0, 4),
    "RS0": (0xD0, 3), "OV": (0xD0, 2), "P": (0xD0, 0),
    # TCON
    "TF1": (0x88, 7), "TR1": (0x88, 6), "TF0": (0x88, 5), "TR0": (0x88, 4),
    "IE1": (0x88, 3), "IT1": (0x88, 2), "IE0": (0x88, 1), "IT0": (0x88, 0),
    # IE
    "EA": (0xA8, 7), "ES": (0xA8, 4), "ET1": (0xA8, 3), "EX1": (0xA8, 2),
    "ET0": (0xA8, 1), "EX0": (0xA8, 0),
    # SCON
    "SM0": (0x98, 7), "SM1": (0x98, 6), "SM2": (0x98, 5), "REN": (0x98, 4),
    "TB8": (0x98, 3), "RB8": (0x98, 2), "TI": (0x98, 1), "RI": (0x98, 0),
    # IP
    "PS": (0xB8, 4), "PT1": (0xB8, 3), "PX1": (0xB8, 2), "PT0": (0xB8, 1), "PX0": (0xB8, 0),
    # P3 alternate functions — the dump uses these names for the pin bits
    "RXD": (0xB0, 0), "TXD": (0xB0, 1), "INT0": (0xB0, 2), "INT1": (0xB0, 3),
    "T0": (0xB0, 4), "T1": (0xB0, 5), "WR": (0xB0, 6), "RD": (0xB0, 7),
    # P1 bits the dump names explicitly (``P1_3`` etc. live here as P1.3)
    "P1_0": (0x90, 0), "P1_1": (0x90, 1), "P1_2": (0x90, 2), "P1_3": (0x90, 3),
    "P1_4": (0x90, 4), "P1_5": (0x90, 5), "P1_6": (0x90, 6), "P1_7": (0x90, 7),
}

_RAM_SIZE = 256
_XDATA_SIZE = 0x10000


class SFR:
    """A live SFR cell that keeps a bit view consistent with its byte view."""

    __slots__ = ("machine", "addr")

    def __init__(self, machine: "Machine", addr: int) -> None:
        self.machine = machine
        self.addr = addr

    def _get(self) -> int:
        return self.machine._sfr[self.addr]

    def _set(self, value: int) -> None:
        value &= 0xFF
        old = self.machine._sfr[self.addr]
        self.machine._sfr[self.addr] = value
        self.machine.on_sfr_write(self.addr, value, old)

    value = property(_get, _set)

    def __int__(self) -> int:
        return self._get()

    def __index__(self) -> int:
        return self._get()

    def __eq__(self, other) -> bool:                      # type: ignore[override]
        return self._get() == (int(other) & 0xFF if isinstance(other, (int, SFR, BitAddress)) else other)

    def __hash__(self) -> int:
        return hash((self.addr, self._get()))

    def __repr__(self) -> str:
        return f"SFR(0x{self.addr:02X})={self._get():#04x}"


class BitAddress:
    """A single bit, either in internal RAM (0x00-0x7F bit space) or an SFR.

    The decompiler's mangled globals such as ``undefined 22.1;`` mean "bit 1 of
    internal RAM byte 0x22"; ``P1.3`` means "bit 3 of the P1 SFR".
    """

    __slots__ = ("machine", "byte", "bit")

    def __init__(self, machine: "Machine", byte: int, bit: int) -> None:
        self.machine = machine
        self.byte = byte & 0xFF
        self.bit = bit & 7

    @property
    def mask(self) -> int:
        return 1 << self.bit

    def _container(self) -> bytearray:
        # Bits 0x20..0x2F of the bit space are internal RAM; anything >= 0x80 is
        # an SFR (the decompiler only ever produces these two cases).
        if self.byte < 0x80:
            return self.machine._ram
        return self.machine._sfr

    def _get(self) -> int:
        return 1 if self._container()[self.byte] & self.mask else 0

    def _set(self, value) -> None:
        container = self._container()
        old = container[self.byte]
        if value:
            container[self.byte] = old | self.mask
        else:
            container[self.byte] = old & ~self.mask & 0xFF
        if self.byte >= 0x80:
            self.machine.on_sfr_write(self.byte, container[self.byte], old)

    value = property(_get, _set)

    def __int__(self) -> int:
        return self._get()

    def __index__(self) -> int:
        return self._get()

    def __bool__(self) -> bool:
        return bool(self._get())

    def __eq__(self, other) -> bool:                      # type: ignore[override]
        return self._get() == (int(other) & 1 if isinstance(other, (int, BitAddress, SFR)) else other)

    def __hash__(self) -> int:
        return hash((self.byte, self.bit, self._get()))

    def __repr__(self) -> str:
        return f"Bit(0x{self.byte:02X}.{self.bit})={self._get()}"


class Machine:
    """Mutable 8051 state plus the hooks recovered code needs.

    ``on_sfr_write`` and ``xdata_*`` are the seams where the cash register's
    hardware attaches; see :mod:`recover.hal`.
    """

    def __init__(self) -> None:
        self._ram = bytearray(_RAM_SIZE)
        self._sfr = bytearray(0x100)
        self._xdata = bytearray(_XDATA_SIZE)
        #: set of external addresses that something actually handles
        self.xdata_devices: Dict[int, object] = {}
        #: called for every SFR write that is not a plain RAM-like store
        self.sfr_listeners: Dict[int, list] = {}
        #: called on every xdata access, in order, until one returns a value
        self.xdata_hooks: list = []
        #: how many instructions the recovered program has executed
        self.steps = 0
        #: cap, so a runaway recovered program cannot hang the UI
        self.step_limit = 5_000_000
        #: names of routines that were called but are not in any dump
        self.missing_calls: Dict[str, int] = {}
        #: cache of global-name -> live memory proxy built by the interpreter
        self.proxy_cache: Dict[str, object] = {}
        #: set by the recovered code's ROM access helper
        self.rom_reader: Optional[Callable[[int], int]] = None

    # ------------------------------------------------------------------ memory
    def ram(self, addr: int) -> int:
        return self._ram[addr & 0xFF]

    def set_ram(self, addr: int, value: int) -> None:
        self._ram[addr & 0xFF] = value & 0xFF

    def sfr(self, addr: int) -> int:
        return self._sfr[addr & 0xFF]

    def set_sfr(self, addr: int, value: int) -> None:
        addr &= 0xFF
        old = self._sfr[addr]
        self._sfr[addr] = value & 0xFF
        self.on_sfr_write(addr, value & 0xFF, old)

    # ------------------------------------------------------------ xdata (MOVX)
    def xdata_read(self, addr: int) -> int:
        addr &= 0xFFFF
        for hook in self.xdata_hooks:
            result = hook(addr, False, 0)
            if result is not None:
                return result & 0xFF
        return self._xdata[addr]

    def xdata_write(self, addr: int, value: int) -> None:
        addr &= 0xFFFF
        value &= 0xFF
        for hook in self.xdata_hooks:
            if hook(addr, True, value) is not None:
                return
        self._xdata[addr] = value

    def install_xdata_device(self, address: int, device) -> None:
        """Register ``device`` (with read/write methods) at an xdata address."""
        self.xdata_devices[address & 0xFFFF] = device

    # ---------------------------------------------------------------- SFR glue
    def install_sfr_listener(self, addr: int, callback) -> None:
        self.sfr_listeners.setdefault(addr & 0xFF, []).append(callback)

    def on_sfr_write(self, addr: int, value: int, old: int) -> None:
        listeners = self.sfr_listeners.get(addr)
        if listeners:
            for callback in listeners:
                callback(value, old)

    # --------------------------------------------------------------- ROM reads
    def read_code(self, addr: int) -> int:
        """``MOVC`` - read the program ROM at ``addr``."""
        if self.rom_reader is None:
            raise MissingFirmware(addr, "code read with no ROM attached")
        return self.rom_reader(addr & 0xFFFF)

    # ------------------------------------------------------------------ named
    def resolve(self, name: str):
        """Return a live proxy for a global named in the dump."""
        if name in SFR_NAMES:
            return SFR(self, SFR_NAMES[name])
        if name in SFR_BITS:
            byte, bit = SFR_BITS[name]
            return BitAddress(self, byte, bit)
        if name.startswith("DAT_SFR_"):
            return SFR(self, int(name[len("DAT_SFR_"):], 16))
        if name.startswith("DAT_INTMEM_"):
            addr = int(name[len("DAT_INTMEM_"):], 16)
            return RAMCell(self, addr)
        if name.startswith("DAT_EXTMEM_"):
            addr = int(name[len("DAT_EXTMEM_"):], 16)
            return XdataCell(self, addr)
        for prefix in ("DAT_CODE_", "SUB_CODE_", "UNK_CODE_", "LAB_CODE_"):
            if name.startswith(prefix):
                # a named location in program memory: reading it is a MOVC
                return CodeCell(self, int(name[len(prefix):], 16))
        # The decompiler names some single bytes "<type><space><address>"
        # without declaring them anywhere: bINTMEM80, bINTMEMe5, cINTMEMea
        # (internal RAM) and cCODEb46c (program memory).  The name itself states
        # the space, so this is a translation, not a guess.
        m = _TYPED_ALIAS_RE.fullmatch(name)
        if m:
            space, addr_hex = m.group(1), m.group(2)
            addr = int(addr_hex, 16)
            if space in ("INTMEM",):
                return RAMCell(self, addr)
            if space in ("EXTMEM", "XDATA"):
                return XdataCell(self, addr)
            if space == "SFR":
                return SFR(self, addr)
            if space == "CODE":
                return CodeCell(self, addr)
        if name.startswith("BANK") and "_R" in name:
            bank = int(name[4])
            reg = int(name.split("_R")[1])
            return RAMCell(self, bank * 8 + reg)
        if "." in name:
            head, _, bit = name.partition(".")
            # ``P0.0`` - a bit of a *named* SFR comes first: "P0" is not hex
            if head in SFR_NAMES:
                return BitAddress(self, SFR_NAMES[head], int(bit))
            try:
                return BitAddress(self, int(head, 16), int(bit))
            except ValueError:
                pass
        raise KeyError(name)

    # ------------------------------------------------------------- diagnostics
    def snapshot(self) -> Dict[str, int]:
        return {
            "steps": self.steps,
            "pc": self._sfr[0x00] if False else 0,
            "acc": self._sfr[0xE0],
            "psw": self._sfr[0xD0],
            "sp": self._sfr[0x81],
            "p0": self._sfr[0x80],
            "p1": self._sfr[0x90],
            "p2": self._sfr[0xA0],
            "p3": self._sfr[0xB0],
            "dptr": (self._sfr[0x83] << 8) | self._sfr[0x82],
            "missing_calls": len(self.missing_calls),
        }

    def __repr__(self) -> str:
        return f"<Machine steps={self.steps} missing={len(self.missing_calls)}>"


class RAMCell:
    """A proxy for one byte of internal RAM named by the dump."""

    __slots__ = ("machine", "addr")

    def __init__(self, machine: Machine, addr: int) -> None:
        self.machine = machine
        self.addr = addr & 0xFF

    @property
    def value(self) -> int:
        return self.machine._ram[self.addr]

    @value.setter
    def value(self, v: int) -> None:
        self.machine._ram[self.addr] = v & 0xFF

    def __int__(self) -> int:
        return self.value

    def __index__(self) -> int:
        return self.value

    def __eq__(self, other) -> bool:                      # type: ignore[override]
        return self.value == (int(other) if isinstance(other, (int, RAMCell, XdataCell)) else other)

    def __hash__(self) -> int:
        return hash((self.addr, self.value))

    def __repr__(self) -> str:
        return f"RAM[{self.addr:#04x}]={self.value:#04x}"


class XdataCell:
    """A proxy for one byte of external memory named by the dump."""

    __slots__ = ("machine", "addr")

    def __init__(self, machine: Machine, addr: int) -> None:
        self.machine = machine
        self.addr = addr & 0xFFFF

    @property
    def value(self) -> int:
        return self.machine.xdata_read(self.addr)

    @value.setter
    def value(self, v: int) -> None:
        self.machine.xdata_write(self.addr, v)

    def __int__(self) -> int:
        return self.value

    def __index__(self) -> int:
        return self.value

    def __eq__(self, other) -> bool:                      # type: ignore[override]
        return self.value == (int(other) if isinstance(other, (int, RAMCell, XdataCell)) else other)

    def __hash__(self) -> int:
        return hash((self.addr, self.value))

    def __repr__(self) -> str:
        return f"XDATA[{self.addr:#06x}]={self.value:#04x}"


class CodeCell:
    """A proxy for one byte of *program* memory named by the dump.

    ``DAT_CODE_8299``, ``SUB_CODE_003c`` and the decompiler's label pseudo-
    variables are locations in ROM: reading one is a ``MOVC`` and goes through
    :meth:`Machine.read_code`, so an address no dump covers reports
    :class:`~recover.errors.MissingFirmware` instead of returning a guess.
    Writing code memory is never legal - that reports the gap too.
    """

    __slots__ = ("machine", "addr")

    def __init__(self, machine: Machine, addr: int) -> None:
        self.machine = machine
        self.addr = addr & 0xFFFF

    @property
    def value(self) -> int:
        return self.machine.read_code(self.addr) & 0xFF

    @value.setter
    def value(self, v: int) -> None:
        raise MissingFirmware(self.addr, "write to code memory (ROM is read-only)")

    def __int__(self) -> int:
        return self.value

    def __index__(self) -> int:
        return self.value

    def __eq__(self, other) -> bool:                      # type: ignore[override]
        return self.value == (int(other) if isinstance(other, (int, CodeCell)) else other)

    def __hash__(self) -> int:
        return hash((self.addr, self.value))

    def __repr__(self) -> str:
        return f"CODE[{self.addr:#06x}]={self.value:#04x}"
