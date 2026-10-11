"""HAL: bridge the recovered pseudo-C to the emulated cash register.

What this module is for
-----------------------
`recover.namespace.Machine` gives the recovered code a flat 64 KiB external
data space.  The real machine is *not* flat: the firmware talks to the display,
keyboard, printer, motor and handshake latches through ``MOVX`` pages.  This
module connects the two:

* ``Machine.xdata_hooks``      - device windows are served by the board model,
* ``Machine.install_sfr_listener`` - ``P1``/``P2``/``P3``/``TCON``/``SBUF`` writes
  reach the board's pin-level interface,
* ``sync_inputs()``            - board state (keys, busy) is driven back onto the
  SFR bits the recovered code samples.

Evidence policy (binding)
-------------------------
Everything below is derived from ``docs/nm27c512n_decompiled.c`` **and the bytes
of ``firmware/nm27c512n.hex``**.  No external source is used and no device is
asserted by analogy:

* every window/cell carries an :class:`Evidence` record with the quoted witness
  and a ``CONFIRMED`` / ``HYPOTHESIS`` tag;
* a window that the dump never reads is *write-only*: reading it raises
  :class:`~recover.errors.MissingFirmware` instead of inventing a value
  (``strict=True``, the default);
* addresses outside every proven window stay plain external RAM: they are real
  data, so the machine's flat image serves them.

The 8255 question
-----------------
``0x89`` / ``0xA9`` written to two low addresses *look* like 8255 mode words and
that is how ``docs/architecture.md`` explains them.  The dump itself only proves
two write-only bytes; the port registers an 8255 would need are touched only by
code in the missing half of the ROM.  So the HAL models exactly that (two write
latches) and offers :func:`decode_8255_control` as an explicitly *labelled
hypothesis* used for diagnostics - never as the device identity.

Reuse of ``board/``
-------------------
``board.cashboard.CashRegisterBoard`` (teammate ``hal-ppi``) already implements
display, keyboard, printer and the PPI behind the ``HardwareBus`` contract.  The
HAL **wraps** it when it is importable; the small fallback classes at the bottom
of this file exist only so the recovery runtime still has a coherent device when
``board/`` is absent.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .errors import MissingFirmware
from .namespace import Machine

__all__ = [
    "Evidence",
    "EVIDENCE",
    "DEVICE_PAGES",
    "PAGE_DIRECTIONS",
    "SEG7_TABLE",
    "SegmentFont",
    "decode_8255_control",
    "parse_8255_control",
    "WriteLatch",
    "StatusRegister",
    "WordRegister",
    "HandshakeMailbox",
    "CodeCell",
    "PIN_ALIASES",
    "bind_recovered_aliases",
    "bit_aliases_from_globals",
    "CashRegisterHAL",
    "MissingFirmware",
]

CONFIRMED = "CONFIRMED"
HYPOTHESIS = "HYPOTHESIS"


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Evidence:
    """One address (or one address page) with the witness that proves it."""

    address: int
    name: str
    direction: str            # "r" | "w" | "rw"
    witness: str              # C file / ROM bytes
    quote: str
    confidence: str = CONFIRMED
    page: bool = False        # True: ``address`` is a whole 0xNN00 page window
    values: Tuple[int, ...] = ()
    note: str = ""

    @property
    def readable(self) -> bool:
        return "r" in self.direction

    @property
    def writable(self) -> bool:
        return "w" in self.direction

    def as_row(self) -> Tuple[str, str, str, str, str]:
        """``(addr, dir, values, confidence, witness)`` - for the docs table."""
        addr = f"0x{self.address:04X}" + ("xx" if self.page else "")
        values = ", ".join(f"0x{v:02X}" for v in self.values) or "-"
        return addr, self.direction, values, self.confidence, self.witness


#: Every address/page the decompiled dump proves is hardware, with its witness.
#: The ``C Lnnn`` references are line numbers of ``docs/nm27c512n_decompiled.c``;
#: ``ROM 0xNNNN`` references are bytes of ``firmware/nm27c512n.hex``.
EVIDENCE: Dict[int, Evidence] = {
    # ------------------------------------------------------------------ page 0
    0x000000: Evidence(
        0x000000, "xdata page 0 (buffers + status)", "rw",
        "ROM 0x819F..0x81C0",
        "819F MOV DPH,#00h / 81A2 MOV DPL,R4 / 81A4 MOVX A,@DPTR / 81C0 CJNE A,#20h",
        CONFIRMED, page=True,
        note="page pointer DPH=0 is read as data (CJNE A,#20h at 0x81C0, "
             "CJNE A,#10h at 0x81AD); the named cells below live in this page",
    ),
    # ------------------------------------------------------------ named cells
    0x000009: Evidence(
        0x000009, "control latch 1", "w",
        "C L1109-1111",
        "DAT_EXTMEM_0009 = 0x89;  if (_7_4 != '\\0') { DAT_EXTMEM_0009 = 0xa9; }",
        HYPOTHESIS,
        values=(0x89, 0xA9),
        note="two constants that differ only in bit 5; identical code writes "
             "0x000B.  8255 mode-word reading is a HYPOTHESIS (see "
             "decode_8255_control); no port register is ever touched by dumped code",
    ),
    0x00000B: Evidence(
        0x00000B, "control latch 2", "w",
        "C L850-852 / ROM 0xB2A9..0xB2B2",
        "74 89 30 3C 02 74 A9 F3  =  MOV A,#89h / JNB 3Ch,+2 / MOV A,#0A9h / "
        "MOVX @R1,A   (R1 = 0Bh set at 0xB2A9)",
        CONFIRMED,
        values=(0x89, 0xA9),
        note="MOVX @R1: the effective address is P2<<8|0x0B; the dump names it "
             "by its low byte only, exactly like the other DAT_EXTMEM_00xx cells",
    ),
    0x000015: Evidence(
        0x000015, "16-bit register, high byte", "w",
        "C L906-907",
        "DAT_EXTMEM_0015 = (undefined1)((ushort)(sVar3 + 1) >> 8); "
        "DAT_EXTMEM_0016 = (undefined1)(sVar3 + 1);",
        CONFIRMED,
        values=(0x0B,),
        note="written as a hi/lo pair directly after P2 = 1 (C L905); sVar3 is "
             "0x0BC5 / 0x0B95 - a code address in the missing half",
    ),
    0x000016: Evidence(
        0x000016, "16-bit register, low byte", "w",
        "C L906-907",
        "DAT_EXTMEM_0016 = (undefined1)(sVar3 + 1);",
        CONFIRMED,
        values=(0xC6, 0x96),
    ),
    0x000093: Evidence(
        0x000093, "arm/reset pair, low", "w",
        "C L932-935",
        "DAT_EXTMEM_00d3 = 0;  DAT_EXTMEM_0093 = 0;  DAT_EXTMEM_0094 = 1;",
        CONFIRMED, values=(0x00,),
    ),
    0x000094: Evidence(
        0x000094, "arm/reset pair, high", "w",
        "C L932-935",
        "DAT_EXTMEM_0093 = 0;  DAT_EXTMEM_0094 = 1;",
        CONFIRMED, values=(0x01,),
        note="always the complementary pair 0/1, written together",
    ),
    0x0000BC: Evidence(
        0x0000BC, "exchange buffer", "w",
        "C L12702 / L13135",
        "DAT_EXTMEM_00bc = BANK3_R7;",
        CONFIRMED, values=(),
    ),
    0x0000D3: Evidence(
        0x0000D3, "status byte (waited for 0x5A)", "rw",
        "C L12632-12633 / L13065-13066",
        "cVar5 = (DAT_EXTMEM_00d3 < 0x5a) << 7;  if (DAT_EXTMEM_00d3 != 0x5a) {",
        CONFIRMED, values=(0x00,),
        note="read twice per site, written 0 three times: the code waits for 0x5A",
    ),
    0x0000FE: Evidence(
        0x0000FE, "handshake mailbox A (low)", "rw",
        "C L2303-2307 / ROM 0xD4xx",
        "puVar13 = &DAT_EXTMEM_00fe;  *puVar13 = 0xa5;  puVar13[1] = 0x5a;",
        CONFIRMED, values=(0xA5, 0x5A),
        note="same 0xA5/0x5A pattern as 0x0C7A; written twice per site",
    ),
    0x0000FF: Evidence(
        0x0000FF, "handshake mailbox A (high)", "rw",
        "C L2307",
        "puVar13[1] = 0x5a;",
        CONFIRMED, values=(0x5A,),
    ),
    0x000107: Evidence(
        0x000107, "handshake control", "w",
        "C L1461",
        "DAT_EXTMEM_0107 = 0xff;",
        CONFIRMED, values=(0xFF,),
    ),
    0x000C7A: Evidence(
        0x000C7A, "handshake mailbox B (status)", "rw",
        "C L1956-1958 / L2356 / L12632",
        "cVar5 = (DAT_EXTMEM_0c7a < 0xa5) << 7;  if (DAT_EXTMEM_0c7a != 0xa5) "
        "break;  DAT_EXTMEM_0c7a = 0x7a;",
        CONFIRMED, values=(0xA5, 0x7A),
        note="waits for the peer to present 0xA5, then acknowledges with 0x7A",
    ),
    0x000C7B: Evidence(
        0x000C7B, "handshake mailbox B (gate)", "rw",
        "C L1947 / L2360 / L2763",
        "if (*pbVar10 != 0x5a) break;   // pbVar10 = param_1 + 1",
        CONFIRMED, values=(0x5A,),
    ),
    0x001B83: Evidence(
        0x001B83, "software variable, NOT hardware", "rw",
        "C L3560-3563",
        "DAT_EXTMEM_1b83 = param_7 + 1U >> 1 | (param_7 + 1U) * -0x80;  "
        "pcVar4 = (char *)(*(code *)((ushort)DAT_EXTMEM_1b83 + 0x1b83))(...)",
        CONFIRMED,
        note="index into a code table in the missing half; plain external RAM, "
             "deliberately NOT hooked as a device",
    ),
    # ------------------------------------------------------------- device pages
    0x000C00: Evidence(
        0x000C00, "page 0x0C: key/print ring buffer", "rw",
        "ROM 0x83E0-0x83E8 / 0xDCD5",
        "83E0 MOV DPH,#0Ch / 83E3 MOV DPL,4Fh / 83E7 MOVX @DPTR,A / 83E8 MOV 4Fh,R5 "
        "/ DCD5 MOV DPH,#0Ch / DCD8 MOV DPL,4Eh / MOVX A,@DPTR",
        CONFIRMED, page=True,
        note="RAM[0x4F]/RAM[0x4E] are the write/read pointers of this FIFO "
             "(wrap 0x80..0xA0); 0x0C7A/0x0C7B handshake sits in the same page",
    ),
    0x008100: Evidence(
        0x008100, "page 0x81: write-only output latch", "w",
        "ROM 0x812F-0x8132 / 0x81F3-0x81F6 / 0x84FF-0x8502",
        "812F MOV DPH,#81h / 8132 MOVX @DPTR,A   ...   81F3 MOV DPH,#81h / "
        "81F6 MOVX @DPTR,A   (then 81F7 SETB P3.4)",
        CONFIRMED, page=True,
        note="DPL is 0x31 in the printer path (0x81E7 MOV DPL,#31h); never read",
    ),
    0x008200: Evidence(
        0x008200, "page 0x82: display segment byte 0", "w",
        "ROM 0x830F-0x8317",
        "830F MOV DPH,#92h / 8312 MOVX @DPTR,A ; 8314 MOV DPH,#82h / 8317 MOVX @DPTR,A",
        HYPOTHESIS, page=True,
        note="write-only in every dumped site; the low byte is written from RAM",
    ),
    0x009100: Evidence(
        0x009100, "page 0x91: keyboard column read", "r",
        "ROM 0x8393-0x8399",
        "8393 MOV DPH,#91h / 8396 MOV DPL,A / 8398 MOVX A,@DPTR / 8399 CPL A",
        CONFIRMED, page=True,
        note="DPL = 0x30 | (R0 & 7): row in the low address bits, active-low columns",
    ),
    0x009200: Evidence(
        0x009200, "page 0x92: display segment byte 1", "w",
        "ROM 0x830F-0x8312",
        "830F MOV DPH,#92h / 8312 MOVX @DPTR,A",
        HYPOTHESIS, page=True,
        note="never read by dumped code",
    ),
    0x00A100: Evidence(
        0x00A100, "page 0xA1: display cell window", "rw",
        "ROM 0x810F-0x8112 / 0x8142-0x8159 / 0x8171-0x817C",
        "810F MOV DPH,#A1h / 8112 MOVX @DPTR,A ; 814E MOVX A,@DPTR / ANL A,#80h / "
        "8151 MOV DPL,A ; 8159 MOVX @DPTR,A",
        CONFIRMED, page=True,
        note="low byte selects the cell (RAM[0x3E] or 0x00/0x80); the payload is "
             "a segment byte or 0x40|gray(i) digit-selector (ROM table 0x8203)",
    ),
    0x00A200: Evidence(
        0x00A200, "page 0xA2: display grid/blank select", "w",
        "ROM 0x8319-0x831E / 0x842E-0x8431 / 0x84D6-0x84DB",
        "8319 ANL A,#07h / 831B MOV DPH,#0A2h / 831E MOVX @DPTR,A ; 84D6 MOV DPH,#0A2h "
        "/ 84D9 MOV A,#08h / MOVX @DPTR,A",
        CONFIRMED, page=True,
        note="values 0..7 select a digit, 8 = blank; never read",
    ),
    0x00B100: Evidence(
        0x00B100, "page 0xB1: carriage/motor phase latch", "w",
        "ROM 0x840D-0x8412 / 0x841A-0x841F",
        "840D MOV DPH,#B1h / 8410 MOV A,#0Fh / MOVX @DPTR,A ; 841A MOV DPH,#B1h / "
        "MOV A,#0Eh / MOVX @DPTR,A",
        CONFIRMED, page=True,
        values=(0x0F, 0x0E),
        note="alternating 0x0F/0x0E: HYPOTHESIS stepper/print-motor phases",
    ),
}

#: ``page -> Evidence`` for window lookups.
DEVICE_PAGES: Dict[int, Evidence] = {
    ev.address >> 8: ev for ev in EVIDENCE.values() if ev.page
}

#: ``page -> "r"/"w"/"rw"`` shortcut.
PAGE_DIRECTIONS: Dict[int, str] = {
    page: ev.direction for page, ev in DEVICE_PAGES.items()
}


# ---------------------------------------------------------------------------
# 7-segment font found inside the dumped half (so display bytes stay decodable)
# ---------------------------------------------------------------------------
#: MOVC table of the helper at ROM 0x9EB6:  ADD A,#01h / MOVC A,@A+PC / RET
#: 0x9EBA: 3F 06 5B 4F 66 6D 7D 07 7F 6F 77 7C 39 5E 79 71  ("0".."F")
SEG7_TABLE_ADDRESS = 0x9EBA
SEG7_TABLE = (0x3F, 0x06, 0x5B, 0x4F, 0x66, 0x6D, 0x7D, 0x07,
              0x7F, 0x6F, 0x77, 0x7C, 0x39, 0x5E, 0x79, 0x71)

#: Intel-HEX images that may carry the font / reset vector.
ROM_CANDIDATES = (
    "firmware/nm27c512n.hex",
    "docs/nm27c512n.hex",
)

#: 8051 SFRs the recovery model knows; the HAL forwards the ones that carry
#: board-visible meaning.
SFR_PORTS = {0x80: 0, 0x90: 1, 0xA0: 2, 0xB0: 3}     # P0 P1 P2 P3 -> port index
SFR_SBUF = 0x99
SFR_SCON = 0x98
SFR_TCON = 0x88
SFR_IE = 0xA8
SFR_TIMER1_RELOAD = (0x8B, 0x8D)                      # TL1, TH1
#: bits the board drives *into* the CPU (so recovered code can sample them).
#: CONFIRMED: ROM 0x813D JNB P1.3 = "key present" sense; C L464 reads P1_3.
INPUT_BITS: Tuple[Tuple[int, int], ...] = ((0x90, 3),)


#: Identifier aliases the decompiler left dangling.  The dump declares pins
#: with a dot (``undefined P1.3;``) but the bodies read a mangled name
#: (``cVar1 = P1_3;``); ``Machine.resolve`` does not know the mangled form, so
#: without these bindings the recovered code raises ``KeyError`` instead of
#: running.  Every entry carries the witness that pins it to a pin.
PIN_ALIASES: Dict[str, Tuple[int, int]] = {
    # C L649/L1782: 617 P1_3  <-> ROM 0x813D  JNB P1.3,8142h   (key present)
    "P1_3": (0x90, 3),
    # C L480/L921: P2 = ... ; the dump also declares P2.0 / P2.6
    "P2_0": (0xA0, 0), "P2_6": (0xA0, 6),
    "P0_0": (0x80, 0), "P0_2": (0x80, 2),
    # C L624 (FUN_CODE_83f0: T0 = 0) <-> ROM 0x83F8  CLR P3.4  (ISR epilogue)
    "T0": (0xB0, 4),
    # 8051 pin names: T1 = P3.5, RXD = P3.0, TXD = P3.1
    "T1": (0xB0, 5), "RXD": (0xB0, 0), "TXD": (0xB0, 1),
}


class CodeCell:
    """A read-only view of one ROM byte named ``DAT_CODE_xxxx`` by the dump."""

    __slots__ = ("machine", "addr")

    def __init__(self, machine: Machine, addr: int) -> None:
        self.machine = machine
        self.addr = addr & 0xFFFF

    @property
    def value(self) -> int:
        return self.machine.read_code(self.addr)

    @value.setter
    def value(self, v) -> None:
        raise MissingFirmware(self.addr, "write to code memory (ROM is read-only)")

    def __int__(self) -> int:
        return self.value

    def __index__(self) -> int:
        return self.value

    def __repr__(self) -> str:
        return f"CODE[{self.addr:#06x}]={self.value:#04x}"


def bit_aliases_from_globals(globals_) -> Dict[str, Tuple[int, int]]:
    """Map the dump's mangled ``_N_M`` names onto their real bit addresses.

    The dump declares bit-addressable RAM as ``XX.Y`` (``undefined 22.7;``) but
    the function bodies use ``_2_7``.  The binding is proven twice over:

    * the declared set is exactly ``20.0`` .. ``2f.2``, and every ``_N_M`` name
      used in a body has its ``2N.M`` declaration (e.g. ``_7_4`` <-> ``27.4``);
    * the ROM bytes agree: ``JNB 3Ch`` at 0xB27C is bit address 0x3C = byte 0x27
      bit 4, exactly where the dump tests ``_7_4``; ``JBC 17h`` at 0x8135 is
      bit 0x17 = byte 0x22 bit 7, where the dump tests ``_2_7``.

    ``recover/interp.py`` maps the underscore form to byte 0x0N (wrong); these
    pre-seeded proxies take precedence in ``Machine.proxy_cache``, so the
    recovered code reads the right bits.  Reported to the Lead as the fix
    ``interp.py`` still needs.
    """
    out: Dict[str, Tuple[int, int]] = {}
    for decl in globals_:
        name = getattr(decl, "name", "") or ""
        if "." not in name:
            continue
        head, _, bit = name.partition(".")
        try:
            byte = int(head, 16)
            index = int(bit)
        except ValueError:
            continue
        if 0x20 <= byte <= 0x2F and 0 <= index <= 7:
            out[f"_{byte & 0x0F}_{index}"] = (byte, index)
    return out


def bind_recovered_aliases(machine: Machine, globals_, log=None) -> Dict[str, object]:
    """Seed ``machine.proxy_cache`` with every alias the dump leaves dangling.

    Returns a small report ``{"bits": n, "pins": n, "code": n, "unresolved": [...]}``
    so the caller can be honest about what is still missing.  Nothing is
    guessed: the bit map comes from the dump's own declarations, the pin map
    from the ROM bytes quoted in :data:`PIN_ALIASES`, and ``DAT_CODE_xxxx``
    reads ROM through ``Machine.read_code`` (which reports the missing half).
    """
    from .namespace import BitAddress

    bits = bit_aliases_from_globals(globals_)
    report: Dict[str, object] = {"bits": 0, "pins": 0, "code": 0, "unresolved": []}

    for name, (byte, index) in bits.items():
        machine.proxy_cache.setdefault(name, BitAddress(machine, byte, index))
        report["bits"] = int(report["bits"]) + 1

    for name, (byte, index) in PIN_ALIASES.items():
        machine.proxy_cache.setdefault(name, BitAddress(machine, byte, index))
        report["pins"] = int(report["pins"]) + 1

    for decl in globals_:
        name = getattr(decl, "name", "") or ""
        if name.startswith("DAT_CODE_"):
            try:
                addr = int(name[len("DAT_CODE_"):], 16)
            except ValueError:
                continue
            machine.proxy_cache.setdefault(name, CodeCell(machine, addr))
            report["code"] = int(report["code"]) + 1

    if log is not None:
        log.append(f"aliases bound: {report}")
    return report


class SegmentFont:
    """Decode display bytes with the 7-segment table that is *in* the dump.

    The alphanumeric dot-matrix font the printer path uses lives at ROM 0x6931
    (see ``board/printer.py``) and is in the **missing** half of the ROM, so it
    is unavailable here; the 16-entry 7-segment table at 0x9EBA is present and
    is used for the display window.  When a byte matches no entry the caller
    gets ``None`` - never a guessed character.
    """

    def __init__(self, table: Sequence[int] = SEG7_TABLE) -> None:
        self.table = tuple(int(v) & 0xFF for v in table)
        self.by_mask: Dict[int, str] = {}
        alphabet = "0123456789ABCDEF"
        for index, mask in enumerate(self.table):
            self.by_mask.setdefault(mask, alphabet[index])

    @classmethod
    def from_rom(cls, rom) -> "SegmentFont":
        if rom is None:
            return cls()
        table = tuple(rom.byte(SEG7_TABLE_ADDRESS + i) for i in range(16))
        if table == SEG7_TABLE:
            return cls(table)
        # A different image: only trust it if it still looks like a font.
        if len(set(table)) == 16 and table[0] == 0x3F:
            return cls(table)
        return cls()

    def char(self, value: int) -> Optional[str]:
        return self.by_mask.get(int(value) & 0xFF)


# ---------------------------------------------------------------------------
# 8255 hypothesis helper (explicitly NOT the device identity)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PPI8255Control:
    """One decoded 8255 mode-set word (hypothesis layer only)."""

    raw: int
    mode_set: bool
    group_a_mode: int
    group_b_mode: int
    port_a_input: bool
    port_b_input: bool
    port_c_upper_input: bool
    port_c_lower_input: bool

    def describe(self) -> str:
        return (f"8255 ctrl=0x{self.raw:02X} modeA={self.group_a_mode} "
                f"modeB={self.group_b_mode} A="
                f"{'in' if self.port_a_input else 'out'} B="
                f"{'in' if self.port_b_input else 'out'} "
                f"CU={'in' if self.port_c_upper_input else 'out'} "
                f"CL={'in' if self.port_c_lower_input else 'out'}")

    def as_dict(self) -> Dict[str, object]:
        return {
            "raw": self.raw,
            "mode_set": self.mode_set,
            "group_a_mode": self.group_a_mode,
            "group_b_mode": self.group_b_mode,
            "port_a_input": self.port_a_input,
            "port_b_input": self.port_b_input,
            "port_c_upper_input": self.port_c_upper_input,
            "port_c_lower_input": self.port_c_lower_input,
            "hypothesis": True,
        }


def decode_8255_control(value: int) -> PPI8255Control:
    """Decode ``0x89``/``0xA9`` the way an 8255 would - HYPOTHESIS only.

    ``0x89`` -> group A mode 0, A/B outputs, C inputs.
    ``0xA9`` -> group A mode 1 (strobed output), A/B outputs, C inputs.
    """
    value &= 0xFF
    return PPI8255Control(
        raw=value,
        mode_set=bool(value & 0x80),
        group_a_mode=(value >> 5) & 0x03,
        group_b_mode=(value >> 2) & 0x01,
        port_a_input=bool(value & 0x10),
        port_b_input=bool(value & 0x02),
        port_c_upper_input=bool(value & 0x08),
        port_c_lower_input=bool(value & 0x01),
    )


def parse_8255_control(value: int) -> Dict[str, object]:
    """:func:`decode_8255_control` as a plain dict (convenience for tests/UI)."""
    return decode_8255_control(value).as_dict()


# ---------------------------------------------------------------------------
# device cells
# ---------------------------------------------------------------------------
class WriteLatch:
    """A write-only register: writes are recorded, reads report the gap.

    The dump proves only *writes* at these addresses, so the honest answer to a
    read is "unknown" rather than a value this model invented.
    """

    def __init__(self, address: int, name: str, evidence: Evidence) -> None:
        self.address = address
        self.name = name
        self.evidence = evidence
        self.last: Optional[int] = None
        self.writes: List[int] = []

    def write(self, addr: int, value: int) -> None:
        value &= 0xFF
        self.last = value
        self.writes.append(value)

    def read(self, addr: int) -> int:
        raise MissingFirmware(
            self.address,
            f"read of write-only register {self.name} "
            f"({self.evidence.witness}); no dumped code reads it, so its "
            f"readback is unknown",
        )

    @property
    def pair(self) -> Optional[Tuple[int, int]]:
        """Last two values written - the 0x89/0xA9 style pattern."""
        return tuple(self.writes[-2:]) if len(self.writes) >= 2 else None

    def describe(self) -> str:
        val = "-" if self.last is None else f"0x{self.last:02X}"
        return f"{self.name}@0x{self.address:04X} last={val} writes={len(self.writes)}"


class StatusRegister:
    """A byte the dump both reads and writes (``0x00D3``).

    The firmware waits for ``0x5A`` in it and writes ``0x00`` at reset, so the
    default here is ``0x00`` ("not ready"): nothing is invented for the code to
    read.  A board/peer may present the ready value with :meth:`present`.
    """

    READY = 0x5A

    def __init__(self, address: int, name: str, evidence: Evidence,
                 value: int = 0x00) -> None:
        self.address = address
        self.name = name
        self.evidence = evidence
        self.value = value & 0xFF
        self.writes: List[int] = []
        self.presented: Optional[int] = None

    def write(self, addr: int, value: int) -> None:
        self.value = value & 0xFF
        self.writes.append(self.value)

    def read(self, addr: int) -> int:
        return self.value

    def present(self, value: int) -> None:
        """The peer made the status byte ready."""
        self.presented = value & 0xFF
        self.value = value & 0xFF

    def describe(self) -> str:
        return f"{self.name}@0x{self.address:04X}=0x{self.value:02X}"


class WordRegister:
    """One 16-bit register split over ``hi``/``lo`` addresses (0x0015/0x0016)."""

    def __init__(self, hi: int, lo: int, name: str, evidence: Evidence) -> None:
        self.hi = hi
        self.lo = lo
        self.name = name
        self.evidence = evidence
        self.high = 0
        self.low = 0
        self.writes: List[Tuple[int, int]] = []

    def write(self, addr: int, value: int) -> None:
        value &= 0xFF
        if addr == self.hi:
            self.high = value
        else:
            self.low = value
        self.writes.append((addr, value))

    def read(self, addr: int) -> int:
        return self.high if addr == self.hi else self.low

    @property
    def value(self) -> int:
        return (self.high << 8) | self.low

    def describe(self) -> str:
        return (f"{self.name}@0x{self.hi:04X}/0x{self.lo:04X}"
                f"=0x{self.value:04X} writes={len(self.writes)}")


class HandshakeMailbox:
    """A two-byte ``0xA5/0x5A`` handshake window.

    CONFIRMED shape (C L2303-2307, L1945-1959): the firmware writes 0xA5,0x5A to
    ``lo``/``lo+1``, waits for ``lo == 0xA5`` and acknowledges with ``0x7A``.
    ``peer`` may be set by the board (or :meth:`peer_write`) to present a byte;
    ``peer_ready`` defaults to "idle" so nothing is invented for the firmware to
    read - a peer that never answers simply makes the firmware report a gap.
    """

    ACK = 0x7A
    READY = 0xA5
    GATE = 0x5A

    def __init__(self, address: int, name: str, evidence: Evidence,
                 peer: str = "idle") -> None:
        self.address = address
        self.name = name
        self.evidence = evidence
        self.bytes = bytearray(2)
        self.peer = peer            # "idle" | "ready"
        self.writes: List[Tuple[int, int]] = []
        self.acks = 0
        self.last_written: List[int] = []

    # ---------------------------------------------------------------- firmware
    def write(self, addr: int, value: int) -> None:
        value &= 0xFF
        offset = (addr - self.address) & 0x01
        self.writes.append((offset, value))
        self.last_written.append(value)
        if offset == 0 and value == self.ACK:
            self.acks += 1
        self.bytes[offset] = value
        if value == self.READY:
            # the firmware just rang the doorbell; a live peer answers with 0xA5
            if self.peer == "ready":
                self.bytes[0] = self.READY

    def read(self, addr: int) -> int:
        return self.bytes[(addr - self.address) & 0x01]

    # -------------------------------------------------------------------- peer
    def peer_write(self, low: Optional[int] = None, high: Optional[int] = None) -> None:
        """The modelled peripheral presents bytes to the firmware."""
        if low is not None:
            self.bytes[0] = low & 0xFF
        if high is not None:
            self.bytes[1] = high & 0xFF

    def peer_ready(self, ready: bool = True) -> None:
        self.peer = "ready" if ready else "idle"
        if ready:
            self.bytes[0] = self.READY
            self.bytes[1] = self.GATE

    @property
    def ready(self) -> bool:
        return self.bytes[0] == self.READY

    def describe(self) -> str:
        return (f"{self.name}@0x{self.address:04X} "
                f"[0x{self.bytes[0]:02X},0x{self.bytes[1]:02X}] "
                f"acks={self.acks} peer={self.peer}")


# ---------------------------------------------------------------------------
# the fallback board (only used when board.cashboard is unavailable)
# ---------------------------------------------------------------------------
class _FallbackDisplay:
    """Minimal stand-in honouring ``docs/board_contract.md`` section 2."""

    def __init__(self, columns: int = 8, lines: int = 1) -> None:
        self.columns = int(columns)
        self.lines = int(lines)
        self.cells = [0] * self.columns
        self.font = SegmentFont()

    def write_digit_byte(self, index: int, value: int) -> None:
        if 0 <= int(index) < self.columns:
            self.cells[int(index)] = int(value) & 0xFF

    def text(self) -> str:
        out = []
        for mask in self.cells:
            if not mask:
                out.append(" ")
            else:
                char = self.font.char(mask)
                out.append(char if char else "?")
        return "".join(out)

    def cell_segments(self, index: int) -> int:
        return self.cells[int(index) % self.columns]

    def render_rows(self, scale: int = 1) -> List[str]:
        return ["".join("." if m & (1 << b) else " " for b in range(8))
                for m in self.cells]


class _FallbackKeyboard:
    """Minimal stand-in honouring ``docs/board_contract.md`` section 3."""

    KEYS = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ".", "00",
            "СУММА", "ОПЛ", "X", "ITOG", "ОТМЕНА", "ВОЗВРАТ", "СКИДКА",
            "КАССИР", "СЕРВИС", "РЕЖИМ", "ВВОД", "СБРОС", "ПОДЫТОГ",
            "ЧЕК", "КС", "Z", "ПИТ", "СТРЕЛКА_ВЛЕВО", "СТРЕЛКА_ВПРАВО",
            "ПРОБЕЛ", "ТАБ"]

    def __init__(self) -> None:
        self.keys = list(self.KEYS)
        self._pressed: List[str] = []

    def press(self, name: str) -> None:
        if name in self.keys and name not in self._pressed:
            self._pressed.append(name)

    def release(self, name: str) -> None:
        if name in self._pressed:
            self._pressed.remove(name)

    def tap(self, name: str) -> None:
        self.press(name)
        self.release(name)

    def is_pressed(self, name: str) -> bool:
        return name in self._pressed

    def any_pressed(self) -> bool:
        return bool(self._pressed)


class _FallbackPrinter:
    """Minimal stand-in honouring ``docs/board_contract.md`` section 4."""

    def __init__(self, columns: int = 40) -> None:
        self.columns = int(columns)
        self.lines: List[str] = []
        self._line = ""

    def write_byte(self, value: int) -> None:
        value &= 0xFF
        if value == 0x0A:
            self._newline()
        elif value == 0x0D:
            self._newline()
        elif value >= 0x20:
            self._line += chr(value)
            if len(self._line) >= self.columns:
                self._newline()

    def _newline(self) -> None:
        self.lines.append(self._line)
        self._line = ""

    def feed(self, lines: int = 1) -> None:
        for _ in range(max(0, int(lines))):
            self._newline()

    def paper(self) -> List[str]:
        return list(self.lines + ([self._line] if self._line else []))

    def text(self) -> str:
        return "\n".join(self.paper())

    def clear(self) -> None:
        self.lines = []
        self._line = ""

    def is_busy(self) -> bool:
        return False


class _FallbackBoard:
    """Tiny data-space model used only when ``board/cashboard.py`` is absent."""

    def __init__(self) -> None:
        self.display = _FallbackDisplay()
        self.keyboard = _FallbackKeyboard()
        self.printer = _FallbackPrinter()
        self.ram: Dict[int, int] = {}
        self.trace: List[Tuple[int, int, str]] = []
        self._port_latch = [0xFF, 0xFF, 0xFF, 0xFF]
        self.print_latch = 0x00

    def tick(self, cycles: int) -> None:
        return None

    def ext_probe(self, addr: int) -> bool:
        addr &= 0xFFFF
        return (addr >> 8) in DEVICE_PAGES or addr < 0x8000

    def ext_write(self, addr: int, value: int) -> None:
        addr &= 0xFFFF
        value &= 0xFF
        self.trace.append((addr, value, "w"))
        page, low = addr >> 8, addr & 0xFF
        if addr < 0x8000:
            self.ram[addr] = value
            return
        if page == 0xA1:
            self.display.write_digit_byte(low & 0x07, value)
        elif page == 0x81:
            self.print_latch = value          # ROM 0x81F3: latch, P3.4 strobes
        else:
            self.ram[addr] = value

    def ext_read(self, addr: int) -> int:
        addr &= 0xFFFF
        page, low = addr >> 8, addr & 0xFF
        if page == 0x91:
            return 0xFF
        if page == 0xA1:
            return self.display.cell_segments(low & 0x07)
        return self.ram.get(addr, 0xFF)

    def port_read(self, port: int) -> int:
        if port == 1 and self.keyboard.any_pressed():
            return 0xFF
        return 0xFF

    def port_write(self, port: int, value: int) -> None:
        """Latch the port and reproduce the ROM's P3.4 strobe edge (0x81F7)."""
        old = self._port_latch[port & 3]
        self._port_latch[port & 3] = value & 0xFF
        self.port_change(port & 3, old, value & 0xFF)

    def port_change(self, port: int, old: int, new: int) -> None:
        if port == 3:
            was, now = (old >> 4) & 1, (new >> 4) & 1
            if now and not was:
                self.printer.write_byte(self.print_latch)

    def serial_write(self, byte: int) -> None:
        return None

    def reset(self) -> None:
        self.ram.clear()
        self._port_latch = [0xFF] * 4
        self.print_latch = 0x00


def _try_import_board():
    try:                                          # pragma: no cover - env dependent
        from board.cashboard import CashRegisterBoard
        return CashRegisterBoard
    except Exception:
        return None


# ---------------------------------------------------------------------------
# the HAL
# ---------------------------------------------------------------------------
class CashRegisterHAL:
    """Attach the recovered machine to the cash register's devices.

    Parameters
    ----------
    board:
        ``board.cashboard.CashRegisterBoard`` or the internal fallback.  When
        ``None`` the HAL imports ``board/`` and falls back if that fails.
    rom:
        Code image used for the 7-segment table and the reset vector.  Loaded
        from ``firmware/nm27c512n.hex`` when not given and present.
    strict:
        When true (default) a read of a window the dump never reads raises
        :class:`MissingFirmware` instead of returning latch state.
    """

    def __init__(self, board=None, rom=None, strict: bool = True) -> None:
        self.strict = bool(strict)
        self.font = SegmentFont()
        if board is None:
            factory = _try_import_board()
            board = factory() if factory is not None else _FallbackBoard()
            self.board_is_fallback = factory is None
        else:
            self.board_is_fallback = isinstance(board, _FallbackBoard)
        self.board = board
        self.rom = rom
        if rom is not None:
            self.font = SegmentFont.from_rom(rom)

        #: named cells (low addresses) with their evidence
        self.cells: Dict[int, object] = {}
        #: page -> evidence for every proven window
        self.pages: Dict[int, Evidence] = dict(DEVICE_PAGES)
        #: diagnostics
        self.observed: Dict[int, List[int]] = {}
        self.reads: Dict[int, int] = {}
        self.writes: Dict[int, int] = {}
        self.missing: List[MissingFirmware] = []
        self.sfr_events: List[Tuple[int, int, int]] = []
        self.installed = False
        #: addresses answered from program memory because the ROM proves the
        #: read is a decompiler-rendered ``MOVC`` (see :meth:`_scan_movc_windows`)
        self.rom_window_reads: Dict[int, int] = {}
        self._movc_windows: List[Tuple[int, int]] = self._scan_movc_windows(rom)

        self._build_cells()

    # ------------------------------------------------------------- evidence
    @staticmethod
    def evidence(addr: int) -> Optional[Evidence]:
        """Evidence for one address (named cell first, then its page)."""
        addr &= 0xFFFF
        hit = EVIDENCE.get(addr)
        if hit is not None:
            return hit
        return DEVICE_PAGES.get(addr >> 8)

    def claims(self, addr: int) -> bool:
        """True when the HAL (not the flat bytearray) serves ``addr``."""
        addr &= 0xFFFF
        if addr in self.cells:
            return True
        return (addr >> 8) in self.pages

    def hardware_addresses(self) -> List[int]:
        """Every named address the HAL models (for tests and the UI)."""
        return sorted(self.cells)

    # ---------------------------------------------------------------- build
    def _build_cells(self) -> None:
        for addr, ev in EVIDENCE.items():
            if ev.page or addr == 0x1B83:
                continue                    # windows are handled as pages
            if addr in (0x000C7A, 0x000C7B, 0x0000FF):
                continue                    # covered by their mailbox object
            if addr == 0x0000FE:
                cell = HandshakeMailbox(addr, ev.name, ev)       # covers 0x00FE/FF
                self.cells[addr] = cell
                self.cells[addr + 1] = cell
                continue
            if addr == 0x000015:
                cell = WordRegister(0x000015, 0x000016, ev.name, ev)
                self.cells[0x000015] = cell
                self.cells[0x000016] = cell
                continue
            if addr == 0x000016:
                continue
            if addr == 0x0000D3:
                self.cells[addr] = StatusRegister(addr, ev.name, ev)
                continue
            # everything else is a proven write-only register
            self.cells[addr] = WriteLatch(addr, ev.name, ev)

        # mailbox B: 0x0C7A + 0x0C7B in one object
        mailbox = HandshakeMailbox(0x0C7A, "handshake mailbox B", EVIDENCE[0x000C7A])
        self.cells[0x0C7A] = mailbox
        self.cells[0x0C7B] = mailbox
        self.mailbox_b = mailbox
        self.mailbox_a = self.cells[0x0000FE]
        self.word_register = self.cells[0x000015]
        self.status_byte = self.cells[0x0000D3]

        # 0x0009 / 0x000B are the two control latches; keep them addressable by
        # name so the diagnostics can talk about "control latch 1/2".
        self.control_latches = {a: self.cells[a] for a in (0x000009, 0x00000B)}

    # -------------------------------------------------------------- install
    def install(self, machine: Machine) -> "CashRegisterHAL":
        """Attach the HAL to ``machine`` (idempotent)."""
        self.machine = machine
        if self not in machine.xdata_hooks:
            machine.xdata_hooks.append(self)
        for addr in (SFR_TCON, SFR_SCON, SFR_SBUF, SFR_IE, 0x8B, 0x8D, 0x80, 0x90, 0xA0, 0xB0):
            machine.install_sfr_listener(addr, self._make_sfr_listener(addr))
        self.installed = True
        return self

    def _make_sfr_listener(self, addr: int) -> Callable[[int, int], None]:
        def listener(value: int, old: int) -> None:
            self.on_sfr_write(addr, value, old)
        return listener

    # ------------------------------------------------------------ xdata hook
    def __call__(self, addr: int, write: bool, value: int = 0):
        """``Machine.xdata_hooks`` entry point.

        Returning ``None`` lets the machine fall through to its flat external
        RAM (real data); returning a value consumes the access.
        """
        addr &= 0xFFFF
        try:
            if write:
                return self._write(addr, value)
            return self._read(addr)
        except MissingFirmware as exc:
            self.missing.append(exc)
            raise

    # --------------------------------------------------------------- reads
    def _read(self, addr: int):
        cell = self.cells.get(addr)
        if cell is not None:
            value = cell.read(addr)
            self.reads[addr] = self.reads.get(addr, 0) + 1
            return value & 0xFF
        page = addr >> 8
        ev = self.pages.get(page)
        if ev is None:
            return None                        # plain external RAM / code data
        if not ev.readable and self.strict:
            rom_value = self._rom_window_read(addr)
            if rom_value is not None:
                # not latch state and not a guess: the ROM instruction stream
                # proves this address is read as program memory (MOVC)
                return rom_value
            raise MissingFirmware(
                addr, f"read of write-only window 0x{page:02X}xx ({ev.witness})")
        self.reads[addr] = self.reads.get(addr, 0) + 1
        return self._board_read(addr) & 0xFF

    # ------------------------------------------- decompiler-rendered MOVC reads
    @staticmethod
    def _scan_movc_windows(rom) -> List[Tuple[int, int]]:
        """Merged address ranges the ROM proves are read as *program* memory.

        ``MOVC A,@A+PC`` (opcode ``0x83``) reads ``ROM[PC + 1 + A]`` with an
        8-bit ``A``, so the instruction at ``P`` proves that every address
        ``P+1 .. P+255`` is read from ROM - never from external data memory.

        The decompiler renders such a read as a plain pointer dereference
        (``*(byte *)((ushort)(param_3 + 0xac) + 0x8157)`` in the refresh ISR,
        which the ROM answers at ``0x8156: MOVC A,@A+PC``), with no space
        marker, while genuine MOVX accesses come out as ``CONCAT11(hi, lo)`` or
        as named ``DAT_EXTMEM_xxxx`` cells.  When recovered code therefore
        "reads" an address in a window the dump never reads as data (a
        write-only page), the byte in the ROM image is the *real* value at that
        address, so it is served from ROM instead of inventing latch state or
        reporting a gap that is not one.

        ``MOVC A,@A+DPTR`` (``0x93``) is deliberately not included: DPTR is
        computed elsewhere, so the reachable range cannot be bounded by the
        instruction alone.
        """
        if rom is None:
            return []
        windows: List[Tuple[int, int]] = []
        for addr in range(0x8000, 0x10000):
            try:
                if rom.is_mapped(addr) and rom.byte(addr) == 0x83:
                    start = addr + 1
                    windows.append((start, min(start + 0xFF, 0xFFFF)))
            except Exception:                   # noqa: BLE001 - a scan, not a gate
                continue
        if not windows:
            return []
        windows.sort()
        merged = [windows[0]]
        for start, end in windows[1:]:
            last_start, last_end = merged[-1]
            if start <= last_end + 1:
                merged[-1] = (last_start, max(last_end, end))
            else:
                merged.append((start, end))
        return merged

    def _rom_window_read(self, addr: int) -> Optional[int]:
        """The ROM byte at ``addr`` when the instruction stream proves a MOVC.

        ``None`` when there is no ROM, the address is outside program memory,
        or no ``MOVC A,@A+PC`` can reach it - the caller then reports the gap
        as usual.
        """
        if self.rom is None or not self._movc_windows:
            return None
        if not (0x8000 <= addr <= 0xFFFF) or not self.rom.is_mapped(addr):
            return None
        for start, end in self._movc_windows:
            if addr < start:
                return None                     # windows are sorted
            if addr <= end:
                self.rom_window_reads[addr] = self.rom_window_reads.get(addr, 0) + 1
                return self.rom.byte(addr) & 0xFF
        return None

    # -------------------------------------------------------------- writes
    def _write(self, addr: int, value: int):
        value &= 0xFF
        cell = self.cells.get(addr)
        if cell is not None:
            cell.write(addr, value)
            self.observed.setdefault(addr, []).append(value)
        page = addr >> 8
        if cell is not None or page in self.pages:
            self.writes[addr] = self.writes.get(addr, 0) + 1
            self._board_write(addr, value)
            return value
        return None

    # ------------------------------------------------------------ board glue
    def _board_write(self, addr: int, value: int) -> None:
        self.board.ext_write(addr, value)

    def _board_read(self, addr: int) -> int:
        return self.board.ext_read(addr)

    # ------------------------------------------------------------ SFR bridge
    def on_sfr_write(self, addr: int, value: int, old: int) -> None:
        """``Machine.install_sfr_listener`` callback: SFR -> board pins."""
        self.sfr_events.append((addr, value, old))
        board = self.board
        if addr in SFR_PORTS:
            port = SFR_PORTS[addr]
            board.port_write(port, value)
            board.port_change(port, old, value)
            return
        if addr == SFR_SBUF:
            board.serial_write(value)
            return
        if addr in SFR_TIMER1_RELOAD or addr == SFR_TCON or addr == SFR_SCON:
            return                       # seen, no pin-level meaning modelled

    def sync_inputs(self, machine: Machine) -> None:
        """Drive board state onto the SFR bits the recovered code samples."""
        board = self.board
        for sfr_addr, bit in INPUT_BITS:
            try:
                pins = board.port_read(SFR_PORTS[sfr_addr]) & 0xFF
            except Exception:
                pins = 0xFF
            mask = 1 << bit
            current = machine.sfr(sfr_addr)
            new = (current | mask) if (pins & mask) else (current & ~mask & 0xFF)
            if new != current:
                machine.set_sfr(sfr_addr, new)

    # ------------------------------------------------------------- helpers
    def tick(self, cycles: int) -> None:
        try:
            self.board.tick(int(cycles))
        except Exception:
            pass

    def xdata_write(self, addr: int, value: int) -> None:
        """Write through the installed policy (used by demo/session/test code)."""
        consumed = self._write(addr & 0xFFFF, value & 0xFF)
        if consumed is None:
            # no device claims it; the caller is expected to own real RAM
            raise MissingFirmware(addr, "no device claims this address")

    def xdata_read(self, addr: int) -> int:
        value = self._read(addr & 0xFFFF)
        if value is None:
            raise MissingFirmware(addr, "no device claims this address")
        return value & 0xFF

    # -------------------------------------------------------- device facade
    @property
    def display(self):
        return self.board.display

    @property
    def keyboard(self):
        return self.board.keyboard

    @property
    def printer(self):
        return self.board.printer

    def tap(self, name: str) -> None:
        self.board.keyboard.tap(name)

    def write_display_byte(self, index: int, value: int) -> None:
        """Write one display cell through the same window the firmware uses."""
        self.xdata_write(0xA100 + (int(index) & 0x07), value & 0xFF)

    def write_display_char(self, index: int, char: str) -> int:
        """Encode ``char`` with the ROM font and write it to a display cell."""
        alphabet = "0123456789ABCDEF"
        if char == " ":
            mask = 0x00
        elif char in alphabet:
            mask = SEG7_TABLE[alphabet.index(char)]
        else:
            raise ValueError(f"no segment code for {char!r} in ROM table 0x9EBA")
        self.write_display_byte(index, mask)
        return mask

    def print_char(self, value: int, strobe: bool = True) -> None:
        """Reproduce ROM 0x81F3-0x81F7 / 0x83F8: latch, then pulse P3.4.

        ``board.port_write`` performs the edge detection itself (see
        ``board/cashboard.py`` ``port_change``), so P3.4 is only driven here.
        """
        self.xdata_write(0x8100, value & 0xFF)
        if strobe:
            self.board.port_write(3, 0x00)     # CLR P3.4 (ROM 0x83F8)
            self.board.port_write(3, 0x10)     # SETB P3.4 (ROM 0x81F7) -> strobe

    def print_text(self, text: str) -> None:
        for ch in text:
            self.print_char(ord(ch) & 0xFF)
        self.print_char(0x0A)

    # ---------------------------------------------------------- diagnostics
    def reload_period(self, machine: Optional[Machine] = None) -> int:
        """Timer-1 reload period in machine cycles, taken from TL1/TH1.

        The recovered ISR reloads TL1/TH1 itself (C L503-504, L572-573); the
        default 0x35C comes from the ROM value 0xFC/A4 used at 0x81C7/0x81CA.
        """
        if machine is not None:
            reload = (machine.sfr(0x8D) << 8) | machine.sfr(0x8B)
            period = (0x10000 - reload) & 0xFFFF
            if period:
                return period
        return 0x35C

    def describe(self) -> str:
        return (f"CashRegisterHAL(board={type(self.board).__name__}, "
                f"cells={len(self.cells)}, pages={len(self.pages)}, "
                f"strict={self.strict})")


def load_rom(path_candidates: Sequence[str] = ROM_CANDIDATES):
    """Best-effort Intel-HEX load of the firmware image (``None`` on failure).

    **Record space, by design.**  ``firmware/nm27c512n.hex`` stores the 32 KiB
    image at record addresses ``0x8000..0xFFFF`` - Ghidra's load address, the
    space every ``FUN_CODE_xxxx`` label and every prose cite ("ROM 0x8135")
    uses, and the space this pseudo-code world (MOVC gates, the 7-segment
    font at record ``0x9EBA``, the XDATA evidence strings) is built around.
    The bytes are *really* CPU addresses ``0x0000..0x7FFF`` (record minus
    ``0x8000``: record ``0x8000`` is the reset vector ``LJMP 0x0A06``, and
    CPU ``0x0000`` is where an 8051 boots).  The single translation point
    lives in :func:`recover.realrun._cpu_space_rom`, where
    :class:`~recover.realrun.RealRunner` builds its own rebased copy for
    execution; this loader deliberately does **not** shift anything, and
    MOVX/XDATA windows (``0x81xx``/``0x91xx``/``0xA1xx`` ...) are external
    addresses that are never rebased anywhere.
    """
    try:
        from m8051.rom import load_intel_hex
    except Exception:
        return None
    for candidate in path_candidates:
        for base in (candidate, os.path.join(os.path.dirname(__file__), "..", candidate)):
            try:
                if os.path.isfile(base):
                    return load_intel_hex(base)
            except Exception:
                continue
    return None
