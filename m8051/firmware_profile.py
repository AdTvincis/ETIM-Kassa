"""How the ETIM ROM dump is turned into a runnable 64 KiB code image.

The only firmware this project runs is ``nm27c512n.hex``.

Where the image really lives
----------------------------
The Intel-HEX records of ``nm27c512n.hex`` carry **programmer offsets**:
they are written at ``0x8000..0xFFFF``, but the image is the *low* 32 KiB of
CPU code space (``0x0000..0x7FFF``).  Two pieces of evidence make this a
fact rather than a hypothesis:

* the bytes at record offset ``0x8000`` are ``02 0A 06`` - ``LJMP 0x0A06``,
  a real MCS-51 **reset vector**, which only makes sense at CPU ``0x0000``,
  and its target ``0x0A06`` lies *inside this very image*;
* interrupt vectors land where an 8051 expects them once the image is
  rebased (CPU ``0x0003``, ``0x0013``, ``0x0023``), and with the rebase the
  firmware executes millions of cycles without hitting an undumped address
  while driving the display and keyboard of the emulated board.

So :func:`load_firmware` rebases the dump by ``-0x8000``: the CPU starts at
the **real** reset vector (no trampoline is needed) and everything the image
provides is real code.  What this dump does *not* contain is the **upper**
half ``0x8000..0xFFFF``; a fetch there stops the CPU with an honest message.

Provenance labels (``FirmwareProfile.provenance``) tell the UI which byte
came from where:

``stub``
    Ranges we synthesised (only when the real reset vector is unusable -
    e.g. a dump that lacks bytes at ``0x0000``; the normal ETIM path has
    none).
``missing``
    Ranges with no code at all (for the rebased ETIM image: the upper half);
    hitting them stops the CPU and is reported.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .rom import ROM, rebase_low32k
from .shim import build_shim

__all__ = ["FirmwareProfile", "load_firmware", "available_images", "PROFILES"]

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIRMWARE_DIR = os.path.join(HERE, "firmware")

ETIM_IMAGE = "nm27c512n.hex"

# The Intel-HEX records of the ETIM dump are written at programmer offsets
# 0x8000..0xFFFF; the image itself is CPU code space 0x0000..0x7FFF (see the
# module docstring for the evidence).  A dump with this exact coverage is
# rebased by -0x8000 when loaded.
ETIM_RECORD_BASE = 0x8000
# Where the real ETIM code starts in CPU space after the rebase.
ETIM_ENTRY = 0x0000
# The reset target named by the ETIM reset vector (LJMP 0x0A06); with the
# rebase it lies inside the image, so the reset path is real code.
ETIM_LOW_ENTRY = 0x0A06


def available_images() -> List[str]:
    if not os.path.isdir(FIRMWARE_DIR):
        return []
    return sorted(
        f for f in os.listdir(FIRMWARE_DIR)
        if f.lower().endswith((".hex", ".ihx", ".bin"))
    )


@dataclass
class FirmwareProfile:
    """A runnable code image plus provenance information."""

    name: str
    rom: ROM
    reset_pc: int
    #: address ranges copied from the primary (real) dump
    authoritative: List[Tuple[int, int]] = field(default_factory=list)
    #: address ranges taken from the secondary dump
    filler: List[Tuple[int, int]] = field(default_factory=list)
    #: address ranges we synthesised
    stub: List[Tuple[int, int]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def provenance(self, addr: int) -> str:
        """Which source put a byte at ``addr`` - or ``missing`` if none did.

        An address that no image covers is ``missing`` even when it happens to
        fall inside a *declared* range: the ranges describe intent, the ROM
        dictionary describes content, and only the content can be executed.
        """
        if not self.rom.is_mapped(addr):
            return "missing"
        for lo, hi in self.authoritative:
            if lo <= addr <= hi:
                return "flash"
        for lo, hi in self.filler:
            if lo <= addr <= hi:
                return "filler"
        for lo, hi in self.stub:
            if lo <= addr <= hi:
                return "stub"
        return "missing"

    def summary(self) -> str:
        counts = {"flash": 0, "filler": 0, "stub": 0, "missing": 0}
        for addr in range(0x10000):
            counts[self.provenance(addr)] += 1
        return (
            f"{self.name}: reset=0x{self.reset_pc:04X}, "
            f"flash={counts['flash']}B, filler={counts['filler']}B, "
            f"stub={counts['stub']}B, missing={counts['missing']}B"
        )

    def missing_count(self) -> int:
        return sum(
            1 for addr in range(0x10000) if self.provenance(addr) == "missing"
        )


def _merge(target: ROM, source: ROM, only_gaps: bool = True) -> None:
    for addr, value in source._mem.items():          # noqa: SLF001 - same package
        if only_gaps and addr in target._mem:
            continue
        target._mem[addr] = value
    target.mapped = len(target._mem)


def _ret_stub_gaps(rom: ROM, skip_below: int = 0x0000) -> List[Tuple[int, int]]:
    """Fill unmapped runs above ``skip_below`` with ``RET`` padding."""
    filled = []
    for lo, hi in rom.unmapped_ranges():
        lo = max(lo, skip_below)
        if hi < lo:
            continue
        for addr in range(lo, hi + 1):
            rom._mem[addr] = 0x22                      # RET
        filled.append((lo, hi))
    rom.mapped = len(rom._mem)
    return filled


#: The rebase rule lives in one place: :func:`m8051.rom.rebase_low32k`
#: (this alias keeps the old private name for existing callers; the evidence
#: is in the module docstring).
_rebase_low32k = rebase_low32k


def load_firmware(
    primary: str = ETIM_IMAGE,
    secondary: Optional[str] = None,
    *,
    reset_to_entry: bool = True,
    pad_missing: bool = False,
) -> FirmwareProfile:
    """Assemble the most runnable image available and record its provenance.

    Parameters
    ----------
    primary:
        The firmware to actually emulate (defaults to the ETIM dump).
    secondary:
        Optional dump used only to fill address ranges the primary lacks.
    reset_to_entry:
        When the image provides no usable reset vector, point the synthesised
        one at a byte the image really has, instead of at an address nobody
        dumped.  (The rebased ETIM dump has a real reset vector, so this only
        matters for other images.)
    pad_missing:
        Replace remaining gaps with ``RET``.  Off by default and it should stay
        off: a ``RET`` there pops a zero return address and silently lands the
        CPU back on the reset vector, so the machine appears to "run" while
        doing nothing at all and the missing ROM is never reported.  With padding
        off, execution stops at the first undumped address with an explicit
        message, which is the honest outcome.
    """
    path = os.path.join(FIRMWARE_DIR, primary)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"firmware image not found: {path}")
    real = ROM(primary).load_file(path)
    rebased = _rebase_low32k(real)
    coverage = real.coverage()
    profile = FirmwareProfile(
        name=primary,
        rom=ROM(primary),
        reset_pc=0x0000,
    )
    if coverage:
        profile.authoritative.append(coverage)

    if secondary:
        sec_path = os.path.join(FIRMWARE_DIR, secondary)
        if os.path.isfile(sec_path):
            filler_rom = ROM(secondary).load_file(sec_path)
            before = len(profile.rom)
            _merge(profile.rom, filler_rom, only_gaps=True)
            gained = len(profile.rom) - before
            if gained:
                lo = min((a for a in filler_rom._mem if a not in real._mem), default=None)
                profile.filler.append((lo if lo is not None else 0, 0xFFFF))
                profile.notes.append(
                    f"{gained} bytes of low address space taken from "
                    f"{secondary} (a different program) so calls below "
                    f"0x{coverage[0]:04X} land on real instructions instead of 0xFF"
                )

    _merge(profile.rom, real, only_gaps=False)         # real bytes always win

    if rebased:
        profile.notes.append(
            f"records rebased by -0x{ETIM_RECORD_BASE:04X}: the hex carries "
            f"programmer offsets, the image is CPU 0x0000..0x7FFF "
            f"(record 0x{ETIM_RECORD_BASE:04X} is the reset vector LJMP 0x0A06)"
        )

    # The reset vector: real bytes when the image provides them (the rebased
    # ETIM dump does - its first byte is ``LJMP 0x0A06``).  Only when the
    # image lacks a usable vector is a trampoline synthesised, and then it
    # points at the first byte the image really has.
    reset_target: Optional[int] = None
    if profile.rom.byte(0x0000) == 0x02:
        candidate = profile.rom.word(0x0001)
        if profile.rom.is_mapped(candidate):
            reset_target = candidate
    if reset_target is not None:
        profile.reset_pc = 0x0000
        profile.notes.append(
            f"reset vector is REAL: 0x0000 = LJMP 0x{reset_target:04X}, "
            f"covered by this image - no trampoline needed"
        )
    else:
        reset_target = coverage[0] if coverage else 0x0000
        shim = build_shim(reset_target)
        for addr, value in shim.items():
            profile.rom._mem[addr] = value
        profile.reset_pc = 0x0000
        profile.stub.append((min(shim), max(shim)))
        profile.notes.append(
            f"reset borrowed: this image provides no usable reset vector, so a "
            f"3-byte LJMP to 0x{reset_target:04X} (the first byte it provides) "
            f"was synthesised"
        )
    if coverage and coverage[0] != 0x0000:
        profile.notes.append(
            f"execution starts at 0x{coverage[0]:04X}; the vector table at "
            f"0x0000..0x{coverage[0] - 1:04X} was not dumped, so no interrupt "
            f"can be serviced"
        )
    if rebased:
        profile.notes.append(
            f"the upper half 0x{ETIM_RECORD_BASE:04X}..0xFFFF is NOT in this "
            f"dump; a fetch there stops the CPU with an explicit message"
        )

    if pad_missing:
        filled = [r for r in _ret_stub_gaps(profile.rom, 0x0000) if r[1] > r[0]]
        for lo, hi in filled:
            profile.stub.append((lo, hi))
        if filled:
            total = sum(hi - lo + 1 for lo, hi in filled)
            profile.notes.append(
                f"{total} bytes of undumped memory padded with RET so a call "
                f"into the missing ROM returns instead of halting the CPU"
            )

    profile.rom.mapped = len(profile.rom._mem)
    return profile


PROFILES: Dict[str, Dict[str, object]] = {
    "etim": {
        "primary": ETIM_IMAGE,
        # Deliberately no filler: only nm27c512n.hex is this project's
        # firmware.  Merging anything else under it would let the CPU execute
        # foreign code and quietly report nonsense instead of stopping at the
        # exact undumped address that proves the gap.
        "secondary": None,
        "description": 'Firmware кассы AO "ETIM" (СПб), 1994-95',
    },
}
