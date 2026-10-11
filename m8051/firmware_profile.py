"""How the ETIM ROM dump is turned into a runnable 64 KiB code image.

The only firmware this project runs is ``nm27c512n.hex`` (0x8000..0xFFFF,
reset vector ``LJMP 0x0A06``).

The ETIM firmware is split across two devices: the code we have lives entirely
above 0x8000, and everything it calls below 0x0FFF - including the reset code
at 0x0A06 and the interrupt handlers - was in the AT89C55's internal ROM, which
nobody dumped.  There is therefore *no* way to run it completely faithfully.

What this module does is make the best available image, and label every part of
it so the UI can say exactly what is real and what is a stand-in:

``authoritative``
    Address ranges that come from the real ETIM dump.
``stub``
    Ranges we synthesised (reset/vector trampolines, ``RET`` padding).
``missing``
    Ranges with no code at all; hitting them stops the CPU and is reported.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .rom import ROM
from .shim import SHIM_BASE, build_shim

__all__ = ["FirmwareProfile", "load_firmware", "available_images", "PROFILES"]

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIRMWARE_DIR = os.path.join(HERE, "firmware")

ETIM_IMAGE = "nm27c512n.hex"

# Where the real ETIM code starts (its first byte is a LJMP dispatch table).
ETIM_ENTRY = 0x8000
# The reset target named by the ETIM reset vector (in the missing low ROM).
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
        Point the synthesised reset vector at the first byte that *is*
        present, instead of at an address nobody dumped.
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

    # The reset/vector trampolines belong to the missing low ROM: synthesise them.
    # The target is the first byte the primary image actually provides, so the
    # machine starts in real code instead of jumping into an undumped gap (or
    # into the shim itself, which is an infinite self-loop).
    reset_target = coverage[0] if coverage else 0x0000
    shim = build_shim(reset_target)
    for addr, value in shim.items():
        profile.rom._mem[addr] = value
    profile.reset_pc = 0x0000
    profile.stub.append((min(shim), max(shim)))
    profile.notes.append(
        f"reset borrowed: the real reset vector lives in the missing half of the "
        f"ROM, so a 3-byte LJMP to 0x{reset_target:04X} (the first byte this "
        f"image provides) was synthesised"
    )
    if coverage and coverage[0] != 0x0000:
        profile.notes.append(
            f"execution starts at 0x{coverage[0]:04X}; the vector table at "
            f"0x0000..0x{coverage[0] - 1:04X} was not dumped, so no interrupt "
            f"can be serviced"
        )

    if pad_missing:
        filled = [r for r in _ret_stub_gaps(profile.rom, SHIM_BASE + 0x40) if r[1] > r[0]]
        for lo, hi in filled:
            profile.stub.append((lo, hi))
        if filled:
            total = sum(hi - lo + 1 for lo, hi in filled)
            profile.notes.append(
                f"{total} bytes of undumped low memory padded with RET so a call "
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
