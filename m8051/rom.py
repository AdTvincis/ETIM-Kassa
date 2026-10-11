"""Code memory images for the 8051 emulator."""

from __future__ import annotations

import os
from typing import Dict, Iterable, Optional, Tuple

__all__ = ["ROM", "load_intel_hex", "rebase_low32k"]


def rebase_low32k(rom: "ROM") -> bool:
    """Shift a programmer-offset dump (records at 0x8000..0xFFFF) down to
    the CPU addresses it really occupies (0x0000..0x7FFF).

    Single source of truth for the ETIM dump rule (see
    :mod:`m8051.firmware_profile` for the evidence: record 0x8000 holds the
    reset vector ``LJMP 0x0A06`` whose target lies inside the same image, so
    the records are programmer offsets, not CPU addresses).  Returns ``True``
    when the shift happened; images with any other coverage are untouched.
    """
    if rom.coverage() != (0x8000, 0xFFFF):
        return False
    shifted = {addr - 0x8000: value for addr, value in rom._mem.items()}
    rom._mem.clear()
    for addr, value in shifted.items():
        rom._mem[addr] = value
    rom.mapped = len(rom._mem)
    return True


class _Mapped(dict):
    """Mapped-byte dict that mirrors every write into a flat 64 KiB array.

    ``ROM.byte`` is the hottest read in the emulator (two calls per
    executed instruction), and a ``dict.get`` with a mask is measurably
    slower than a single bytearray index.  The dict side keeps all the
    sparse bookkeeping (:meth:`ROM.stack`, :meth:`ROM.unmapped_ranges`,
    ``addr in rom._mem``); the flat side is the read view.

    Writes also arrive as plain ``rom._mem[addr] = value`` assignments
    from :mod:`m8051.firmware_profile`, so the mirror has to live in
    ``__setitem__`` itself rather than in ROM's methods.  Unmapped bytes
    stay ``0xFF`` (erased EPROM), which is exactly what ``byte()`` must
    return for addresses nobody loaded.
    """

    __slots__ = ("flat",)

    #: The read view carries a three-byte mirror of addresses 0..2 so the
    #: fetch path can index ``flat[p]`` for ``p == 0x10000..0x10002`` without
    #: masking (``p = pc + 1`` reaches exactly there when PC sits at the top
    #: of code space).  Byte 0x10000 mirrors address 0, and so on.
    _MIRROR = 0x10000

    def __init__(self) -> None:
        super().__init__()
        self.flat = bytearray(b"\xFF" * (self._MIRROR + 3))

    def clear(self) -> None:
        """dict.clear() не проходит через ``__delitem__`` — плоский буфер
        остался бы со старыми байтами.  Rebase (``rebase_low32k``) полагается
        на чистку: после сдвига верхняя половина обязана читаться как 0xFF."""
        dict.clear(self)
        flat = self.flat
        flat[:] = b"\xFF" * len(flat)

    def __setitem__(self, addr, value) -> None:
        addr &= 0xFFFF
        value &= 0xFF
        dict.__setitem__(self, addr, value)
        self.flat[addr] = value
        if addr < 3:
            self.flat[self._MIRROR + addr] = value

    def __delitem__(self, addr) -> None:
        addr &= 0xFFFF
        dict.__delitem__(self, addr)
        self.flat[addr] = 0xFF
        if addr < 3:
            self.flat[self._MIRROR + addr] = 0xFF


class ROM:
    """A sparse 64 KiB code-space image.

    Unmapped bytes read back as 0xFF, exactly like an erased EPROM.  This is
    important: an erased 8051 executes ``MOV A,#0FFh`` (0x74 0xFF) forever,
    which is what a blank device actually does.
    """

    __slots__ = ("_mem", "name", "mapped", "flat")

    def __init__(self, name: str = "rom") -> None:
        self._mem = _Mapped()
        # Плоское представление: объект bytearray живёт всю жизнь ROM
        # (_Mapped никогда не подменяется), поэтому кэш ссылки безопасен и
        # снимает property-вызов на КАЖДОЙ инструкции (cpu._execute).
        self.flat = self._mem.flat
        self.name = name

    # ------------------------------------------------------------------ build
    def load_block(self, base: int, data: bytes) -> None:
        for i, b in enumerate(data):
            addr = (base + i) & 0xFFFF
            self._mem[addr] = b
        self.mapped = len(self._mem)

    def load_file(self, path: str) -> "ROM":
        """Load ``.hex`` (Intel HEX) or ``.bin``/``.rom`` (raw at base 0)."""
        ext = os.path.splitext(path)[1].lower()
        with open(path, "rb") as fh:
            raw = fh.read()
        if ext in (".hex", ".ihx", ".ihex"):
            # Intel HEX is ASCII but dumps often carry CRLF; latin-1 decodes
            # byte-for-byte and parse_intel_hex strips surrounding whitespace.
            self.load_hex_text(raw.decode("latin-1"))
        elif ext == ".bin":
            self.load_block(0x0000, raw)
        else:
            self.load_block(0x0000, raw)
        self.name = os.path.basename(path)
        return self

    def load_hex_text(self, text: str) -> "ROM":
        for addr, data in parse_intel_hex(text):
            self.load_block(addr, data)
        return self

    def stack(self, other: "ROM", only_gaps: bool = True) -> int:
        """Merge ``other`` into this image; return how many bytes were added.

        With ``only_gaps=True`` (the default) bytes already present here win,
        which is what you want when layering a full dump over a partial one.
        """
        added = 0
        mem = self._mem
        for addr, value in other._mem.items():
            if only_gaps and addr in mem:
                continue
            if addr not in mem:
                added += 1
            mem[addr] = value
        self.mapped = len(mem)
        return added

    def fill_range(self, start: int, end: int, value: int = 0xFF) -> None:
        """Fill ``[start, end]`` with a constant byte."""
        for addr in range(start, end + 1):
            self._mem[addr & 0xFFFF] = value & 0xFF
        self.mapped = len(self._mem)

    def unmapped_ranges(self) -> list:
        """Sorted list of ``(first, last)`` unmapped runs across 64 KiB."""
        gaps = []
        first = None
        for addr in range(0x10000):
            if addr not in self._mem:
                if first is None:
                    first = addr
            elif first is not None:
                gaps.append((first, addr - 1))
                first = None
        if first is not None:
            gaps.append((first, 0xFFFF))
        return gaps

    # ----------------------------------------------------------------- access
    # NB: ``flat`` — обычный атрибут, заданный в __init__ (а не property):
    # cpu._execute читает его на каждой инструкции, property стоила вызова на
    # каждый фетч; зеркало +3 байта см. в :class:`_Mapped`.

    def __getitem__(self, addr: int) -> int:
        return self._mem.flat[addr & 0xFFFF]

    def byte(self, addr: int) -> int:
        return self._mem.flat[addr & 0xFFFF]

    def word(self, addr: int) -> int:
        return self.byte(addr) << 8 | self.byte(addr + 1)

    def get_slice(self, start: int, length: int) -> bytes:
        # Один срез плоского представления вместо покадрового byte() на каждый
        # байт: get_slice зовётся сканерами MOVC десятками тысяч раз за бут
        # (cProfile: 32K вызовов, 0.27s только на генexpr).  Семантика та же:
        # адрес маскируется, несопоставленные байты читаются как 0xFF.
        flat = self._mem.flat
        start &= 0xFFFF
        end = start + int(length)
        if end <= 0x10000:
            return bytes(flat[start:end])
        return bytes(flat[start:0x10000]) + bytes(flat[0:end - 0x10000])

    def __len__(self) -> int:
        return len(self._mem)

    def coverage(self) -> Optional[Tuple[int, int]]:
        if not self._mem:
            return None
        keys = self._mem.keys()
        return (min(keys), max(keys))

    def is_mapped(self, addr: int) -> bool:
        return (addr & 0xFFFF) in self._mem


def parse_intel_hex(text: str) -> Iterable[Tuple[int, bytes]]:
    """Yield ``(address, data)`` records from Intel HEX text.

    Extended-address (type 04) and extended-linear (type 05) records are
    honoured; type 01 ends the file.  Bad checksums raise ``ValueError``.
    """
    base = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or not line.startswith(":"):
            continue
        try:
            raw = bytes.fromhex(line[1:])
        except ValueError as exc:
            raise ValueError(f"line {lineno}: bad hex digits: {line!r}") from exc
        if len(raw) < 5:
            raise ValueError(f"line {lineno}: record too short")
        if sum(raw) & 0xFF:
            raise ValueError(
                f"line {lineno}: bad checksum (sum=0x{sum(raw) & 0xFF:02X})"
            )
        count, addr, rtype = raw[0], (raw[1] << 8) | raw[2], raw[3]
        data = raw[4 : 4 + count]
        if len(data) != count or len(raw) != count + 5:
            raise ValueError(f"line {lineno}: truncated data")
        if rtype == 0x00:
            yield (base + addr) & 0xFFFF, bytes(data)
        elif rtype == 0x01:
            return
        elif rtype == 0x04:
            base = ((data[0] << 8) | data[1]) << 16
        elif rtype == 0x05:
            base = ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) << 16
        # 02/03 (segment) records are ignored: they do not occur in 8051 images.


def load_intel_hex(path: str, name: str = "") -> ROM:
    """Convenience helper: build a :class:`ROM` from an Intel HEX file."""
    rom = ROM(name or os.path.basename(path))
    return rom.load_file(path)
