"""Exception types shared by the recovery runtime."""

from __future__ import annotations

__all__ = ["MissingFirmware", "XdataUnmapped", "BadDecompilation", "UnmappedRegister"]


class MissingFirmware(RuntimeError):
    """Raised when recovered code needs a location that no dump covers.

    The decompiler invented plausible-looking code wherever it had no bytes
    to disassemble (addresses below record ``0x8000`` in the dump), so
    executing those paths would produce fiction.  Instead of
    returning fabricated values, the runtime raises this: the caller (a test,
    the UI, or a HAL hook) can then decide whether to supply the routine or
    report the gap.

    ``addr`` may be negative when the gap is *named* but has no address at all
    (a goto to a label no function defines, a register the dump declares but
    never locates).  The message then says what is missing without inventing a
    hexadecimal address.
    """

    def __init__(self, addr: int, what: str = "code") -> None:
        self.addr = addr
        self.what = what
        if addr < 0:
            super().__init__(f"missing firmware ({what})")
        else:
            super().__init__(
                f"missing firmware at 0x{addr:04X} ({what}): this address is not "
                f"covered by any dump, only by decompiler guesswork"
            )


class UnmappedRegister(MissingFirmware):
    """A global the dump *declares* but whose address the dump never states.

    ``undefined1 RXSTAT;`` is a real declaration from Ghidra, but the dump says
    nothing about where ``RXSTAT`` lives (internal RAM, an SFR, external
    memory).  Binding it to a plausible address would be invention, so reading
    or writing it reports this instead - the caller sees both the symbol name
    and the fact that only the decompiler's symbol table knows it.
    """

    def __init__(self, name: str, where: str = "") -> None:
        self.name = name
        self.where = where
        detail = (
            f"symbol {name!r} is declared in the dump but the dump never states "
            f"where it lives"
        )
        if where:
            detail += f" (declared as {where})"
        super().__init__(-1, detail)


class XdataUnmapped(RuntimeError):
    """Raised on access to external memory that nothing handles."""

    def __init__(self, addr: int, write: bool = False, value: int = 0) -> None:
        self.addr = addr
        self.write = write
        self.value = value
        op = "write" if write else "read"
        super().__init__(f"unmapped external memory {op} at 0x{addr:04X}")


class BadDecompilation(SyntaxError):
    """Raised when a pseudo-C construct cannot be translated."""
