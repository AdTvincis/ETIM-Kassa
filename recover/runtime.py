"""Helpers the recovered code calls.

The decompiler emits a handful of pseudo-functions that do not exist in C:
``CONCAT11``, ``SUB41``, ``ZEXT14``, ``__PAIR__`` and friends.  They are pure
bit arithmetic and are reproduced here exactly as Ghidra defines them.

It also emits free-standing gotos into the middle of other functions
(``goto LAB_CODE_ee3f;`` when ``LAB_CODE_ee3f`` is not a label of the current
function) and calls to ``func_0x1234`` for addresses it could not resolve.
Both are handled at runtime rather than guessed at translation time.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

__all__ = [
    "concat",
    "SUB41",
    "SUB42",
    "ZEXT14",
    "ZEXT24",
    "SEXT",
    "pair",
    "swap_bytes",
    "carry_of_add",
    "decimal_adjust",
    "RuntimeHelpers",
]


def _u(value, bits: int) -> int:
    return int(value) & ((1 << bits) - 1)


def concat(high, low, high_bits: int, low_bits: int) -> int:
    """``CONCAT`` of two values with the given bit widths."""
    return (_u(high, high_bits) << low_bits) | _u(low, low_bits)


def SUB41(value, shift: int = 0) -> int:
    """``SUB41(x, n)`` - take the low byte of ``x`` as seen from bit ``n``."""
    return _u(value, 8)


def SUB42(value, shift: int = 0) -> int:
    return _u(value, 16)


def ZEXT14(value) -> int:
    """Zero-extend a 4-bit value to 1 byte (Ghidra's ``ZEXT14``)."""
    return _u(value, 4)


def ZEXT24(value) -> int:
    return _u(value, 4)


def SEXT(value, bits: int) -> int:
    """Sign-extend the low ``bits`` of ``value`` to a Python int."""
    value = _u(value, bits)
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def pair(high, low) -> int:
    return ((int(high) & 0xFF) << 8) | (int(low) & 0xFF)


def swap_bytes(value) -> int:
    value = int(value) & 0xFFFF
    return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)


def carry_of_add(a: int, b: int) -> int:
    return 1 if (int(a) & 0xFF) + (int(b) & 0xFF) > 0xFF else 0


def decimal_adjust(value, *rest) -> int:
    """``decimal_adjust(x)`` - the 8051 ``DA`` (decimal adjust) on a byte.

    Ghidra emits a call to ``decimal_adjust`` wherever the processor model
    folded the BCD adjustment of an addition into one helper.  It takes the
    *value* only: the decompiler models the carry that ``DA`` produces with
    ``CARRY1(...)`` right next to the call (see e.g. ``FUN_CODE_f372``:
    ``cVar7 = decimal_adjust(param_1 + param_8);`` followed by a ``CARRY1``
    on the same operands), so this helper reads no flags and writes none - it
    is exactly the algorithm the instruction implements:

    1. if the low BCD digit is greater than 9, add 6;
    2. if the result exceeds ``0x99``, add ``0x60`` (the carry out of that
       addition is what the surrounding code takes with ``CARRY1``).

    Examples the algorithm must produce: ``0x9A -> 0x00`` (99+1 in BCD),
    ``0x55 -> 0x55`` (already valid), ``0x3A -> 0x40``.
    """
    v = int(value) & 0xFF
    if (v & 0x0F) > 9:
        v = (v + 0x06) & 0xFF
    if v > 0x99:
        v = (v + 0x60) & 0xFF
    return v


def _sext(bits: int):
    def impl(value, *rest):
        value = int(value) & ((1 << bits) - 1)
        sign = 1 << (bits - 1)
        return (value ^ sign) - sign
    return impl


class RuntimeHelpers:
    """The callable namespace generated code is executed against.

    It holds the functions recovered from the dump plus the hooks for anything
    the dump does not cover.  There is no ``__missing__`` protocol here: the
    lookup lives in :meth:`__getitem__` (with :meth:`get` as the tolerant
    wrapper) and resolves in a fixed order - recovered functions, then HAL
    hooks, then the decompiler's own names - so that

    * ``thunk_NAME`` strips its prefix and resolves ``NAME``;
    * ``func_0xNNNN`` is a *known* gap: it increments
      ``machine.missing_calls`` and returns ``0`` (it does **not** raise, so
      the half of the firmware that was never dumped keeps its call sites
      executable and countable);
    * anything else is recorded in :attr:`unresolved` and raises ``KeyError``
      with the exact identifier, instead of a bare ``NameError``.
    """

    def __init__(self, machine, loader: Optional[Callable[[int], None]] = None) -> None:
        self.machine = machine
        self.functions: Dict[str, Callable] = {}
        self.by_address: Dict[int, str] = {}
        self.loader = loader
        self.unresolved: Dict[str, int] = {}
        #: hooks installed by the HAL: name -> callable
        self.hooks: Dict[str, Callable] = {}
        self.install_decompiler_helpers()

    # ------------------------------------------------- decompiler intrinsics
    def install_decompiler_helpers(self) -> None:
        """Register Ghidra's pseudo-functions so recovered code can call them.

        These are pure bit arithmetic, defined by the decompiler, and they occur
        hundreds of times (``ZEXT12`` alone appears 239 times), so they must be
        available under their own names.
        """
        import re as _re

        def zext(width: int):
            def impl(value, *rest):
                return int(value) & ((1 << width) - 1)
            return impl

        def sub(width: int, bits: int):
            def impl(value, shift=0):
                return (int(value) >> int(shift)) & ((1 << bits) - 1)
            return impl

        for bits in range(1, 17):
            self.functions[f"ZEXT1{bits}" if bits < 10 else f"ZEXT{bits}"] = zext(bits)
        for bits in range(1, 17):
            self.functions.setdefault(f"ZEXT{bits}", zext(bits))
            self.functions[f"SEXT{bits}"] = _sext(bits)
        for out_bits in (1, 2, 4):
            for in_bits in range(1, 9):
                self.functions[f"SUB{out_bits}{in_bits}"] = sub(out_bits, in_bits)
        for out_bits in (1, 2, 4):
            for in_bits in range(1, 9):
                self.functions.setdefault(f"SUB{out_bits}{in_bits}", sub(out_bits, in_bits))

        def concat_impl(high_bits: int, low_bits: int):
            def impl(high, low, high2=None, low2=None):
                if high2 is None:
                    return ((int(high) & ((1 << high_bits) - 1)) << low_bits) | (
                        int(low) & ((1 << low_bits) - 1)
                    )
                return (
                    ((int(high) & ((1 << high_bits) - 1)) << low_bits)
                    | (int(low) & ((1 << low_bits) - 1))
                )
            return impl

        for high_bits in (1, 2, 4):
            for low_bits in (1, 2, 4, 8):
                self.functions.setdefault(
                    f"CONCAT{high_bits}{low_bits}", concat_impl(high_bits, low_bits)
                )
        self.functions["CONCAT11"] = concat_impl(1, 1)
        self.functions["CONCAT12"] = concat_impl(1, 2)
        self.functions["CONCAT13"] = concat_impl(1, 3)
        self.functions["CONCAT14"] = concat_impl(1, 4)
        self.functions["CONCAT21"] = concat_impl(2, 1)
        self.functions["CONCAT22"] = concat_impl(2, 2)
        self.functions["CONCAT31"] = concat_impl(3, 1)
        self.functions["CONCAT41"] = concat_impl(4, 1)
        self.functions["CONCAT44"] = concat_impl(4, 4)

        # Ghidra emits these when it loses track of the code
        def halt_baddata(*_args):
            return 0

        def nop(*_args):
            return 0

        self.functions["halt_baddata"] = halt_baddata
        self.functions["nop"] = nop
        self.functions["__halt"] = halt_baddata

        # ``CARRY1(a, b)`` is Ghidra's name for "does a + b carry out of bit 7".
        # It appears wherever the decompiler could not fold an add's carry.
        def carry1(a, b, _c=None):
            return 1 if (int(a) & 0xFF) + (int(b) & 0xFF) > 0xFF else 0

        def carry2(a, b, _c=None):
            return 1 if (int(a) & 0xFFFF) + (int(b) & 0xFFFF) > 0xFFFF else 0

        def borrow1(a, b, _c=None):
            return 1 if (int(a) & 0xFF) < (int(b) & 0xFF) else 0

        self.functions["CARRY1"] = carry1
        self.functions["CARRY2"] = carry2
        self.functions["BORROW1"] = borrow1

        # Ghidra's BCD helper (the 8051 ``DA`` instruction), pure: see
        # :func:`recover.runtime.decimal_adjust`.
        self.functions["decimal_adjust"] = decimal_adjust
        self.functions["decimaladjust"] = decimal_adjust

    # ------------------------------------------------------------- registration
    def register(self, name: str, func: Callable, address: Optional[int] = None) -> None:
        self.functions[name] = func
        if address is not None:
            self.by_address[address] = name

    def hook(self, name: str, func: Callable) -> None:
        self.hooks[name] = func

    # ------------------------------------------------------------------ lookup
    def __getitem__(self, name: str) -> Callable:
        try:
            return self.functions[name]
        except KeyError:
            pass
        if name in self.hooks:
            return self.hooks[name]
        if name.startswith("func_0x"):
            # The *stub* returned here increments machine.missing_calls when it
            # is called.  Counting at lookup time as well made every call count
            # twice (``get()`` + call), inflating the honest gap report.
            return self._missing(name, int(name[7:], 16))
        if name.startswith("thunk_"):
            return self[name[len("thunk_"):]]
        self.unresolved[name] = self.unresolved.get(name, 0) + 1
        raise KeyError(
            f"recovered code calls '{name}', which is not defined anywhere in the dump"
        )

    def get(self, name: str, default=None):
        try:
            return self[name]
        except KeyError:
            return default

    def _missing(self, name: str, addr: int) -> Callable:
        def stub(*args):
            self.machine.missing_calls[name] = self.machine.missing_calls.get(name, 0) + 1
            return 0

        stub.__name__ = name
        return stub

    # ------------------------------------------------------------------- calls
    def call(self, name: str, *args):
        """Invoke a recovered function by name."""
        return self[name](*args)

    def stats(self) -> Dict[str, int]:
        return {
            "functions": len(self.functions),
            "unresolved": len(self.unresolved),
            "missing_calls": sum(self.machine.missing_calls.values()),
        }
