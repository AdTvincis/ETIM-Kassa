# -*- coding: utf-8 -*-
"""``tools/asm51.py`` -- a small two-pass MCS-51 (8051) assembler.

Why it exists
-------------
The real cash-register firmware (``firmware/nm27c512n.hex``) is incomplete:
its reset vector ``LJMP 0x0A06`` points into ``0x0000..0x7FFF``, the half of
the ROM that was never dumped.  To give the emulator and the emulated board a
program that actually runs, ``firmware/demo/cashier.asm`` is a *stand-in*
(демонстрационная программа) written in this assembler's syntax.

The assembler is deliberately small but honest: it hand-encodes every opcode it
supports and then **cross-checks each encoding by disassembling it again** with
:func:`tools.disasm.disassemble_one` (see :func:`selftest` and the
``--selftest`` command line switch).  Nothing is emitted that the emulator's own
disassembler does not read back as the instruction that was written.

Syntax
------
::

    ; comment  (everything after ';' outside quotes is ignored)
    LABEL:  MOV   A,#5        ; labels need a colon...
    COUNT   EQU   20          ; ...except on EQU lines
            ORG   0x0000
            CHARSET koi8-r    ; codec for string/char literals (default koi8-r)
            DB    1, 2, "OK", 0
            DW    0x1234, TABLE
            END

Operands
--------
``A``, ``B``, ``C``, ``AB``, ``DPTR``, ``R0``..``R7``, ``@R0``, ``@R1``,
``@DPTR``, ``@A+DPTR``, ``@A+PC``, ``#expr`` (immediate), direct addresses
(``30h``, ``0x30``, ``NAME``), bit addresses (``CY``, ``ACC.3``, ``20h.1``,
``0xD7``) and code labels for the branch/call instructions.

Expressions
-----------
``+ - * / % & | ^ ~ << >>``, parentheses, ``$`` (address of the current
instruction), ``LOW(x)``, ``HIGH(x)``, character literals (``'A'``), and the
radixes ``123`` (decimal), ``0x7B``/``7Bh`` (hex), ``1010b``/``0b1010``
(binary).  All names are case-insensitive; the returned symbol table uses
upper-case keys.  Built-in names are the SFRs and bit names known to
:mod:`tools.disasm`.

Public API
----------
``assemble(source: str, ...) -> AssemblyResult``
``assemble_file(path, ...) -> AssemblyResult``
``AssemblyResult.image``      - ``bytes`` for ``[base, end)`` (gaps = 0xFF)
``AssemblyResult.symbols``    - ``{NAME: value}`` for labels and EQU
``AssemblyResult.blocks``     - ``[(address, bytes), ...]`` contiguous runs
``AssemblyResult.intel_hex()``- Intel HEX text (what ``firmware/demo`` writes)
``selftest()``                - assemble -> disassemble -> verify every opcode
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# The assembler lives in tools/ but imports its sibling disassembler through the
# package, so make the project root importable when run as a script.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.disasm import BIT_NAMES, SFR_NAMES, disassemble_one  # noqa: E402

__all__ = [
    "AsmError",
    "AssemblyResult",
    "ListingEntry",
    "assemble",
    "assemble_file",
    "intel_hex",
    "selftest",
    "ENC",
    "DEFAULT_CHARSET",
]

DEFAULT_CHARSET = "koi8-r"
"""String literals are stored as KOI8-R by default.

The real firmware keeps its Russian text in KOI8-R: ``docs/rom_strings.txt``
shows ``spasibo!``/``nali~nye``/``sda~a``, i.e. KOI8-R bytes read as latin-1.
The stand-in program follows the same convention so its receipt text matches
the wording of the machine it replaces.
"""


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------
class AsmError(Exception):
    """Any assembly-time error; carries the source line number."""

    def __init__(self, message: str, line_no: Optional[int] = None, text: str = "") -> None:
        self.message = message
        self.line_no = line_no
        self.text = text
        where = f"line {line_no}: " if line_no else ""
        detail = f"  [{text.strip()}]" if text.strip() else ""
        super().__init__(f"{where}{message}{detail}")


# ---------------------------------------------------------------------------
# built-in names (SFRs and bits, taken from the emulator's own tables)
# ---------------------------------------------------------------------------
def _build_builtin_names() -> Tuple[Dict[str, int], Dict[str, int]]:
    direct = {name.upper(): addr for addr, name in SFR_NAMES.items()}
    bits = {name.upper(): addr for addr, name in BIT_NAMES.items()}
    # SFRs that the disassembler prefers to spell as raw numbers in _dir() but
    # which every 8051 programmer expects to be able to write by name.
    direct.update({"ACC": 0xE0, "B": 0xF0, "PSW": 0xD0, "SP": 0x81,
                   "DPL": 0x82, "DPH": 0x83, "P0": 0x80, "P1": 0x90,
                   "P2": 0xA0, "P3": 0xB0})
    # Commonly used P3 pin names (not in BIT_NAMES, they are plain port bits).
    bits.update({"RXD": 0xB0, "TXD": 0xB1, "INT0": 0xB2, "INT1": 0xB3,
                 "T0": 0xB4, "T1": 0xB5, "WR": 0xB6, "RD": 0xB7})
    return direct, bits


BUILTIN_DIRECT, BUILTIN_BITS = _build_builtin_names()


# ---------------------------------------------------------------------------
# expressions
# ---------------------------------------------------------------------------
_NUM_RE = re.compile(
    r"""
      0[xX][0-9A-Fa-f]+
    | 0[bB][01]+
    | [0-9][0-9A-Fa-f]*[hH]
    | [0-9]+[bB]
    | [0-9]+
    """,
    re.X,
)
_NAME_RE = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$]*")
_CHAR_RE = re.compile(r"'(?:\\.|[^'\\])*'")
_OP_RE = re.compile(r"<<|>>|[-+*/%&|^~()]")
_TOKEN_RE = re.compile(
    f"(?P<num>{_NUM_RE.pattern})|(?P<char>{_CHAR_RE.pattern})"
    f"|(?P<name>{_NAME_RE.pattern})|(?P<op>{_OP_RE.pattern})",
    re.X,
)

_PREC = {"|": 1, "^": 2, "&": 3, "<<": 4, ">>": 4,
         "+": 5, "-": 5, "*": 6, "/": 6, "%": 6}

# An expression is a small AST of tuples, evaluated later against a resolver.
Expr = tuple


def _unescape(text: str) -> str:
    out: List[str] = []
    i = 0
    simple = {"n": "\n", "r": "\r", "t": "\t", "0": "\0",
              "\\": "\\", "'": "'", '"': '"', "a": "\a", "b": "\b",
              "f": "\f", "v": "\v"}
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt == "x" and i + 3 < len(text) + 1:
                hexpart = text[i + 2:i + 4]
                try:
                    out.append(chr(int(hexpart, 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            raise AsmError(f"bad escape sequence '\\{nxt}' in {text!r}")
        out.append(ch)
        i += 1
    return "".join(out)


def string_bytes(text: str, charset: str, line_no: Optional[int] = None) -> bytes:
    """Encode a source string literal with ``charset`` (KOI8-R by default)."""
    try:
        data = _unescape(text).encode(charset)
    except UnicodeEncodeError as exc:
        raise AsmError(
            f"string {text!r} cannot be encoded as {charset}: {exc}", line_no
        ) from exc
    except LookupError as exc:
        raise AsmError(f"unknown CHARSET {charset!r}", line_no) from exc
    return data


def _decode_number(tok: str) -> int:
    low = tok.lower()
    if low.startswith("0x"):
        return int(low, 16)
    if low.startswith("0b") and set(low[2:]) <= set("01"):
        return int(low[2:], 2)
    if low.endswith("h"):
        return int(low[:-1], 16)
    if low.endswith("b") and set(low[:-1]) <= set("01") and low[:-1]:
        return int(low[:-1], 2)
    return int(low, 10)


def _tokenize(text: str, line_no: Optional[int] = None) -> List[Tuple[str, str]]:
    tokens: List[Tuple[str, str]] = []
    i = 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        m = _TOKEN_RE.match(text, i)
        if not m:
            raise AsmError(f"cannot tokenise {text[i:]!r}", line_no, text)
        kind = m.lastgroup or "op"
        tokens.append((kind, m.group(0)))
        i = m.end()
    return tokens


def parse_expr(text: str, line_no: Optional[int] = None) -> Expr:
    """Parse ``text`` into an evaluatable expression AST."""
    tokens = _tokenize(text, line_no)
    if not tokens:
        raise AsmError("empty expression", line_no, text)
    ast, pos = _parse_binary(tokens, 0, 0, line_no, text)
    if pos != len(tokens):
        raise AsmError(f"unexpected {tokens[pos][1]!r} in expression", line_no, text)
    return ast


def _parse_binary(tokens, pos, min_prec, line_no, text):
    left, pos = _parse_unary(tokens, pos, line_no, text)
    while pos < len(tokens):
        kind, tok = tokens[pos]
        if kind != "op" or tok not in _PREC or _PREC[tok] < min_prec:
            break
        pos += 1
        right, pos = _parse_binary(tokens, pos, _PREC[tok] + 1, line_no, text)
        left = ("bin", tok, left, right)
    return left, pos


def _parse_unary(tokens, pos, line_no, text):
    if pos >= len(tokens):
        raise AsmError("expression ends unexpectedly", line_no, text)
    kind, tok = tokens[pos]
    if kind == "op" and tok in ("-", "+", "~"):
        operand, pos = _parse_unary(tokens, pos + 1, line_no, text)
        return ("un", tok, operand), pos
    if kind == "op" and tok == "(":
        inner, pos = _parse_binary(tokens, pos + 1, 0, line_no, text)
        if pos >= len(tokens) or tokens[pos] != ("op", ")"):
            raise AsmError("missing ')' in expression", line_no, text)
        return inner, pos + 1
    if kind == "num":
        return ("num", _decode_number(tok)), pos + 1
    if kind == "char":
        return ("char", tok[1:-1]), pos + 1
    if kind == "name":
        name = tok.upper()
        if name in ("LOW", "HIGH") and pos + 1 < len(tokens) and tokens[pos + 1] == ("op", "("):
            inner, pos = _parse_binary(tokens, pos + 2, 0, line_no, text)
            if pos >= len(tokens) or tokens[pos] != ("op", ")"):
                raise AsmError(f"missing ')' after {name}(", line_no, text)
            return (name.lower(), inner), pos + 1
        return ("sym", name), pos + 1
    raise AsmError(f"unexpected {tok!r} in expression", line_no, text)


def eval_expr(ast: Expr, resolver: Callable[[str], int], charset: str) -> int:
    """Evaluate an AST; ``resolver(name)`` maps a symbol to its value."""
    kind = ast[0]
    if kind == "num":
        return ast[1]
    if kind == "char":
        data = string_bytes(ast[1], charset)
        if len(data) != 1:
            raise AsmError(f"character literal {ast[1]!r} is not one byte in {charset}")
        return data[0]
    if kind == "sym":
        return resolver(ast[1])
    if kind == "un":
        op, operand = ast[1], ast[2]
        value = eval_expr(operand, resolver, charset)
        if op == "-":
            return -value
        if op == "+":
            return value
        return ~value
    if kind == "bin":
        op, left, right = ast[1], ast[2], ast[3]
        a = eval_expr(left, resolver, charset)
        b = eval_expr(right, resolver, charset)
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op == "/":
            if b == 0:
                raise AsmError("division by zero in expression")
            return a // b
        if op == "%":
            if b == 0:
                raise AsmError("modulo by zero in expression")
            return a % b
        if op == "&":
            return a & b
        if op == "|":
            return a | b
        if op == "^":
            return a ^ b
        if op == "<<":
            return a << b
        if op == ">>":
            return a >> b
        raise AsmError(f"unknown operator {op!r}")
    if kind == "low":
        return eval_expr(ast[1], resolver, charset) & 0xFF
    if kind == "high":
        return (eval_expr(ast[1], resolver, charset) >> 8) & 0xFF
    raise AsmError(f"bad expression node {ast!r}")


# ---------------------------------------------------------------------------
# operands
# ---------------------------------------------------------------------------
_BITNAME_RE = re.compile(
    r"^(?P<base>[A-Za-z_][A-Za-z0-9_]*|0X[0-9A-Fa-f]+|[0-9]+H|[0-9]+)"
    r"\s*\.\s*(?P<bit>[0-7])$"
)


@dataclass
class Operand:
    """One parsed operand.

    ``kind`` is the *syntactic* kind: ``A``, ``B``, ``C``, ``AB``, ``DPTR``,
    ``R``/``@R`` (with ``rn``), ``@DPTR``, ``@A+DPTR``, ``@A+PC``, ``IMM``,
    ``BIT`` (``base``/``bitno``) or ``EXPR`` (direct/bit/rel -- decided by the
    instruction pattern).

    ``neg`` marks the ``/bit`` operand of ``ANL/ORL C,/bit``.  The slash does
    not change the bit address - it selects a *different opcode*
    (``0xB0``/``0xA0`` instead of ``0x82``/``0x72``).
    """

    kind: str
    text: str
    expr: Optional[Expr] = None
    rn: Optional[int] = None
    base: Optional[str] = None
    bitno: Optional[int] = None
    neg: bool = False


def parse_operand(text: str, line_no: Optional[int] = None) -> Operand:
    raw = text.strip()
    flat = re.sub(r"\s+", "", raw).upper()
    if not flat:
        raise AsmError("empty operand", line_no, text)
    if flat.startswith("#"):
        return Operand("IMM", raw, expr=parse_expr(raw[1:], line_no))
    if flat.startswith("/"):
        # ANL/ORL C,/bit: parse the remainder as an ordinary bit operand and
        # remember the complement - the '/' lives in the opcode, not here.
        inner = parse_operand(raw[1:], line_no)
        if inner.kind != "BIT":
            raise AsmError(
                f"'/' complements a bit address (20h.1, ACC.3, ...), "
                f"got {raw!r}", line_no, text)
        return Operand("BIT", raw, base=inner.base, bitno=inner.bitno, neg=True)
    if flat.startswith("@"):
        if flat in ("@R0", "@R1"):
            return Operand("@R", raw, rn=int(flat[2]))
        if flat == "@DPTR":
            return Operand("@DPTR", raw)
        if flat == "@A+DPTR":
            return Operand("@A+DPTR", raw)
        if flat == "@A+PC":
            return Operand("@A+PC", raw)
        raise AsmError(f"unknown indirect operand {raw!r}", line_no, text)
    if flat in ("A", "AB", "C", "B", "DPTR"):
        return Operand(flat, raw)
    if re.fullmatch(r"R[0-7]", flat):
        return Operand("R", raw, rn=int(flat[1]))
    m = _BITNAME_RE.match(flat)
    if m:
        return Operand("BIT", raw, base=m.group("base"), bitno=int(m.group("bit")))
    return Operand("EXPR", raw, expr=parse_expr(raw, line_no))


# ---------------------------------------------------------------------------
# instruction encoding table
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Enc:
    """``opcode`` plus how to finish the instruction.

    ``mod``: ``''`` | ``'n'`` (add Rn to the opcode) | ``'ri'`` (add the
    ``@R0``/``@R1`` number) | ``'p'`` (fold in the AJMP/ACALL page bits).
    ``plan``: emitted bytes, one token each (``imm16``/``addr16`` are two):
    ``imm8 imm16 dir bit rel addr16 page o0 o1``.
    """

    opcode: int
    mod: str = ""
    plan: Tuple[str, ...] = ()

    @property
    def size(self) -> int:
        return 1 + sum(2 if t in ("imm16", "addr16") else 1 for t in self.plan)


# Patterns use operand roles:
#   A B C AB DPTR Rn @Ri @DPTR @A+DPTR @A+PC  - literal token
#   #i  - immediate
#   D   - direct address expression
#   T   - bit address expression
#   S   - short relative code label
#   L   - 16-bit code label
#   P   - page-relative code label (AJMP/ACALL)
ENC: Dict[str, List[Tuple[Tuple[str, ...], Enc]]] = {}


def _add(mnem: str, pattern: Sequence[str], opcode: int,
         mod: str = "", plan: Sequence[str] = ()) -> None:
    ENC.setdefault(mnem, []).append((tuple(pattern), Enc(opcode, mod, tuple(plan))))


# --- no operands -----------------------------------------------------------
_add("NOP", (), 0x00)
_add("RET", (), 0x22)
_add("RETI", (), 0x32)
_add("MUL", ("AB",), 0xA4)
_add("DIV", ("AB",), 0x84)
_add("DA", ("A",), 0xD4)
_add("RL", ("A",), 0x23)
_add("RR", ("A",), 0x03)
_add("RLC", ("A",), 0x33)
_add("RRC", ("A",), 0x13)
_add("SWAP", ("A",), 0xC4)
_add("CLR", ("A",), 0xE4)
_add("CPL", ("A",), 0xF4)
_add("CLR", ("C",), 0xC3)
_add("CPL", ("C",), 0xB3)
_add("SETB", ("C",), 0xD3)
_add("CLR", ("T",), 0xC2, "", ("bit",))
_add("CPL", ("T",), 0xB2, "", ("bit",))
_add("SETB", ("T",), 0xD2, "", ("bit",))

# --- MOV -------------------------------------------------------------------
_add("MOV", ("A", "#i"), 0x74, "", ("imm8",))
_add("MOV", ("A", "D"), 0xE5, "", ("dir",))
_add("MOV", ("A", "@Ri"), 0xE6, "ri")
_add("MOV", ("A", "Rn"), 0xE8, "n")
_add("MOV", ("Rn", "A"), 0xF8, "n")
_add("MOV", ("Rn", "#i"), 0x78, "n", ("imm8",))
_add("MOV", ("Rn", "D"), 0xA8, "n", ("dir",))
_add("MOV", ("D", "A"), 0xF5, "", ("dir",))
_add("MOV", ("D", "#i"), 0x75, "", ("dir", "imm8"))
_add("MOV", ("D", "Rn"), 0x88, "n", ("dir",))
_add("MOV", ("D", "D"), 0x85, "", ("o1", "o0"))
_add("MOV", ("D", "@Ri"), 0x86, "ri", ("dir",))
_add("MOV", ("@Ri", "A"), 0xF6, "ri")
_add("MOV", ("@Ri", "#i"), 0x76, "ri", ("imm8",))
_add("MOV", ("@Ri", "D"), 0xA6, "ri", ("dir",))
_add("MOV", ("DPTR", "#i"), 0x90, "", ("imm16",))
_add("MOV", ("C", "T"), 0xA2, "", ("bit",))
_add("MOV", ("T", "C"), 0x92, "", ("bit",))

# --- MOVX / MOVC -----------------------------------------------------------
_add("MOVX", ("A", "@DPTR"), 0xE0)
_add("MOVX", ("A", "@Ri"), 0xE2, "ri")
_add("MOVX", ("@DPTR", "A"), 0xF0)
_add("MOVX", ("@Ri", "A"), 0xF2, "ri")
_add("MOVC", ("A", "@A+DPTR"), 0x93)
_add("MOVC", ("A", "@A+PC"), 0x83)

# --- ADD / ADDC / SUBB -----------------------------------------------------
for _m, _b in (("ADD", 0x20), ("ADDC", 0x30), ("SUBB", 0x90)):
    _add(_m, ("A", "#i"), _b + 4, "", ("imm8",))
    _add(_m, ("A", "D"), _b + 5, "", ("dir",))
    _add(_m, ("A", "@Ri"), _b + 6, "ri")
    _add(_m, ("A", "Rn"), _b + 8, "n")

# --- INC / DEC -------------------------------------------------------------
_add("INC", ("A",), 0x04)
_add("INC", ("D",), 0x05, "", ("dir",))
_add("INC", ("@Ri",), 0x06, "ri")
_add("INC", ("Rn",), 0x08, "n")
_add("INC", ("DPTR",), 0xA3)
_add("DEC", ("A",), 0x14)
_add("DEC", ("D",), 0x15, "", ("dir",))
_add("DEC", ("@Ri",), 0x16, "ri")
_add("DEC", ("Rn",), 0x18, "n")

# --- ANL / ORL / XRL -------------------------------------------------------
for _m, _b in (("ANL", 0x50), ("ORL", 0x40), ("XRL", 0x60)):
    _add(_m, ("A", "#i"), _b + 4, "", ("imm8",))
    _add(_m, ("A", "D"), _b + 5, "", ("dir",))
    _add(_m, ("A", "@Ri"), _b + 6, "ri")
    _add(_m, ("A", "Rn"), _b + 8, "n")
    _add(_m, ("D", "A"), _b + 2, "", ("dir",))
    _add(_m, ("D", "#i"), _b + 3, "", ("dir", "imm8"))
# The carry forms exist only for ANL/ORL, and the complemented bit is a
# *different opcode*, which is why it needs its own pattern ("/T"):
#   ANL C,bit = 0x82   ANL C,/bit = 0xB0
#   ORL C,bit = 0x72   ORL C,/bit = 0xA0
# Without these four entries the assembler could not emit a quarter of the
# MCS-51 bit logic at all (and asm51.selftest never noticed, because it only
# checks that every ENC entry is *used*, not that the opcode map is covered).
_add("ANL", ("C", "T"), 0x82, "", ("bit",))
_add("ANL", ("C", "/T"), 0xB0, "", ("bit",))
_add("ORL", ("C", "T"), 0x72, "", ("bit",))
_add("ORL", ("C", "/T"), 0xA0, "", ("bit",))

# --- XCH / XCHD / stack ----------------------------------------------------
_add("XCH", ("A", "D"), 0xC5, "", ("dir",))
_add("XCH", ("A", "@Ri"), 0xC6, "ri")
_add("XCH", ("A", "Rn"), 0xC8, "n")
_add("XCHD", ("A", "@Ri"), 0xD6, "ri")
_add("PUSH", ("D",), 0xC0, "", ("dir",))
_add("POP", ("D",), 0xD0, "", ("dir",))

# --- branches and calls ----------------------------------------------------
_add("LJMP", ("L",), 0x02, "", ("addr16",))
_add("LCALL", ("L",), 0x12, "", ("addr16",))
_add("AJMP", ("P",), 0x01, "p", ("page",))
_add("ACALL", ("P",), 0x11, "p", ("page",))
_add("SJMP", ("S",), 0x80, "", ("rel",))
_add("JMP", ("@A+DPTR",), 0x73)             # PC <- DPTR + A
_add("JC", ("S",), 0x40, "", ("rel",))
_add("JNC", ("S",), 0x50, "", ("rel",))
_add("JZ", ("S",), 0x60, "", ("rel",))
_add("JNZ", ("S",), 0x70, "", ("rel",))
_add("JB", ("T", "S"), 0x20, "", ("bit", "rel"))
_add("JNB", ("T", "S"), 0x30, "", ("bit", "rel"))
_add("JBC", ("T", "S"), 0x10, "", ("bit", "rel"))
_add("CJNE", ("A", "#i", "S"), 0xB4, "", ("imm8", "rel"))
_add("CJNE", ("A", "D", "S"), 0xB5, "", ("dir", "rel"))
_add("CJNE", ("@Ri", "#i", "S"), 0xB6, "ri", ("imm8", "rel"))
_add("CJNE", ("Rn", "#i", "S"), 0xB8, "n", ("imm8", "rel"))
_add("DJNZ", ("Rn", "S"), 0xD8, "n", ("rel",))
_add("DJNZ", ("D", "S"), 0xD5, "", ("dir", "rel"))

DIRECTIVES = ("ORG", "EQU", "DB", "DW", "END", "CHARSET")


def _fits(parsed: Operand, want: str) -> bool:
    """Can a parsed operand play the role ``want`` of a table pattern?"""
    if want == "#i":
        return parsed.kind == "IMM"
    if want == "Rn":
        return parsed.kind == "R"
    if want == "@Ri":
        return parsed.kind == "@R"
    if want == "D":
        if parsed.kind == "D":
            return True
        if parsed.kind == "EXPR":
            return True
        return parsed.kind == "B"          # 'B' means the SFR at 0xF0
    if want == "/T":
        # ANL/ORL C,/bit - only a bit operand that was written with a
        # leading '/'; a plain bit address must not match it (and vice
        # versa), otherwise the two encodings become ambiguous.
        return parsed.kind == "BIT" and parsed.neg
    if want in ("T", "S", "L", "P"):
        if parsed.kind == "EXPR":
            return True
        if want != "T":
            return False
        return parsed.kind == "BIT" and not parsed.neg
    return parsed.kind == want


def _match(mnem: str, ops: Sequence[Operand], line_no: Optional[int] = None,
           text: str = "") -> Tuple[Tuple[str, ...], Enc]:
    entries = ENC.get(mnem)
    if entries is None:
        raise AsmError(f"unknown mnemonic {mnem!r}", line_no, text)
    hits = [(p, e) for p, e in entries
            if len(p) == len(ops) and all(_fits(o, w) for o, w in zip(ops, p))]
    if not hits:
        forms = ", ".join(" ".join(p) for p, _ in entries) or "(no operands)"
        raise AsmError(
            f"no encoding for {mnem} with {len(ops)} operand(s); known forms: {forms}",
            line_no, text,
        )
    if len(hits) > 1:
        forms = " / ".join(" ".join(p) for p, _ in hits)
        raise AsmError(f"ambiguous {mnem}: matches {forms}", line_no, text)
    return hits[0]


# ---------------------------------------------------------------------------
# source splitting helpers
# ---------------------------------------------------------------------------
def _strip_comment(text: str) -> str:
    out: List[str] = []
    quote: Optional[str] = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == ";":
            break
        else:
            out.append(ch)
        i += 1
    if quote:
        raise AsmError("unterminated string literal", None, text)
    return "".join(out)


def _split_top(text: str, sep: str = ",") -> List[str]:
    """Split on ``sep`` at nesting depth 0, respecting quotes and parentheses."""
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    quote: Optional[str] = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip() != ""]


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------
@dataclass
class ListingEntry:
    addr: int
    data: bytes
    source: str
    text: str = ""
    kind: str = "ins"          # "ins" for instructions, "data" for DB/DW

    def __str__(self) -> str:  # pragma: no cover - formatting only
        hexs = " ".join(f"{b:02X}" for b in self.data)
        return f"{self.addr:04X}  {hexs:<14}  {self.source}"


@dataclass
class AssemblyResult:
    image: bytes
    base: int
    end: int
    symbols: Dict[str, int]
    listing: List[ListingEntry] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    blocks: List[Tuple[int, bytes]] = field(default_factory=list)
    encodings: List[Tuple[str, Tuple[str, ...]]] = field(default_factory=list)

    def symbol(self, name: str) -> int:
        return self.symbols[name.upper()]

    def intel_hex(self) -> str:
        return intel_hex(self.blocks)

    def hexdump(self) -> str:
        lines = []
        for addr, data in self.blocks:
            for off in range(0, len(data), 16):
                chunk = data[off:off + 16]
                hexs = " ".join(f"{b:02X}" for b in chunk)
                lines.append(f"{addr + off:04X}  {hexs}")
        return "\n".join(lines)


def intel_hex(blocks: Sequence[Tuple[int, bytes]], eol: str = "\n") -> str:
    """Render ``[(address, bytes), ...]`` as Intel HEX text."""
    out: List[str] = []
    for base, data in blocks:
        if base < 0 or base + len(data) > 0x10000:
            raise AsmError(f"block at 0x{base:04X} does not fit in 64 KiB")
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            addr = base + off
            rec = bytes((len(chunk), (addr >> 8) & 0xFF, addr & 0xFF, 0x00)) + chunk
            out.append(":" + (rec + bytes(((-sum(rec)) & 0xFF,))).hex().upper())
    out.append(":00000001FF")
    return eol.join(out) + eol


# ---------------------------------------------------------------------------
# the assembler itself
# ---------------------------------------------------------------------------
class Assembler:
    def __init__(self, org: int = 0, charset: str = DEFAULT_CHARSET,
                 filename: str = "<string>") -> None:
        self.org = org
        self.charset = charset
        self.filename = filename
        self.symbols: Dict[str, int] = {}
        self.equs: Dict[str, Expr] = {}
        self.equ_lines: Dict[str, int] = {}
        self.mem: Dict[int, int] = {}
        self.items: List[Tuple] = []          # ('ins'|'data', ...)
        self.warnings: List[str] = []
        self.listing: List[ListingEntry] = []
        self.encodings: List[Tuple[str, Tuple[str, ...]]] = []
        self.line_no = 0
        self.end_seen = False

    # -- symbols ------------------------------------------------------------
    def _define_label(self, name: str, value: int, line_no: int, text: str) -> None:
        key = name.upper()
        if key in self.symbols and self.symbols[key] != value:
            raise AsmError(
                f"symbol {key} redefined (0x{self.symbols[key]:04X} -> 0x{value:04X})",
                line_no, text,
            )
        self.symbols[key] = value

    def _resolver(self, pc: int) -> Callable[[str], int]:
        def resolve(name: str) -> int:
            key = name.upper()
            if key == "$":
                return pc
            if key in self.symbols:
                return self.symbols[key]
            if key in BUILTIN_DIRECT:
                return BUILTIN_DIRECT[key]
            if key in BUILTIN_BITS:
                return BUILTIN_BITS[key]
            # A hex literal whose first digit is a letter (FFh, A9h, C0h)
            # tokenises as a *name* - _NUM_RE demands a leading decimal
            # digit and _NAME_RE happily swallows the rest.  Known symbols
            # and SFR/bit names above always win, so the ambiguity is
            # resolved in favour of the symbol, and only an unknown all-hex
            # name ending in 'H' is read back as a number.  Without this no
            # operand printed by tools/disasm.py at >= 0xA0 survived a
            # round-trip ("MOV A,#FFh" -> undefined symbol 'FFH').
            #
            # NB: the check runs over key[:-1] - the trailing 'H' is the
            # radix marker, not a hex digit, and including it made the whole
            # condition always false.
            if (len(key) > 1 and key[-1] == "H" and key[0] in "ABCDEF"
                    and all(c in "0123456789ABCDEF" for c in key[:-1])):
                return int(key[:-1], 16)
            raise AsmError(f"undefined symbol {key!r}")
        return resolve

    def _eval(self, ast: Expr, pc: int = 0) -> int:
        return eval_expr(ast, self._resolver(pc), self.charset)

    def _try_eval(self, ast: Expr, pc: int = 0) -> Optional[int]:
        try:
            return self._eval(ast, pc)
        except AsmError:
            return None

    # -- pass 1 -------------------------------------------------------------
    def _pass1(self, source: str) -> int:
        pc = self.org
        for raw_line in source.splitlines():
            self.line_no += 1
            text = _strip_comment(raw_line)
            stripped = text.strip()
            if not stripped:
                continue
            label: Optional[str] = None
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:([\s\S]*)$", stripped)
            if m:
                label, stripped = m.group(1), m.group(2).strip()
            else:
                m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s+(?:EQU)\s+([\s\S]*)$",
                             stripped, re.I)
                if m:
                    label, stripped = m.group(1), "EQU " + m.group(2)
            if not stripped:
                if label:
                    self._define_label(label, pc, self.line_no, raw_line)
                continue
            parts = stripped.split(None, 1)
            op = parts[0].upper()
            args = parts[1].strip() if len(parts) > 1 else ""

            if op == "END":
                self.end_seen = True
                return pc
            if op == "ORG":
                value = self._eval(parse_expr(args, self.line_no), pc)
                if value < 0 or value > 0xFFFF:
                    raise AsmError(f"ORG 0x{value:X} outside 64 KiB", self.line_no, raw_line)
                pc = value
                continue
            if op == "CHARSET":
                name = args.strip().strip("\"'")
                try:
                    "".encode(name)
                except LookupError as exc:
                    raise AsmError(f"unknown CHARSET {name!r}", self.line_no, raw_line) from exc
                self.charset = name
                continue
            if op == "EQU":
                if not label:
                    raise AsmError("EQU needs a name", self.line_no, raw_line)
                ast = parse_expr(args, self.line_no)
                self.equs[label.upper()] = ast
                self.equ_lines[label.upper()] = self.line_no
                value = self._try_eval(ast, pc)
                if value is not None:
                    self.symbols[label.upper()] = value
                continue
            if op in ("DB", "DW"):
                if label:
                    self._define_label(label, pc, self.line_no, raw_line)
                size, value = self._data_size(op, args)
                self.items.append(("data", pc, op, args, size, raw_line))
                pc += size
                continue

            # ---- instruction
            if label:
                self._define_label(label, pc, self.line_no, raw_line)
            ops = [parse_operand(a, self.line_no) for a in _split_top(args)] if args else []
            pattern, enc = _match(op, ops, self.line_no, raw_line)
            self.items.append(("ins", pc, op, ops, pattern, enc, raw_line))
            self.encodings.append((op, pattern))
            pc += enc.size
        return pc

    def _data_size(self, op: str, args: str) -> Tuple[int, str]:
        items = _split_top(args)
        if not items:
            raise AsmError(f"{op} without data", self.line_no)
        size = 0
        for item in items:
            if item[0] in "\"'" and item[-1] == item[0] and len(item) >= 2:
                size += len(string_bytes(item[1:-1], self.charset, self.line_no))
            else:
                size += 1 if op == "DB" else 2
        return size, args

    # -- symbol resolution --------------------------------------------------
    def _resolve_symbols(self) -> None:
        pending = dict(self.equs)
        # A few iterations are enough: EQU chains are short, cycles error out.
        for _ in range(len(pending) + 2):
            if not pending:
                return
            progress = False
            for name in list(pending):
                value = self._try_eval(pending[name])
                if value is None:
                    continue
                self.symbols[name] = value
                del pending[name]
                progress = True
            if not progress:
                break
        if pending:
            names = ", ".join(sorted(pending))
            line = self.equ_lines.get(sorted(pending)[0])
            raise AsmError(f"cannot evaluate EQU: {names} (undefined or cyclic)", line)

    # -- pass 2 -------------------------------------------------------------
    def _pass2(self) -> None:
        for item in self.items:
            if item[0] == "ins":
                _, addr, mnem, ops, pattern, enc, src = item
                data = self._emit(addr, mnem, ops, pattern, enc)
                kind = "ins"
            else:
                _, addr, op, args, size, src = item
                data = self._emit_data(addr, op, args)
                kind = "data"
            for i, byte in enumerate(data):
                self.mem[(addr + i) & 0xFFFF] = byte & 0xFF
            text, _ = disassemble_one(self.mem_view(), addr)
            self.listing.append(
                ListingEntry(addr, bytes(data), src.strip(), text, kind))

    def mem_view(self):
        """A callable/dict-like byte view used by the disassembler."""
        return _MemView(self.mem)

    def _emit_data(self, addr: int, op: str, args: str) -> bytes:
        out = bytearray()
        for item in _split_top(args):
            if item[0] in "\"'" and item[-1] == item[0] and len(item) >= 2:
                out += string_bytes(item[1:-1], self.charset, self.line_no)
                continue
            value = self._eval(parse_expr(item, self.line_no), addr)
            if op == "DB":
                if not -128 <= value <= 0xFF:
                    self.warnings.append(
                        f"line {self.line_no}: DB value {value} truncated to "
                        f"0x{value & 0xFF:02X}")
                out.append(value & 0xFF)
            else:
                if not -32768 <= value <= 0xFFFF:
                    self.warnings.append(
                        f"line {self.line_no}: DW value {value} truncated to 16 bits")
                out.append((value >> 8) & 0xFF)
                out.append(value & 0xFF)
        return bytes(out)

    def _emit(self, addr: int, mnem: str, ops: Sequence[Operand],
              pattern: Tuple[str, ...], enc: Enc) -> bytes:
        resolve = self._resolver(addr)

        def operand_expr(op: Operand) -> int:
            assert op.expr is not None
            return eval_expr(op.expr, resolve, self.charset)

        def value_of(want: str) -> int:
            # Plan token "bit" asks for role "T"; the complemented patterns
            # (ANL/ORL C,/bit) spell that same role "/T".
            role = want if want in pattern else "/" + want
            idx = pattern.index(role)
            op = ops[idx]
            if want == "T" and op.kind == "BIT":
                base_op = Operand("EXPR", op.base,
                                  expr=parse_expr(op.base, self.line_no))
                base = operand_expr(base_op) if op.base else 0
                try:
                    return bit_address(base, op.bitno or 0) & 0xFF
                except AsmError as exc:
                    raise AsmError(str(exc.message), self.line_no, op.text) from exc
            if op.expr is None and op.kind == "B":
                return 0xF0
            return operand_expr(op)

        opcode = enc.opcode
        if enc.mod == "n":
            idx = pattern.index("Rn")
            opcode += ops[idx].rn or 0
        elif enc.mod == "ri":
            idx = pattern.index("@Ri")
            opcode += ops[idx].rn or 0
        elif enc.mod == "p":
            idx = pattern.index("P")
            target = operand_expr(ops[idx])
            after = addr + enc.size
            if (target & 0xF800) != (after & 0xF800):
                raise AsmError(
                    f"{mnem} target 0x{target:04X} is in another 2 KiB page "
                    f"than 0x{after:04X}", self.line_no)
            opcode |= ((target >> 8) & 0x07) << 5

        out = bytearray((opcode,))
        for token in enc.plan:
            if token == "imm8":
                value = value_of("#i")
                if not -128 <= value <= 0xFF:
                    self.warnings.append(
                        f"line {self.line_no}: {mnem} immediate {value} truncated to "
                        f"0x{value & 0xFF:02X} (use #LOW(x)/#HIGH(x) for addresses)")
                out.append(value & 0xFF)
            elif token == "imm16":
                value = value_of("#i")
                out.append((value >> 8) & 0xFF)
                out.append(value & 0xFF)
            elif token == "dir":
                out.append(value_of("D") & 0xFF)
            elif token == "bit":
                out.append(value_of("T") & 0xFF)
            elif token == "addr16":
                value = value_of("L")
                out.append((value >> 8) & 0xFF)
                out.append(value & 0xFF)
            elif token == "page":
                out.append(value_of("P") & 0xFF)
            elif token == "rel":
                target = value_of("S")
                after = addr + enc.size
                delta = target - after
                if not -128 <= delta <= 127:
                    raise AsmError(
                        f"{mnem} target 0x{target:04X} is {delta} bytes away; "
                        f"a relative jump reaches only -128..+127", self.line_no)
                out.append(delta & 0xFF)
            elif token in ("o0", "o1"):
                idx = int(token[1])
                out.append(operand_expr(ops[idx]) & 0xFF)
            else:  # pragma: no cover - table bug
                raise AsmError(f"internal: unknown plan token {token!r}")
        return bytes(out)

    # -- driver -------------------------------------------------------------
    def run(self, source: str) -> AssemblyResult:
        self._pass1(source)
        self._resolve_symbols()
        self._pass2()
        return self._result()

    def _result(self) -> AssemblyResult:
        if self.mem:
            base = min(self.mem)
            end = max(self.mem) + 1
            image = bytes(self.mem.get(a, 0xFF) for a in range(base, end))
        else:
            base = end = self.org
            image = b""
        blocks: List[Tuple[int, bytes]] = []
        for addr in sorted(self.mem):
            if blocks and blocks[-1][0] + len(blocks[-1][1]) == addr:
                blocks[-1] = (blocks[-1][0], blocks[-1][1] + bytes((self.mem[addr],)))
            else:
                blocks.append((addr, bytes((self.mem[addr],))))
        return AssemblyResult(
            image=image, base=base, end=end, symbols=dict(self.symbols),
            listing=self.listing, warnings=self.warnings, blocks=blocks,
            encodings=list(self.encodings),
        )


class _MemView:
    """Minimal read-only view of the emitted bytes for the disassembler."""

    __slots__ = ("_mem",)

    def __init__(self, mem: Dict[int, int]) -> None:
        self._mem = mem

    def __getitem__(self, addr: int) -> int:
        return self._mem.get(addr & 0xFFFF, 0xFF)


def assemble(source: str, *, org: int = 0, charset: str = DEFAULT_CHARSET,
             filename: str = "<string>") -> AssemblyResult:
    """Assemble ``source`` and return the image plus symbols and a listing."""
    return Assembler(org=org, charset=charset, filename=filename).run(source)


def assemble_file(path: str, *, org: int = 0,
                  charset: str = DEFAULT_CHARSET) -> AssemblyResult:
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    return assemble(source, org=org, charset=charset, filename=path)


# ---------------------------------------------------------------------------
# round-trip verification (used by --selftest and by the unit tests)
# ---------------------------------------------------------------------------
_LITERALS = ("A", "AB", "C", "B", "DPTR", "R0", "R1", "R2", "R3", "R4", "R5",
             "R6", "R7", "@R0", "@R1", "@DPTR", "@A+DPTR", "@A+PC")

_BIT_MNEMONICS = {"CLR", "CPL", "SETB", "JB", "JNB", "JBC"}
_ADDR_MNEMONICS = {"SJMP", "JC", "JNC", "JZ", "JNZ", "AJMP", "ACALL",
                   "LJMP", "LCALL"}


def _operand_roles(mnem: str, ops: Sequence[str]) -> List[str]:
    """Role of every operand of an instruction, from its *text* only.

    Roles: ``lit`` (register/indirect token), ``imm``, ``dir``, ``bit``,
    ``addr`` (code address), ``any``.
    """
    roles = ["any"] * len(ops)
    if mnem in _BIT_MNEMONICS:
        for i, op in enumerate(ops):
            up = op.upper()
            if up in ("A", "C"):
                roles[i] = "lit"
            else:
                roles[i] = "bit"
        if mnem in ("JB", "JNB", "JBC"):
            roles[-1] = "addr"
        return roles
    if mnem in _ADDR_MNEMONICS:
        return ["addr"] * len(ops)
    if mnem == "CJNE":
        if ops[-1].upper() not in _LITERALS:
            roles[-1] = "addr"
        for i in (0, 1):
            up = ops[i].upper()
            if up.startswith("#"):
                roles[i] = "imm"
            elif up in _LITERALS or up in ("R0", "R1"):
                roles[i] = "lit"
            else:
                roles[i] = "dir"
        return roles
    if mnem == "DJNZ":
        return ["dir", "addr"]
    for i, op in enumerate(ops):
        up = op.upper()
        if up.startswith("#"):
            roles[i] = "imm"
        elif up in _LITERALS:
            roles[i] = "lit"
        else:
            roles[i] = "dir"
    if mnem == "MOV" and ops and ops[0].upper() == "DPTR":
        roles[1] = "imm16"
    if mnem == "MOV" and len(ops) == 2 and ops[1].upper() == "C":
        roles[0] = "bit"
    if mnem == "MOV" and len(ops) == 2 and ops[0].upper() == "C":
        roles[1] = "bit"
    return roles


def bit_address(base: int, bitno: int) -> int:
    """Standard MCS-51 bit address for ``base`` (direct address) bit ``bitno``.

    ``0x20..0x2F`` are the bit-addressable RAM bytes (their bits are addressed
    ``0x00..0x7F``), everything at ``>= 0x80`` is an SFR whose bits start at the
    SFR's own address.  This mirrors :meth:`m8051.cpu.CPU8051._bit_addr`.
    """
    if 0x20 <= base <= 0x2F:
        return (base - 0x20) * 8 + bitno
    if base >= 0x80:
        return base + bitno
    raise AsmError(f"0x{base:02X} is not a bit-addressable location")


def _canon_operand(text: str, role: str, symbols: Dict[str, int]) -> Tuple:
    flat = re.sub(r"\s+", "", text).upper()
    if flat in _LITERALS:
        return (flat,)
    if role == "imm16":
        return ("imm16", _canon_number(flat.lstrip("#"), symbols, 0))
    if role == "imm" or flat.startswith("#"):
        return ("imm", _canon_number(flat.lstrip("#"), symbols, 0))
    if role == "addr":
        value = _canon_number(flat, symbols, 0)
        return ("addr", value) if value is not None else ("sym", flat)
    if role == "bit":
        m = _BITNAME_RE.match(flat)
        if m:
            base = _canon_number(m.group("base"), symbols, None)
            if base is not None:
                try:
                    value = bit_address(base, int(m.group("bit")))
                except AsmError:
                    value = base + int(m.group("bit"))
                return ("C",) if value == 0xD7 else ("bit", value)
        if flat in BUILTIN_BITS:
            value = BUILTIN_BITS[flat]
            return ("C",) if value == 0xD7 else ("bit", value)
        value = _canon_number(flat, symbols, None)
        if value is not None:
            return ("C",) if value == 0xD7 else ("bit", value)
        return ("sym", flat)
    # direct / any
    if flat in BUILTIN_DIRECT:
        return ("dir", BUILTIN_DIRECT[flat])
    value = _canon_number(flat, symbols, None)
    if value is not None:
        return ("dir", value)
    return ("sym", flat)


def _canon_number(text: str, symbols: Dict[str, int], default):
    text = text.strip().upper()
    if not text:
        return default
    m = re.fullmatch(r"(LOW|HIGH)\((.*)\)", text)
    if m:
        inner = _canon_number(m.group(2), symbols, None)
        if inner is None:
            return default
        return (inner & 0xFF) if m.group(1) == "LOW" else ((inner >> 8) & 0xFF)
    if text in symbols:
        return symbols[text]
    try:
        return _decode_number(text)
    except ValueError:
        return default


def canon(text: str, symbols: Dict[str, int]) -> Tuple[str, Tuple]:
    """Canonical ``(mnemonic, operands)`` for both source and disassembly text."""
    body = text.split(";")[0].strip()
    body = re.sub(r"^[A-Za-z_][A-Za-z0-9_]*\s*:", "", body).strip()
    if not body:
        return ("", ())
    body = body.replace("\t", " ")
    head, _, tail = body.partition(" ")
    mnem = head.upper()
    ops = [o for o in _split_top(tail)] if tail.strip() else []
    roles = _operand_roles(mnem, ops)
    canon_ops = tuple(_canon_operand(o, r, symbols) for o, r in zip(ops, roles))
    return (mnem, canon_ops)



# ---------------------------------------------------------------------------
# self test
# ---------------------------------------------------------------------------
SELFTEST_SOURCE = r"""
; ---------------------------------------------------------------------------
; asm51 self-test: one line per supported instruction form.
; ---------------------------------------------------------------------------
CHARSET koi8-r
        ORG   0x0000
START:  NOP
        MOV   A,#12h
        MOV   A,30h
        MOV   A,@R0
        MOV   A,@R1
        MOV   A,R0
        MOV   A,R7
        MOV   R0,A
        MOV   R3,#7
        MOV   R2,30h
        MOV   30h,A
        MOV   30h,#5
        MOV   30h,R1
        MOV   31h,32h
        MOV   33h,@R0
        MOV   34h,@R1
        MOV   @R0,A
        MOV   @R1,A
        MOV   @R0,#9
        MOV   @R1,#9
        MOV   @R0,30h
        MOV   @R1,30h
        MOV   DPTR,#1234h
        MOV   C,ACC.3
        MOV   20h.1,C
        MOVX  A,@DPTR
        MOVX  A,@R0
        MOVX  A,@R1
        MOVX  @DPTR,A
        MOVX  @R0,A
        MOVX  @R1,A
        MOVC  A,@A+DPTR
        MOVC  A,@A+PC
        ADD   A,#1
        ADD   A,30h
        ADD   A,@R0
        ADD   A,R2
        ADDC  A,#1
        ADDC  A,30h
        ADDC  A,@R1
        ADDC  A,R3
        SUBB  A,#1
        SUBB  A,30h
        SUBB  A,@R0
        SUBB  A,R4
        INC   A
        INC   30h
        INC   @R0
        INC   R5
        INC   DPTR
        DEC   A
        DEC   30h
        DEC   @R1
        DEC   R6
        ANL   A,#0Fh
        ANL   A,30h
        ANL   A,@R0
        ANL   A,R1
        ANL   30h,A
        ANL   30h,#0Fh
        ORL   A,#0Fh
        ORL   A,30h
        ORL   A,@R1
        ORL   A,R2
        ORL   30h,A
        ORL   30h,#0Fh
        XRL   A,#0Fh
        XRL   A,30h
        XRL   A,@R0
        XRL   A,R3
        XRL   30h,A
        XRL   30h,#0Fh
        CLR   A
        CLR   C
        CLR   20h.0
        CPL   A
        CPL   C
        CPL   20h.1
        SETB  C
        SETB  20h.2
        ANL   C,20h.0
        ANL   C,/20h.0
        ORL   C,20h.0
        ORL   C,/20h.0
        RL    A
        RR    A
        RLC   A
        RRC   A
        SWAP  A
        XCH   A,30h
        XCH   A,@R0
        XCH   A,R7
        XCHD  A,@R1
        MUL   AB
        DIV   AB
        DA    A
        PUSH  30h
        POP   30h
        PUSH  PSW
        POP   PSW
        JMP   @A+DPTR
LOOP:   SJMP  LOOP
        JC    LOOP
        JNC   LOOP
        JZ    LOOP
        JNZ   LOOP
        JB    20h.0,LOOP
        JNB   20h.1,LOOP
        JBC   20h.2,LOOP
        CJNE  A,#5,LOOP
        CJNE  A,30h,LOOP
        CJNE  @R0,#5,LOOP
        CJNE  R0,#5,LOOP
        DJNZ  R2,LOOP
        DJNZ  30h,LOOP
        AJMP  PAGE2
        ACALL PAGE2
        LJMP  PAGE2
        LCALL PAGE2
        RET
        RETI
PAGE2:  MOV   A,#LOW(PAGE2)
        MOV   A,#HIGH(PAGE2)
        MOV   DPTR,#TABLE
        MOV   A,#LOW(TABLE)
        MOV   A,#HIGH(TABLE)
TABLE:  DB    1,2,"OK",0
        DW    TABLE,0x1234
        END
"""


def selftest(verbose: bool = True) -> int:
    """Assemble the built-in sample, disassemble it, verify every encoding.

    Returns 0 when everything round-trips and every table entry was exercised,
    otherwise 1.  Prints a short report when ``verbose``.
    """
    result = assemble(SELFTEST_SOURCE, charset=DEFAULT_CHARSET)
    symbols = dict(result.symbols)
    failures: List[str] = []
    exercised = set()
    image_view = _MemView({a: b for a, b in enumerate(result.image, result.base)})
    checked = 0

    for entry in result.listing:
        if entry.kind != "ins":
            continue
        checked += 1
        want = canon(entry.source, symbols)
        if want[0] == "ACALL":
            # tools/disasm.py has no ACALL case; verified separately below.
            continue
        text, length = disassemble_one(image_view, entry.addr)
        if length != len(entry.data):
            failures.append(
                f"{entry.addr:04X}: encoded {len(entry.data)} byte(s) but the "
                f"disassembler reads {length} ({text})")
            continue
        got = canon(text, symbols)
        ok = want == got
        if not ok:
            failures.append(f"{entry.addr:04X}: wrote {entry.source!r} -> {want}, "
                            f"disassembled {text!r} -> {got}")
        if verbose:
            hexs = " ".join(f"{b:02X}" for b in entry.data)
            print(f"  {entry.addr:04X} {hexs:<12} {'ok ' if ok else 'BAD'} "
                  f"{entry.source:<22} | {text}")

    # ACALL is a real 8051 instruction that tools/disasm.py does not decode
    # (0x11/0x31/.../0xF1 fall through to "DB").  Verify it by construction:
    # opcode = 0x11 | page<<5, then the low target byte.
    acall = [e for e in result.listing
             if e.kind == "ins" and canon(e.source, symbols)[0] == "ACALL"]
    if not acall:
        failures.append("self-test source does not exercise ACALL")
    for entry in acall:
        target = canon(entry.source, symbols)[1][0][1]
        expect = bytes((0x11 | (((target >> 8) & 7) << 5), target & 0xFF))
        if entry.data != expect:
            failures.append(f"{entry.addr:04X}: ACALL encoded {entry.data.hex()} "
                            f"but 0x11|page would be {expect.hex()}")
        elif verbose:
            print(f"  {entry.addr:04X} {entry.data.hex(' ').upper():<12} ok  "
                  f"ACALL (verified by construction; tools/disasm.py has no "
                  f"ACALL case)")

    # every table entry must appear in the self-test source
    for mnem, pattern in result.encodings:
        exercised.add((mnem, pattern))
    missing = sorted(set(
        (m, p) for m, entries in ENC.items() for p, _ in entries
    ) - exercised)

    # data directives
    table = symbols.get("TABLE")
    if table is None:
        failures.append("TABLE label missing")
    else:
        expect = bytes((1, 2, ord("O"), ord("K"), 0, (table >> 8) & 0xFF,
                        table & 0xFF, 0x12, 0x34))
        got = result.image[table - result.base:table - result.base + len(expect)]
        if got != expect:
            failures.append(f"DB/DW at 0x{table:04X}: {got.hex()} != {expect.hex()}")

    if verbose:
        print()
        print(f"asm51 selftest: {checked} instructions, "
              f"{len(exercised)} distinct encodings exercised, "
              f"{len(ENC)} mnemonics, image {len(result.image)} bytes "
              f"(0x{result.base:04X}..0x{result.end - 1:04X})")
        if result.warnings:
            for warning in result.warnings:
                print(f"  warning: {warning}")
        if missing:
            print(f"  NOT COVERED by the self-test source: {missing}")
        if failures:
            print()
            for failure in failures:
                print(f"  FAIL {failure}")
        else:
            print("  every emitted encoding round-trips through tools/disasm.py")
    return 1 if (failures or missing) else 0


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="asm51", description="small two-pass MCS-51 assembler")
    parser.add_argument("source", nargs="?", help="input .asm file")
    parser.add_argument("-o", "--output", help="write Intel HEX here")
    parser.add_argument("--bin", help="write a raw binary image here")
    parser.add_argument("--org", type=lambda v: int(v, 0), default=0,
                        help="default origin when the source has no ORG")
    parser.add_argument("--charset", default=DEFAULT_CHARSET,
                        help="codec for string literals (default: koi8-r)")
    parser.add_argument("--listing", action="store_true",
                        help="print the generated listing")
    parser.add_argument("--selftest", action="store_true",
                        help="assemble/disassemble the built-in test program")
    args = parser.parse_args(argv)

    if args.selftest:
        print("asm51 self-test")
        return selftest(verbose=True)
    if not args.source:
        parser.error("no source file (or use --selftest)")

    try:
        result = assemble_file(args.source, org=args.org, charset=args.charset)
    except AsmError as exc:
        print(f"{args.source}: {exc}", file=sys.stderr)
        return 1

    for warning in result.warnings:
        print(f"{args.source}: warning: {warning}", file=sys.stderr)
    if args.listing:
        for entry in result.listing:
            print(entry)
    if args.output:
        with open(args.output, "w", encoding="ascii", newline="\n") as fh:
            fh.write(result.intel_hex())
        print(f"{args.output}: {len(result.image)} bytes "
              f"(0x{result.base:04X}..0x{result.end - 1:04X})")
    if args.bin:
        with open(args.bin, "wb") as fh:
            fh.write(result.image)
        print(f"{args.bin}: {len(result.image)} bytes")
    if not args.output and not args.bin:
        print(f"{len(result.image)} bytes (0x{result.base:04X}..0x{result.end - 1:04X})")
        print(f"symbols: {', '.join(sorted(result.symbols))}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
