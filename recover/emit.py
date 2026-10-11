"""Emit readable, compilable-looking artifacts from a Ghidra pseudo-C dump.

The recovery pipeline has four stages:

``parse``      :mod:`recover.parse` splits the dump into globals + functions.
``AST``        :mod:`recover.cparse` parses each body into a small syntax tree.
``interpreter``: :mod:`recover.interp` executes that AST against
               :mod:`recover.namespace`'s 8051 model.
``emitter``    (this module) turns the *same* dump back into source a human can
               read and keep working on.

Two artifacts are produced by :func:`emit_c` and :func:`emit_python`:

``firmware_clean.c``
    The whole dump as C: real integer widths instead of ``undefined``/``byte``,
    identifiers that say which address space they live in (``iram_3E``,
    ``xdata_0C7A``, ``sfr_92``, ``sub_810F``, ``loc_EE3F``), one macro per
    decompiler intrinsic, and a comment naming every address that no dump
    covers.
``firmware_recovered.py``
    The same information as a diff-able Python module: one ``RECOVERED`` entry
    per function plus ``STATS`` and ``MISSING_RANGES``.

Honesty rules
-------------
* ``0x8000..0xFFFF`` is the real ROM (``firmware/nm27c512n.hex``); anything the
  dump calls below that is decompiler *fiction* and is emitted with an
  ``_external`` suffix and an explicit comment.
* Stubs (Ghidra's ``halt_baddata()``) are labelled ``stub``, never "recovered".
* Nothing is renamed in a way that invents meaning: addresses are preserved and
  the original Ghidra name is kept in a comment wherever it is changed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .parse import Function, Global, Program, parse_dump

__all__ = [
    "DUMP_ROM_START",
    "DUMP_ROM_END",
    "MISSING_ROM_START",
    "MISSING_ROM_END",
    "EmitResult",
    "CProgram",
    "RecoveredEntry",
    "analyse",
    "build_name_map",
    "check_balance",
    "collect_intrinsics",
    "emit_all",
    "emit_c",
    "emit_python",
    "map_identifier",
    "missing_ranges",
    "pretty_body",
    "rewrite_identifiers",
    "scan_raw_functions",
    "LEGACY_RENAME",
]

# --------------------------------------------------------------------- constants
#: The dump ``docs/nm27c512n_decompiled.c`` was produced from this image only.
DUMP_ROM_START = 0x8000
DUMP_ROM_END = 0xFFFF
#: The other half of the firmware - present in the chip, absent from our dump.
MISSING_ROM_START = 0x0000
MISSING_ROM_END = 0x7FFF

#: ``undefined`` -> C type.  Ghidra's pseudo-types carry no width; each one maps
#: to the narrowest C type that can hold what the dump does with it.
TYPE_MAP: Dict[str, str] = {
    "undefined": "unsigned char",
    "undefined1": "unsigned char",
    "undefined2": "unsigned short",
    "undefined4": "unsigned int",
    "byte": "unsigned char",
    "sbyte": "signed char",
    "ushort": "unsigned short",
    "uint": "unsigned int",
    "ulong": "unsigned long",
    "uint3": "unsigned int",
    "word": "unsigned short",
    "dword": "unsigned int",
    "bool": "unsigned char",
}

#: Ghidra pseudo-types -> real C types, with the reason for the width.  Emitted
#: as a ``typedef`` block so the bodies can keep the decompiler's spelling.
_GHIDRA_TYPES: Tuple[Tuple[str, str, str], ...] = (
    ("undefined", "unsigned char", "Ghidra emits this when it has no type info"),
    ("undefined1", "unsigned char", "8-bit unknown"),
    ("undefined2", "unsigned short", "16-bit unknown"),
    ("undefined4", "unsigned int", "16-bit on this 8051 target"),
    ("byte", "unsigned char", "Ghidra's byte"),
    ("sbyte", "signed char", "Ghidra's signed byte"),
    ("ushort", "unsigned short", "16-bit unsigned"),
    ("uint", "unsigned int", "16-bit on this target"),
    ("uint3", "unsigned int", "24-bit in the decompiler, 16 bits here"),
    ("word", "unsigned short", "16-bit"),
    ("dword", "unsigned int", "32-bit in C, 16-bit on this target"),
    ("bool", "unsigned char", "Ghidra's bool is one byte here"),
)

#: The Ghidra type words, for quick membership tests when filtering names.
_GHIDRA_TYPE_NAMES = frozenset(name for name, _ctype, _note in _GHIDRA_TYPES)

#: Ghidra's intrinsics, with the number of arguments each is emitted with.
INTRINSIC_ARITY: Dict[str, int] = {
    "halt_baddata": 0,
    "nop": 0,
    "ZEXT12": 1,
    "ZEXT14": 1,
    "ZEXT18": 1,
    "ZEXT22": 1,
    "ZEXT24": 1,
    "ZEXT28": 1,
    "ZEXT32": 1,
    "ZEXT34": 1,
    "ZEXT38": 1,
    "ZEXT41": 1,
    "ZEXT42": 1,
    "ZEXT44": 1,
    "SEXT12": 1,
    "SEXT14": 1,
    "SEXT18": 1,
    "SEXT22": 1,
    "SEXT24": 1,
    "SEXT28": 1,
    "SEXT32": 1,
    "SEXT34": 1,
    "SEXT38": 1,
    "SEXT41": 1,
    "SEXT42": 1,
    "SEXT44": 1,
    "SUB41": 2,
    "SUB42": 2,
    "SUB21": 2,
    "SUB22": 2,
    "SUB11": 2,
    "SUB12": 2,
    "CARRY1": 2,
    "CARRY2": 2,
    "CARRY4": 2,
    "SBORROW1": 2,
    "SBORROW2": 2,
    "SBORROW4": 2,
    "SCARRY1": 2,
    "SCARRY2": 2,
    "SCARRY4": 2,
    "CONCAT11": 2,
    "CONCAT12": 2,
    "CONCAT13": 2,
    "CONCAT14": 2,
    "CONCAT21": 2,
    "CONCAT22": 2,
    "CONCAT24": 2,
    "CONCAT31": 2,
    "CONCAT41": 2,
    "CONCAT44": 2,
}

INTRINSIC_RE = re.compile(
    r"\b(ZEXT\d{2}|SEXT\d{2}|SUB\d{2}|CARRY\d|SBORROW\d|SCARRY\d|CONCAT\d{2})\b"
)

_C_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "default", "break",
    "continue", "return", "goto", "sizeof", "void", "char", "short", "int",
    "long", "unsigned", "signed", "float", "double", "struct", "union", "enum",
    "typedef", "static", "const", "volatile", "extern", "register", "auto",
    "true", "false", "bool",
}

#: ``original -> readable`` for every rename the emitter performs.  Filled in by
#: :func:`build_name_map` so callers can document the mapping.
LEGACY_RENAME: Dict[str, str] = {}

_TYPE_WORDS = {
    "undefined", "undefined1", "undefined2", "undefined4", "byte", "sbyte",
    "char", "int", "uint", "long", "ulong", "short", "ushort", "bool", "void",
    "size_t", "word", "dword", "float", "double", "code", "data", "xdata",
    "unsigned", "signed",
    "uint8", "uint16", "uint32", "int8", "int16", "int32",
}

#: SFRs and SFR bits that ``<8051.h>`` already declares.  The dump declares some
#: of them too; redeclaring them is a duplicate-symbol error, so those names are
#: provided by the header instead.
_SFR_NAMES = frozenset({
    "P0", "P1", "P2", "P3", "TCON", "TMOD", "TL0", "TL1", "TH0", "TH1", "SCON",
    "SBUF", "IE", "IP", "PSW", "ACC", "B", "SP", "DPL", "DPH", "PCON", "T2CON",
    "RCAP2L", "RCAP2H", "TL2", "TH2", "CCON", "CMOD", "CCAP0L", "CCAP0H",
    "CCAP1L", "CCAP1H", "CCAP2L", "CCAP2H", "CCAP3L", "CCAP3H", "CCAP4L",
    "CCAP4H", "CCAPM0", "CCAPM1", "CCAPM2", "CCAPM3", "CCAPM4", "WDTRST",
})
_SFR_BIT_NAMES = frozenset({
    "ET1", "ET0", "EX1", "EX0", "ES", "EA", "PT1", "PT0", "PX1", "PX0", "PS",
    "TF1", "TR1", "TF0", "TR0", "IE1", "IT1", "IE0", "IT0",
    "CY", "AC", "F0", "RS1", "RS0", "OV", "P",
    "SM0", "SM1", "SM2", "REN", "TB8", "RB8", "TI", "RI",
    "RXD", "TXD", "T0", "T1", "INT0", "INT1", "WR", "RD",
    "P0_0", "P0_1", "P0_2", "P0_3", "P0_4", "P0_5", "P0_6", "P0_7",
    "P1_0", "P1_1", "P1_2", "P1_3", "P1_4", "P1_5", "P1_6", "P1_7",
    "P2_0", "P2_1", "P2_2", "P2_3", "P2_4", "P2_5", "P2_6", "P2_7",
    "P3_0", "P3_1", "P3_2", "P3_3", "P3_4", "P3_5", "P3_6", "P3_7",
})


# ------------------------------------------------------------------ name mapping
def map_identifier(name: str) -> Tuple[str, bool, Optional[str]]:
    """Map one Ghidra identifier to a readable C identifier.

    Returns ``(new_name, changed, original)``; ``original`` is the old spelling
    when it differs, so callers can keep it in a comment.  The address is always
    preserved - nothing here guesses what a routine *does*.
    """
    if name.startswith("FUN_CODE_"):
        new = "sub_" + name[len("FUN_CODE_"):].upper()
    elif name.startswith("thunk_FUN_CODE_"):
        new = "sub_" + name[len("thunk_FUN_CODE_"):].upper() + "_thunk"
    elif name.startswith("UNK_CODE_"):
        new = "unk_code_" + name[len("UNK_CODE_"):].upper()
    elif name.startswith("LAB_CODE_"):
        new = "loc_" + name[len("LAB_CODE_"):].upper()
    elif name.startswith("code_c0x"):
        new = "loc_" + name[len("code_c0x"):].upper()
    elif name.startswith("DAT_INTMEM_"):
        new = "iram_" + name[len("DAT_INTMEM_"):].upper()
    elif name.startswith("DAT_EXTMEM_"):
        new = "xdata_" + name[len("DAT_EXTMEM_"):].upper()
    elif name.startswith("DAT_SFR_"):
        new = "sfr_" + name[len("DAT_SFR_"):].upper()
    elif name.startswith("UNK_SFR_"):
        new = "sfr_" + name[len("UNK_SFR_"):].upper()
    elif name.startswith("DAT_CODE_"):
        new = "rom_" + name[len("DAT_CODE_"):].upper()
    elif name.startswith("DAT_"):
        new = "unk_" + name[len("DAT_"):]
    elif name.startswith("func_0x"):
        new = "sub_%04X_external" % int(name[len("func_0x"):], 16)
    elif re.fullmatch(r"[A-Za-z_0-9]+\.[0-7]", name):
        head, _, bit = name.partition(".")
        new = "bit_%s_%s" % (head.upper(), bit)
    elif re.fullmatch(r"_[0-9a-fA-F]+_[0-7]", name):
        head, _, bit = name[1:].partition("_")
        new = "bit_%s_%s" % (head.upper(), bit)
    elif re.fullmatch(r"bINTMEM[0-9a-fA-F]+", name):
        new = "bit_iram_" + name[len("bINTMEM"):].upper()
    elif re.fullmatch(r"b[A-Za-z_]*\d[A-Za-z_0-9]*", name):
        new = "bit_" + name[1:]
    else:
        return name, False, None
    return new, new != name, (name if new != name else None)


# -------------------------------------------------------------------------- text
_TOKEN_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z_0-9]*|\s+|.', re.S
)


def rewrite_identifiers(text: str, mapping: Optional[Dict[str, str]] = None) -> str:
    """Rewrite identifiers, leaving string/char literals untouched.

    ``mapping`` (a pre-computed ``original -> replacement`` table) takes
    precedence, so that a global and all of its uses agree.
    """
    out: List[str] = []
    for token in _TOKEN_RE.findall(text):
        if token and (token[0].isalpha() or token[0] == "_"):
            if token in _C_KEYWORDS:
                out.append(token)
            elif mapping is not None and token in mapping:
                out.append(mapping[token])
            else:
                new, changed, _origin = map_identifier(token)
                out.append(new if changed else token)
        else:
            out.append(token)
    return "".join(out)


#: Ghidra's pseudo-types as whole-word matches, longest first so that
#: ``undefined`` never shadows ``undefined1``.
_C_TYPE_WORD_RE = re.compile(
    r"\b(?:"
    + "|".join(sorted((re.escape(word) for word in TYPE_MAP), key=len, reverse=True))
    + r")\b"
)


def rewrite_types(text: str) -> str:
    """Turn Ghidra's pseudo-types into real C types.

    The dump uses ``undefined1``/``byte``/``uint`` where it lost type
    information; leaving them in would mean the reconstruction still only
    compiles through a compatibility ``typedef``.  Comments and string/char
    literals are copied verbatim: they carry provenance (``/* undefined1 in the
    Ghidra dump */``) that must not be rewritten.
    """
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(text[i:j])
            i = j
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(text[i:j])
            i = j
            continue
        if ch in "\"'":
            quote, j = ch, i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            out.append(text[i:j])
            i = j
            continue
        if ch.isalpha() or ch == "_":
            match = _C_TYPE_WORD_RE.match(text, i)
            if match:
                out.append(TYPE_MAP[match.group(0)])
                i = match.end()
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _normalise_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _strip_line_comments(text: str) -> str:
    return "\n".join(re.sub(r"//[^\n]*", "", line) for line in text.splitlines())


def pretty_body(text: str) -> str:
    """Tidy a body for a generated file without changing any token."""
    lines = [line.rstrip() for line in _normalise_newlines(text).splitlines()]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    result: List[str] = []
    blanks = 0
    for line in lines:
        if not line.strip():
            blanks += 1
            if blanks > 1:
                continue
        else:
            blanks = 0
        result.append(line)
    indents = [len(l) - len(l.lstrip(" ")) for l in result if l.strip()]
    if indents:
        common = min(indents)
        if common:
            result = [(l[common:] if l.strip() else l) for l in result]
    return "\n".join(result)


def check_balance(text: str) -> List[str]:
    """Cheap C sanity check: brace/paren/bracket balance outside literals.

    Returns a list of human-readable problems; an empty list means balanced.
    This is deliberately *not* a compiler: it catches truncation and mangled
    emission, the realistic failure modes for generated C.
    """
    problems: List[str] = []
    stack: List[Tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    line = 1
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j < 0:
                problems.append(f"line {line}: unterminated block comment")
                break
            line += text.count("\n", i, j)
            i = j + 2
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\":
                    i += 1
                if i < n and text[i] == "\n":
                    line += 1
                i += 1
            if i >= n:
                problems.append(f"line {line}: unterminated literal")
                break
            i += 1
            continue
        if ch in "([{":
            stack.append((ch, line))
        elif ch in ")]}":
            if not stack:
                problems.append(f"line {line}: unmatched {ch!r}")
            elif stack[-1][0] != pairs[ch]:
                problems.append(
                    f"line {line}: {ch!r} closes {stack[-1][0]!r} opened on line {stack[-1][1]}"
                )
                stack.pop()
            else:
                stack.pop()
        i += 1
    for opener, opened_at in stack:
        problems.append(f"line {opened_at}: unclosed {opener!r}")
    return problems


# ------------------------------------------------------------------ dump indexing
@dataclass
class RawFunction:
    """A function definition found directly in the text of the dump."""

    name: str
    return_type: str
    params: str
    body: str
    line: int
    address: Optional[int] = None


_RAW_SIG_RE = re.compile(
    r"^\s*(?P<ret>(?:unsigned\s+|signed\s+)?[A-Za-z_]\w*(?:\s*\*+)?)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}]*)\)?\s*$"
)
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_LOCAL_DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:unsigned[ \t]+|signed[ \t]+)?"
    r"(?P<type>undefined\d?|byte|char|bool|int|uint|ushort|short|long|void|code|xdata|data|size_t|word|dword)\b"
    r"[^;{}\n]*?(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;"
)


def _params_balanced(text: str) -> bool:
    """True when the parentheses of a signature line are closed."""
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
    return depth == 0


def _extract_braces(code: str, brace_index: int) -> Optional[str]:
    """Return the body of the block starting at ``brace_index``."""
    depth = 0
    i = brace_index
    n = len(code)
    while i < n:
        ch = code[i]
        if ch == '"':
            i += 1
            while i < n and code[i] != '"':
                i += 2 if code[i] == "\\" else 1
        elif ch == "'":
            i += 1
            while i < n and code[i] != "'":
                i += 2 if code[i] == "\\" else 1
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return code[brace_index + 1:i]
        i += 1
    return None


def scan_raw_functions(text: str) -> List[RawFunction]:
    """Find every function definition in the dump text.

    This exists because the layout heuristic in :mod:`recover.parse` only
    recognises identifiers as return types, so definitions such as
    ``byte * FUN_CODE_f80d(...)`` are skipped.  The bodies found here are
    sliced straight out of the dump and are real code.
    """
    code = _strip_line_comments(_normalise_newlines(text))
    lines = code.splitlines()
    offsets: List[int] = []
    running = 0
    for line in lines:
        offsets.append(running)
        running += len(line) + 1

    found: List[RawFunction] = []
    for index, line in enumerate(lines):
        match = _RAW_SIG_RE.match(line)
        if not match:
            continue
        ret = match.group("ret").strip()
        if ret.split()[0] not in _TYPE_WORDS:
            continue
        name = match.group("name")
        if name in _C_KEYWORDS:
            continue
        # the parameter list may be wrapped over the following lines
        j = index
        joined = line
        while not _params_balanced(joined) and j + 1 < len(lines) and j - index < 8:
            j += 1
            joined += " " + lines[j].strip()
        if not _params_balanced(joined):
            continue
        j += 1
        blanks = 0
        while j < len(lines) and not lines[j].strip():
            j += 1
            blanks += 1
        if blanks > 3 or j >= len(lines) or lines[j].strip() != "{":
            continue
        brace_index = offsets[j] + lines[j].index("{")
        body = _extract_braces(code, brace_index)
        if body is None:
            continue
        address = None
        if name.startswith("FUN_CODE_"):
            try:
                address = int(name.split("_")[-1], 16)
            except ValueError:
                address = None
        found.append(
            RawFunction(name, ret, match.group("params").strip(), body, index + 1, address)
        )
    return found


def missing_ranges(
    covered: Sequence[Tuple[int, int]] = ((DUMP_ROM_START, DUMP_ROM_END),),
    total_start: int = 0x0000,
    total_end: int = 0xFFFF,
) -> List[List[int]]:
    """Complement of ``covered`` within ``total_start..total_end``."""
    gaps: List[List[int]] = []
    cursor = total_start
    for start, end in sorted(covered):
        if start > cursor:
            gaps.append([cursor, start - 1])
        cursor = max(cursor, end + 1)
    if cursor <= total_end:
        gaps.append([cursor, total_end])
    return gaps


@dataclass
class DumpFacts:
    """Everything the emitters need to know about one dump."""

    program: Program
    source_name: str
    covered: List[Tuple[int, int]] = field(default_factory=list)
    parsed_names: Set[str] = field(default_factory=set)
    raw_functions: List[RawFunction] = field(default_factory=list)
    raw_only: List[RawFunction] = field(default_factory=list)
    called_names: Dict[str, int] = field(default_factory=dict)
    uncovered_calls: Dict[str, int] = field(default_factory=dict)
    intrinsic_uses: Dict[str, int] = field(default_factory=dict)


def collect_intrinsics(text: str) -> Dict[str, int]:
    """How often each decompiler intrinsic appears in ``text``."""
    counts: Dict[str, int] = {}
    for match in INTRINSIC_RE.finditer(text):
        counts[match.group(1)] = counts.get(match.group(1), 0) + 1
    for name in ("halt_baddata", "nop"):
        found = len(re.findall(r"\b" + name + r"\s*\(", text))
        if found:
            counts[name] = counts.get(name, 0) + found
    return counts


def analyse(
    text: str,
    source_name: str = "",
    covered: Sequence[Tuple[int, int]] = ((DUMP_ROM_START, DUMP_ROM_END),),
) -> DumpFacts:
    """Parse the dump and collect everything both emitters need."""
    program = parse_dump(text, source_name)
    facts = DumpFacts(program=program, source_name=source_name, covered=list(covered))
    facts.parsed_names = {f.name for f in program.functions}
    facts.raw_functions = scan_raw_functions(text)
    facts.raw_only = [r for r in facts.raw_functions if r.name not in facts.parsed_names]

    for body in [f.body for f in program.functions] + [r.body for r in facts.raw_only]:
        for match in _CALL_RE.finditer(body):
            name = match.group(1)
            facts.called_names[name] = facts.called_names.get(name, 0) + 1
        for name, count in collect_intrinsics(body).items():
            facts.intrinsic_uses[name] = facts.intrinsic_uses.get(name, 0) + count

    defined = facts.parsed_names | {r.name for r in facts.raw_functions}

    def covered_addr(addr: int) -> bool:
        return any(start <= addr <= end for start, end in facts.covered)

    for name, count in facts.called_names.items():
        if name in defined or name in _C_KEYWORDS:
            continue
        if INTRINSIC_RE.fullmatch(name) or name in INTRINSIC_ARITY:
            continue
        if name.startswith("func_0x"):
            if not covered_addr(int(name[len("func_0x"):], 16)):
                facts.uncovered_calls[name] = count
            continue
        # Any other called-but-undefined name is equally unavailable.
        facts.uncovered_calls[name] = count
    return facts


def build_name_map(facts: DumpFacts) -> Dict[str, str]:
    """The single ``original -> readable`` table both emitters use."""
    mapping: Dict[str, str] = {}
    names = (
        list(facts.parsed_names)
        + [r.name for r in facts.raw_functions]
        + list(facts.uncovered_calls)
        + [d.name for d in facts.program.globals if d.name]
    )
    for name in names:
        new, changed, _origin = map_identifier(name)
        mapping[name] = new
        if changed:
            LEGACY_RENAME[name] = new
    return mapping


def program_stats(facts: DumpFacts) -> Dict[str, object]:
    """Counters shared by the C and Python emitters."""
    parsed = facts.program.functions
    return {
        "source": facts.source_name,
        "functions": len(parsed),
        "raw_functions": len(facts.raw_functions),
        "raw_only": len(facts.raw_only),
        "stubs": sum(1 for f in parsed if f.is_stub),
        "partials": sum(1 for f in parsed if f.is_partial),
        "recovered_bodies": sum(1 for f in parsed if f.is_recovered),
        "globals": len(facts.program.globals),
        "uncovered_calls": len(facts.uncovered_calls),
        "intrinsics": len(facts.intrinsic_uses),
        "missing_ranges": missing_ranges(facts.covered),
    }


@dataclass
class EmitResult:
    """One generated artifact."""

    path: str
    text: str
    stats: Dict[str, object] = field(default_factory=dict)
    balance: List[str] = field(default_factory=list)


# ------------------------------------------------------------------ C emitter
def _macro_for_intrinsic(name: str) -> str:
    """One ``#define`` reproducing Ghidra's semantics for ``name``."""
    if name == "halt_baddata":
        return "#define halt_baddata() __baddata()"
    if name == "nop":
        return "#define nop() __nop()"
    match = re.fullmatch(r"ZEXT(\d)(\d)", name)
    if match:
        width = int(match.group(1)) * int(match.group(2))
        return f"#define {name}(x) ((unsigned int)((x) & 0x{((1 << width) - 1):X}u))"
    match = re.fullmatch(r"SEXT(\d)(\d)", name)
    if match:
        width = int(match.group(1)) * int(match.group(2))
        sign = 1 << (width - 1)
        return (
            f"#define {name}(x) ((int)((((unsigned int)(x) & 0x{((1 << width) - 1):X}u) ^ "
            f"0x{sign:X}u) - 0x{sign:X}u))"
        )
    match = re.fullmatch(r"SUB(\d)(\d)", name)
    if match:
        out_bytes, in_bytes = int(match.group(1)), int(match.group(2))
        mask = (1 << (in_bytes * 8)) - 1
        if out_bytes == 1:
            return (
                f"#define {name}(x, s) ((unsigned char)(((unsigned int)(x) >> (s)) & "
                f"0x{mask:X}u))"
            )
        width = out_bytes * 8
        return (
            f"#define {name}(x, s) ((unsigned int)(((unsigned int)(x) >> (s)) & "
            f"0x{((1 << width) - 1):X}u))"
        )
    if name == "CARRY1":
        return (
            "#define CARRY1(a, b) ((unsigned char)((((unsigned int)((a) & 0xFFu) + "
            "((unsigned int)((b) & 0xFFu))) > 0xFFu) ? 1 : 0))"
        )
    if name == "CARRY2":
        return (
            "#define CARRY2(a, b) ((unsigned char)((((unsigned long)((a) & 0xFFFFu) + "
            "((unsigned long)((b) & 0xFFFFu))) > 0xFFFFu) ? 1 : 0))"
        )
    if name == "SCARRY1":
        return (
            "#define SCARRY1(a, b) ((unsigned char)((((int)(signed char)(a)) + "
            "((int)(signed char)(b))) > 127 || (((int)(signed char)(a)) + "
            "((int)(signed char)(b))) < -128 ? 1 : 0))"
        )
    if name.startswith("SBORROW"):
        width = {"1": 8, "2": 16, "4": 32}.get(name[-1], 8)
        mask = (1 << width) - 1
        return (
            f"#define {name}(a, b) ((unsigned char)((((signed long)((a) & 0x{mask:X}u)) - "
            f"((signed long)((b) & 0x{mask:X}u))) < 0 ? 1 : 0))"
        )
    match = re.fullmatch(r"CONCAT(\d)(\d)", name)
    if match:
        high_bits, low_bits = int(match.group(1)) * 8, int(match.group(2)) * 8
        return (
            f"#define {name}(hi, lo) ((unsigned int)((((unsigned int)((hi) & "
            f"0x{((1 << high_bits) - 1):X}u)) << {low_bits}) | ((unsigned int)((lo) & "
            f"0x{((1 << low_bits) - 1):X}u))))"
        )
    arity = INTRINSIC_ARITY.get(name)
    if arity == 0:
        return f"#define {name}() ((void)0)"
    if arity == 1:
        return f"#define {name}(x) ((unsigned int)(x))"
    if arity == 2:
        return f"#define {name}(a, b) ((unsigned int)((a) ^ (b)))"
    return f"/* {name}: unknown decompiler intrinsic, left as a call */"


def _c_params(params: str, mapping: Dict[str, str]) -> str:
    """Rewrite a parameter list for a declaration or a definition."""
    out: List[str] = []
    for part in params.split(","):
        part = part.strip()
        if not part:
            continue
        part = re.sub(r"\s*=.*$", "", part)          # drop default initialisers
        out.append(rewrite_types(rewrite_identifiers(part, mapping)))
    return ", ".join(out) if out else "void"


def _c_ret(return_type: str) -> str:
    """Real C type for a return type, keeping any pointer indirection.

    ``byte *`` must become ``unsigned char *`` - mapping only the exact string
    would leave ``byte *`` behind, and that is still a Ghidra spelling.
    """
    base = return_type.rstrip()
    stars = ""
    while base.endswith("*"):
        stars += "*"
        base = base[:-1].rstrip()
    return TYPE_MAP.get(base, base) + ((" " + stars) if stars else "")


def _arg_count(facts: DumpFacts, callee: str) -> int:
    """Maximum argument count with which ``callee`` is actually called."""
    best = 0
    bodies = [f.body for f in facts.program.functions] + [r.body for r in facts.raw_only]
    for body in bodies:
        for match in re.finditer(r"\b" + re.escape(callee) + r"\s*\(", body):
            index = match.end()
            depth = 1
            commas = 0
            seen = False
            while index < len(body) and depth > 0:
                ch = body[index]
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                    if depth == 0:
                        break
                elif depth == 1:
                    if ch == ",":
                        commas += 1
                    elif not ch.isspace():
                        seen = True
                index += 1
            best = max(best, commas + 1 if seen else 0)
    return best


def _dedupe_globals(decls: List[Global], mapping: Dict[str, str]) -> List[Global]:
    """Drop declarations that collide after renaming.

    The decompiler emits both ``byte DAT_INTMEM_44;`` and ``byte *DAT_INTMEM_44;``,
    and both ``byte DAT_INTMEM_5c;`` and ``char DAT_INTMEM_5c;``.  Keeping one
    spelling per name is honest: the address is identical, only the width and
    pointer-ness the decompiler guessed differ.
    """
    best: Dict[str, Global] = {}
    order: List[str] = []
    for decl in decls:
        if not decl.name or decl.type == "typedef":
            continue
        new = mapping.get(decl.name, decl.name)
        if new not in best:
            best[new] = decl
            order.append(new)
        elif best[new].stars and not decl.stars:
            best[new] = decl          # prefer the scalar spelling
    return [best[name] for name in order]


class CProgram:
    """Builds the readable C reconstruction of one dump."""

    def __init__(self, facts: DumpFacts, source_path: str = "") -> None:
        self.facts = facts
        self.source_path = source_path or facts.source_name
        self.name_map: Dict[str, str] = build_name_map(facts)
        self.undefined_globals: Dict[str, str] = {}
        self.label_names: Set[str] = set()

    # -------------------------------------------------------------- collection
    def _bodies(self) -> List[str]:
        facts = self.facts
        return [f.body for f in facts.program.functions] + [r.body for r in facts.raw_only]

    def _collect(self) -> None:
        for body in self._bodies():
            for match in re.finditer(r"\b(?:goto\s+)([A-Za-z_]\w*)\s*;", body):
                self.label_names.add(rewrite_identifiers(match.group(1), self.name_map))
            for match in re.finditer(r"(?m)^[ \t]*([A-Za-z_]\w*)\s*:", body):
                self.label_names.add(rewrite_identifiers(match.group(1), self.name_map))
        self._collect_undefined_globals()

    def _collect_undefined_globals(self) -> None:
        """Identifiers used in code that no declaration covers."""
        facts = self.facts
        declared: Set[str] = set(_C_KEYWORDS)
        declared |= {d.name for d in facts.program.globals if d.name}
        declared |= set(facts.parsed_names)
        declared |= {r.name for r in facts.raw_functions}
        declared |= set(facts.uncovered_calls)
        declared |= set(INTRINSIC_ARITY)
        declared |= self.label_names
        for body in self._bodies():
            for match in _LOCAL_DECL_RE.finditer(body):
                declared.add(match.group("name"))
            for match in re.finditer(r"\bparam_\d+\b", body):
                declared.add(match.group(0))

        for body in self._bodies():
            for match in re.finditer(r"\b([A-Za-z_]\w*)\b", body):
                name = match.group(1)
                if (name in declared or name in _C_KEYWORDS
                        or name in _GHIDRA_TYPE_NAMES or name in _TYPE_WORDS):
                    continue
                if re.fullmatch(r"in_[A-Za-z_]\w*", name):
                    continue
                if INTRINSIC_RE.fullmatch(name) or name in INTRINSIC_ARITY:
                    continue
                new = rewrite_identifiers(name, self.name_map)
                if re.fullmatch(r"[A-Za-z_]\w*", new):
                    self.undefined_globals.setdefault(name, new)

    # ------------------------------------------------------------------- output
    def header(self) -> str:
        stats = self.facts.program.stats()
        return "\n".join(
            [
                "/*",
                f" * firmware_clean.c - readable reconstruction of {self.source_path}",
                " *",
                " * Generated by ``tools/recover_firmware.py emit``.  Do not edit by",
                " * hand: regenerate it from the decompiled dump instead.",
                " *",
                " * What this is",
                " * ------------",
                " * Ghidra decompiled the 27C512 EPROM image firmware/nm27c512n.hex.",
                " * That image only covers 0x8000..0xFFFF of the 64 KiB code space, so:",
                " *",
                " *   0x8000..0xFFFF  real code - the bytes exist and were disassembled",
                " *   0x0000..0x7FFF  NOT dumped.  Anything printed for that range is",
                " *                   decompiler guesswork; such calls are marked",
                " *                   _external and their bodies are placeholders.",
                " *",
                f" * functions in the dump   : {stats['functions']}",
                f" * real (non-stub) bodies  : {stats['recovered']}",
                f" * bad-instruction stubs   : {stats['stubs']}",
                f" * global declarations     : {stats['globals']}",
                f" * pointer-returning fns   : {len(self.facts.raw_only)} (missed by recover.parse)",
                " *",
                " * Renames are mechanical and keep the address; they do not invent",
                " * meaning.  The Ghidra spelling is kept in a comment when it changes:",
                " *   FUN_CODE_810f   -> sub_810F       DAT_INTMEM_3e   -> iram_3E",
                " *   DAT_EXTMEM_0c7a -> xdata_0C7A     DAT_SFR_92      -> sfr_92",
                " *   LAB_CODE_ee3f   -> loc_EE3F       code_c0xf1fe    -> loc_F1FE",
                " *   undefined 22.1  -> bit_22_1       func_0x1eb6     -> sub_1EB6_external",
                " */",
                "",
                "#ifndef FIRMWARE_CLEAN_C",
                "#define FIRMWARE_CLEAN_C",
                "",
                "#ifdef __SDCC",
                "#include <8051.h>            /* P0..P3, TCON, TMOD, SCON, ACC, ... */",
                "#endif",
                "",
            ]
            + self.type_aliases()
            + self.globals_guard()
        )

    def type_aliases(self) -> List[str]:
        lines = [
            "/* ---- Ghidra type names ---------------------------------------------- */",
            "/* The dump uses these instead of real C types.  The widths are the ones",
            " * Ghidra's target definition implies for an 8051 (a byte is 8 bits, an",
            " * int is 16); they are declared once, here, so the bodies stay legible. */",
        ]
        for name, ctype, note in _GHIDRA_TYPES:
            lines.append(f"typedef {ctype:<16} {name};   /* {note} */")
        lines.append("")
        return lines

    def globals_guard(self) -> List[str]:
        """Fallback SFR declarations for compilers that are not SDCC.

        Port bits (``P1_3`` etc.) are part of ``<8051.h>`` and are not repeated
        here: the global declarations below would otherwise collide with it.
        """
        fallback = sorted(
            name for name in (_SFR_NAMES | _SFR_BIT_NAMES)
            if not re.fullmatch(r"P[0-3]_[0-7]", name)
        )
        return [
            "#ifndef __SDCC",
            "/* Plain-C fallback.  On a real 8051 the SFRs live at fixed addresses",
            " * (P1 at 0x90, TCON at 0x88, ACC at 0xE0, ...) and SDCC spells them",
            " * ``__sfr __at(0x90) P1;`` - that spelling lives in <8051.h>.  Without",
            " * the header they are ordinary volatile cells so the file type-checks.",
            " * The dump declares some of these names itself; those declarations are",
            " * skipped below so the two do not collide. */",
        ] + [
            f"volatile unsigned char {name};" for name in fallback
        ] + [
            "#endif",
            "",
        ]

    def macros(self) -> str:
        lines = [
            "/* ---- decompiler intrinsics ------------------------------------------ */",
            "/* Ghidra prints these as if they were functions; they are pure bit",
            " * arithmetic and each one is defined exactly once, here. */",
            "",
        ]
        names = sorted(self.facts.intrinsic_uses, key=lambda n: (-self.facts.intrinsic_uses[n], n))
        for name in names:
            lines.append(_macro_for_intrinsic(name))
        lines += [
            "",
            "/* Ghidra emits halt_baddata() where the bytes could not be decoded.",
            " * Those bytes were never valid code; failing loudly beats returning a",
            " * value that was never in the ROM. */",
            "static void __baddata(void) {",
            "  /* ROM bytes here are not valid code */",
            "  for (;;) {",
            "  }",
            "}",
            "",
            "static void __nop(void) {}",
            "",
        ]
        return "\n".join(lines)

    def globals_block(self) -> str:
        lines = [
            "/* ---- globals -------------------------------------------------------- */",
            "/* Each name says which 8051 space it lives in:",
            " *   iram_XX    internal RAM (direct/indirect, 256 bytes)",
            " *   xdata_XXXX external data memory reached with MOVX - the cash",
            " *              register's 8255 PPI, display and printer live here",
            " *   sfr_XX     a special function register the decompiler did not name",
            " *   rom_XXXX   a byte in code space",
            " *   bit_XX_Y   bit Y of internal RAM byte XX (Ghidra prints ``22.1``)",
            " *",
            " * Some names are declared with two different widths in the dump; only",
            " * the first spelling is emitted and the address is unchanged either way.",
            " */",
            "",
        ]
        emitted: Set[str] = set()
        for decl in _dedupe_globals(self.facts.program.globals, self.name_map):
            if decl.type == "typedef":
                continue              # the alias block above already declares these
            if decl.name in _SFR_NAMES or decl.name in _SFR_BIT_NAMES:
                continue          # provided by <8051.h> / the fallback block
            lines.append(self._global_declaration(decl))
            emitted.add(self.name_map.get(decl.name, decl.name))
        extra = sorted(set(self.undefined_globals) - emitted)
        if extra:
            lines += [
                "",
                "/* Referenced by the recovered code but not declared in the dump; the",
                " * decompiler left these to the linker.  Width is unknown. */",
            ]
            reserved = self._reserved_names()
            for name in extra:
                new = self.undefined_globals[name]
                if new in _SFR_BIT_NAMES or new in _SFR_NAMES:
                    continue          # <8051.h> already declares these
                if new in emitted:
                    continue
                if new in reserved:
                    new = new + "_cell"
                if new in emitted:
                    continue
                emitted.add(new)
                lines.append(f"unsigned char {new};   /* was {name} */")
        lines.append("")
        return "\n".join(lines)

    def _reserved_names(self) -> Set[str]:
        """Function names and SFR names a global must not collide with."""
        return (
            {self.name_map.get(f.name, f.name) for f in self.facts.program.functions}
            | {self.name_map.get(r.name, r.name) for r in self.facts.raw_functions}
            | set(_SFR_NAMES)
            | set(_SFR_BIT_NAMES)
        )

    def _global_declaration(self, decl: Global) -> str:
        new = self.name_map.get(decl.name, decl.name)
        if new in self._reserved_names():
            new = new + "_cell"
        if decl.is_bit:
            if new in _SFR_BIT_NAMES and re.fullmatch(r"P[0-3]_[0-7]", new):
                return (
                    f"/* bit cell {decl.name}: 8051 port bit, declared as {new} by"
                    f" <8051.h> (or by the plain-C block above) */"
                )
            note = "" if new == decl.name else f"   /* was {decl.name!r} */"
            return (
                f"volatile unsigned char {new};   /* bit cell: 8051 bit RAM "
                f"{decl.name}, modelled as a byte */{note}"
            )
        ctype = _c_ret(decl.type)
        stars = decl.stars or ""
        array = decl.array or ""
        comment = "" if ctype == decl.type else f"   /* {decl.type} in the Ghidra dump */"
        if decl.type == "undefined" and not array:
            return f"unsigned char {stars}{new};{comment}"
        return f"{ctype} {stars}{new}{array};{comment}"

    # ------------------------------------------------------------------ bodies
    def function_signature(self, func: Function, for_definition: bool = False) -> str:
        new = self.name_map.get(func.name, map_identifier(func.name)[0])
        params = _c_params(", ".join(func.params), self.name_map)
        return f"{_c_ret(func.return_type)} {new}({params})"

    def raw_signature(self, raw: RawFunction) -> str:
        new = self.name_map.get(raw.name, map_identifier(raw.name)[0])
        return f"{_c_ret(raw.return_type)} {new}({_c_params(raw.params, self.name_map)})"

    def forward_declarations(self) -> str:
        lines = ["/* ---- forward declarations ------------------------------------------- */"]
        for func in self.facts.program.functions:
            lines.append(self.function_signature(func) + ";")
        for raw in self.facts.raw_only:
            lines.append(self.raw_signature(raw) + ";")
        seen: Set[str] = set()
        for callee in sorted(self.facts.uncovered_calls):
            new = self.name_map.get(callee, map_identifier(callee)[0])
            if new in seen:
                continue
            seen.add(new)
            args = ", ".join(
                f"unsigned int a{i + 1}" for i in range(_arg_count(self.facts, callee))
            )
            lines.append(f"unsigned int {new}({args if args else 'void'});")
        lines.append("")
        return "\n".join(lines)

    def function_block(self, func: Function) -> str:
        new_name = self.name_map.get(func.name, map_identifier(func.name)[0])
        address = f"0x{func.address:04X}" if func.address is not None else "unknown address"
        if func.name.startswith("thunk_"):
            return "\n".join(
                [
                    f"/* address {address} | duplicate thunk wrapper */",
                    f"/* was {func.name}: Ghidra emitted this body twice, once under the",
                    f" * plain address.  That copy is kept; {new_name} stays a forward",
                    " * declaration only. */",
                    "",
                ]
            )
        lines: List[str] = []
        if func.is_stub:
            status = "stub - these bytes were never valid code"
        elif func.is_partial:
            status = (
                f"partial - {func.baddata_prefix} executable statements, then "
                f"bad instruction data"
            )
        else:
            status = "recovered"
        lines.append(f"/* address {address} | {status} */")
        if func.warnings:
            lines.append("/* Ghidra warnings:")
            for warning in func.warnings[:6]:
                lines.append(f" *   {warning}")
            lines.append(" */")
        if func.name != new_name:
            lines.append(f"/* was {func.name} in the dump */")
        lines.append(self.function_signature(func, for_definition=True))
        lines.append("{")
        body = rewrite_types(
            rewrite_identifiers(pretty_body(func.body), self.name_map)
        )
        lines.append(body if body.strip() else "  /* empty body */")
        lines.append("}")
        lines.append("")
        return "\n".join(lines)

    def raw_function_block(self, raw: RawFunction) -> str:
        address = f"0x{raw.address:04X}" if raw.address is not None else "unknown address"
        body = rewrite_types(
            rewrite_identifiers(pretty_body(raw.body), self.name_map)
        )
        return "\n".join(
            [
                f"/* address {address} | recovered (pointer-returning signature) */",
                f"/* was {raw.name} in the dump; recover.parse's layout heuristic skips it */",
                self.raw_signature(raw),
                "{",
                body if body.strip() else "  /* empty body */",
                "}",
                "",
            ]
        )

    def externals_block(self) -> str:
        facts = self.facts
        lines = [
            "/* ---- routines outside every dump ------------------------------------",
            " * The decompiler resolved these call targets to addresses that",
            " * firmware/nm27c512n.hex does NOT cover (that image starts at 0x8000).",
            " * They live in the other half of the firmware.  Stubbed here so the",
            " * file type-checks; the bodies are NOT real and must not be trusted.",
            " */",
            "",
        ]
        for callee in sorted(facts.uncovered_calls):
            new = self.name_map.get(callee, map_identifier(callee)[0])
            args = ", ".join(f"unsigned int a{i + 1}" for i in range(_arg_count(facts, callee)))
            if callee.startswith("func_0x"):
                addr = int(callee[len("func_0x"):], 16)
                note = (
                    f"/* was {callee}: address 0x{addr:04X} is not covered by any dump "
                    f"(calls: {facts.uncovered_calls[callee]}) */"
                )
            else:
                note = (
                    f"/* was {callee}: not defined anywhere in the dump "
                    f"(calls: {facts.uncovered_calls[callee]}) */"
                )
            lines.append(note)
            lines.append(f"unsigned int {new}({args if args else 'void'})")
            lines.append("{")
            lines.append("  return 0;   /* placeholder - no real firmware at this address */")
            lines.append("}")
            lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------- whole
    def emit(self) -> str:
        self._collect()
        parts: List[str] = [
            self.header(),
            self.macros(),
            self.globals_block(),
            self.forward_declarations(),
        ]
        for func in self.facts.program.functions:
            parts.append(self.function_block(func))
        if self.facts.raw_only:
            parts.append(
                "/* ---- definitions the line-based splitter misses ---------------------\n"
                " * These have a pointer return type (``byte * FUN_CODE_xxxx``), which\n"
                " * the layout heuristic in recover.parse does not recognise as a\n"
                " * signature.  Their bodies are sliced straight out of the dump, so\n"
                " * they are real code. */\n"
            )
            for raw in self.facts.raw_only:
                parts.append(self.raw_function_block(raw))
        if self.facts.uncovered_calls:
            parts.append(self.externals_block())
        parts.append("#endif /* FIRMWARE_CLEAN_C */")
        parts.append("")
        return "\n".join(parts)


def emit_c(
    text: str,
    source_name: str = "",
    covered: Sequence[Tuple[int, int]] = ((DUMP_ROM_START, DUMP_ROM_END),),
) -> EmitResult:
    """Build the readable C reconstruction."""
    facts = analyse(text, source_name, covered)
    code = CProgram(facts, source_path=source_name).emit()
    stats = program_stats(facts)
    problems = check_balance(code)
    stats["balance_problems"] = problems
    stats["bytes"] = len(code)
    return EmitResult(path="firmware_clean.c", text=code, stats=stats, balance=problems)


# --------------------------------------------------------------- Python emitter
@dataclass
class RecoveredEntry:
    """One ``RECOVERED`` entry in ``firmware_recovered.py``."""

    name: str
    original_name: str
    address: Optional[int]
    params: List[str]
    source_body: str
    translated_ops: int
    status: str
    reason: str = ""
    callees: List[str] = field(default_factory=list)

    def to_literal(self, indent: str = "    ") -> str:
        params = ", ".join(repr(p) for p in self.params)
        callees = ", ".join(repr(c) for c in self.callees)
        lines = [
            f"{indent}{self.name!r}: {{",
            f"{indent}    \"name\": {self.name!r},",
            f"{indent}    \"original_name\": {self.original_name!r},",
            f"{indent}    \"address\": {self.address if self.address is not None else 'None'},",
            f"{indent}    \"params\": [{params}],",
            f"{indent}    \"translated_ops\": {self.translated_ops},",
            f"{indent}    \"status\": {self.status!r},",
        ]
        if self.reason:
            lines.append(f"{indent}    \"reason\": {self.reason!r},")
        if self.callees:
            lines.append(f"{indent}    \"callees\": [{callees}],")
        lines.append(f"{indent}    \"source_body\": {self.source_body!r},")
        lines.append(f"{indent}}},")
        return "\n".join(lines)


def _count_ops(body: str) -> int:
    """Statement/expression count of a body: a cheap 'translated ops' metric."""
    tokens = re.findall(r"[A-Za-z_]\w*|\d+|[^\sA-Za-z_0-9]", body)
    return sum(1 for t in tokens if t not in ("{", "}", ";", ",", "(", ")", " "))


def _status_of(func: Function, parsed_ok: Optional[bool], reason: str) -> str:
    if func.is_stub:
        return "stub"
    if parsed_ok is False:
        return "unparseable"
    if func.is_partial:
        return "partial"
    if "truncat" in reason.lower():
        return "truncated"
    return "ok"


def emit_python(
    text: str,
    source_name: str = "",
    covered: Sequence[Tuple[int, int]] = ((DUMP_ROM_START, DUMP_ROM_END),),
) -> EmitResult:
    """Build the machine-readable Python mirror of the dump."""
    from .cparse import ParseError, parse_body

    facts = analyse(text, source_name, covered)
    entries: Dict[str, RecoveredEntry] = {}
    ratio_ok = 0
    ratio_total = 0

    for func in facts.program.functions:
        new_name, _changed, _origin = map_identifier(func.name)
        reason = ""
        parsed_ok: Optional[bool] = None
        if func.is_stub:
            parsed_ok = True
            reason = "Ghidra halted on bytes that are not valid code"
        else:
            ratio_total += 1
            try:
                parse_body(func.body)
                parsed_ok = True
                ratio_ok += 1
            except (ParseError, ValueError, RecursionError) as exc:
                parsed_ok = False
                reason = f"{type(exc).__name__}: {exc}"
            if func.is_partial and parsed_ok:
                reason = (
                    f"executes {func.baddata_prefix} statements, then hits "
                    f"bad instruction data"
                )
        body = pretty_body(func.body)
        entries[new_name] = RecoveredEntry(
            name=new_name,
            original_name=func.name,
            address=func.address,
            params=[p.strip() for p in func.params],
            source_body=body,
            translated_ops=_count_ops(body),
            status=_status_of(func, parsed_ok, reason),
            reason=reason,
            callees=sorted(set(_CALL_RE.findall(body)) - _C_KEYWORDS),
        )

    for raw in facts.raw_only:
        new_name, _changed, _origin = map_identifier(raw.name)
        body = pretty_body(raw.body)
        entries[new_name] = RecoveredEntry(
            name=new_name,
            original_name=raw.name,
            address=raw.address,
            params=[p.strip() for p in raw.params.split(",") if p.strip()],
            source_body=body,
            translated_ops=_count_ops(body),
            status="ok",
            reason="found by emit's text scan; pointer-returning signature",
            callees=sorted(set(_CALL_RE.findall(body)) - _C_KEYWORDS),
        )

    lines: List[str] = [
        '"""Machine-readable mirror of the recovered firmware.',
        "",
        f"Generated by ``tools/recover_firmware.py emit`` from {source_name or '(stdin)'}.",
        "Do not edit by hand; regenerate instead.",
        "",
        "Status values",
        "-------------",
        "ok           the body parses and is backed by bytes at 0x8000..0xFFFF",
        "partial      real statements first, then halt_baddata: it runs up to the",
        "             marker and reports the gap exactly there",
        "stub         the body is *only* halt_baddata: nothing to execute",
        "truncated    the decompiler cut control flow short",
        "unparseable  recover.cparse rejected the body; see ``reason``",
        "",
        "``RECOVERED`` keys are the readable names also used in firmware_clean.c;",
        "``original_name`` is the identifier exactly as it appears in the dump.",
        '"""',
        "",
        f"SOURCE = {source_name!r}",
        f"DUMP_ROM = ({DUMP_ROM_START:#06x}, {DUMP_ROM_END:#06x})",
        "",
        "#: Ranges that no dump covers.  Code below 0x8000 is decompiler guesswork.",
        f"MISSING_RANGES = {missing_ranges(facts.covered)!r}",
        "",
        "#: Call targets outside every dump: name -> (address or None, call count)",
        "UNCOVERED_CALLS = {",
    ]
    for callee, count in sorted(facts.uncovered_calls.items()):
        if callee.startswith("func_0x"):
            addr = int(callee[len("func_0x"):], 16)
            lines.append(f"    {callee!r}: ({addr:#06x}, {count}),")
        else:
            lines.append(f"    {callee!r}: (None, {count}),")
    lines += [
        "}",
        "",
        "#: Renames performed by the emitter: Ghidra spelling -> readable name.",
        "RENAMES = {",
    ]
    for original in sorted(LEGACY_RENAME):
        lines.append(f"    {original!r}: {LEGACY_RENAME[original]!r},")
    lines += [
        "}",
        "",
        "STATS = {",
        f"    \"functions\": {len(entries)},",
        f"    \"recovered\": {sum(1 for e in entries.values() if e.status == 'ok')},",
        f"    \"partials\": {sum(1 for e in entries.values() if e.status == 'partial')},",
        f"    \"stubs\": {sum(1 for e in entries.values() if e.status == 'stub')},",
        f"    \"truncated\": {sum(1 for e in entries.values() if e.status == 'truncated')},",
        f"    \"unparseable\": {sum(1 for e in entries.values() if e.status == 'unparseable')},",
        f"    \"raw_scan_only\": {len(facts.raw_only)},",
        f"    \"globals\": {len(facts.program.globals)},",
        f"    \"uncovered_calls\": {len(facts.uncovered_calls)},",
        f"    \"body_parse_ratio\": ({ratio_ok}, {ratio_total}),",
        "}",
        "",
        "RECOVERED = {",
    ]
    for name in sorted(entries):
        lines.append(entries[name].to_literal())
    lines += [
        "}",
        "",
        "",
        "def by_address():",
        '    """address -> entry, for the functions whose address is known."""',
        '    return {e["address"]: e for e in RECOVERED.values() if e["address"] is not None}',
        "",
        "",
        "def stubs():",
        '    """Bodies that are *only* halt_baddata: nothing to execute."""',
        '    return sorted(n for n, e in RECOVERED.items() if e["status"] == "stub")',
        "",
        "",
        "def partials():",
        '    """Bodies that run until their halt_baddata() marker."""',
        '    return sorted(n for n, e in RECOVERED.items() if e["status"] == "partial")',
        "",
        "",
        "if __name__ == \"__main__\":",
        "    import json",
        "",
        "    print(json.dumps(STATS, indent=2, sort_keys=True))",
        "    print(\"missing ranges:\", MISSING_RANGES)",
        "",
    ]
    code = "\n".join(lines)
    stats = program_stats(facts)
    stats.update(
        {
            "entries": len(entries),
            "ok": sum(1 for e in entries.values() if e.status == "ok"),
            "partials": sum(1 for e in entries.values() if e.status == "partial"),
            "stubs": sum(1 for e in entries.values() if e.status == "stub"),
            "unparseable": sum(1 for e in entries.values() if e.status == "unparseable"),
            "body_parse_ratio": [ratio_ok, ratio_total],
            "bytes": len(code),
        }
    )
    return EmitResult(path="firmware_recovered.py", text=code, stats=stats)


def emit_all(
    text: str,
    source_name: str = "",
    covered: Sequence[Tuple[int, int]] = ((DUMP_ROM_START, DUMP_ROM_END),),
) -> Tuple[EmitResult, EmitResult]:
    """Build both artifacts without touching the filesystem."""
    return emit_c(text, source_name, covered), emit_python(text, source_name, covered)
