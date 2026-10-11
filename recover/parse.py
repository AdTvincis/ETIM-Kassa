"""Split the Ghidra pseudo-C dump into declarations and function definitions.

The dump has a very regular shape:

* a block of global declarations (``undefined1 DAT_INTMEM_3e;`` ...), including
  the decompiler's mangled bit names (``undefined 22.1;`` - not valid C at all);
* then, repeatedly: an optional ``// WARNING: ...`` comment, a function
  signature, a blank line, and a brace-balanced body.

No regular expression can match the body, so this module walks the text and
balances braces while respecting string and character literals.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__all__ = ["Function", "Program", "parse_dump", "MANGLED_BIT_RE"]

# ``undefined 22.1;`` -> global bit named "22.1"
MANGLED_BIT_RE = re.compile(r"^([A-Za-z_][\w]*)\s+(\d+)\.(\d+)\s*;\s*$")
DECL_RE = re.compile(
    r"^(?P<type>[A-Za-z_][\w]*)\s*(?P<stars>\**)\s*(?P<name>[A-Za-z_][\w]*)\s*(?P<array>\[[^\]]*\])?\s*;\s*$"
)

_SIG_RE = re.compile(
    # the return type may be a pointer: the dump has ``char * FUN_CODE_ea4f(...)``
    # and ``byte * FUN_CODE_f80d(...)``; without the ``\s*\*+`` those five
    # definitions were dropped and their call sites looked "undefined".
    r"^(?P<ret>[A-Za-z_][\w]*(?:\s*\*+)?)\s+(?P<name>[A-Za-z_][\w]*)\s*\((?P<params>[^;{}]*)\)\s*$"
)

_C_COMMENT = re.compile(r"//[^\n]*")
_C_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


@dataclass
class Global:
    """One global declaration from the dump."""

    name: str
    type: str
    stars: str = ""
    array: Optional[str] = None
    raw: str = ""
    #: for the decompiler's ``undefined 22.1;`` mangled bit names
    bit_of: Optional[Tuple[str, int]] = None

    @property
    def is_bit(self) -> bool:
        return self.bit_of is not None


@dataclass
class Function:
    """One recovered function."""

    name: str
    return_type: str
    params: List[str]
    body: str
    index: int
    address: Optional[int] = None
    #: lines of ``//`` comments that immediately preceded the signature
    warnings: List[str] = field(default_factory=list)
    #: labels in the body, in order of first appearance
    labels: List[str] = field(default_factory=list)
    #: ``(halt_baddata present?, executable statements before the first one)``,
    #: computed on first use by :meth:`baddata`
    _baddata: Optional[Tuple[bool, int]] = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def param_names(self) -> List[str]:
        names = []
        for p in self.params:
            p = p.strip()
            if not p:
                continue
            names.append(p.split()[-1].lstrip("*"))
        return names

    @property
    def baddata(self) -> Tuple[bool, int]:
        """``(is there a halt_baddata marker?, executable work before it)``.

        ``-1`` for the second element means "the body has a marker but could
        not be parsed"; such a body is classified as a full stub (nothing is
        executed from it) rather than guessed at.
        """
        if self._baddata is None:
            self._baddata = baddata_info(self.body)
        return self._baddata

    def preload_baddata(self, ast) -> None:
        """Classify on an AST the caller has *already* parsed.

        ``FunctionLibrary.load`` parses every body for execution anyway;
        without this hook the first ``is_stub``/``baddata_prefix`` read
        re-parsed the same text a second time (measured: ~2.3 s of the
        recovered backend's boot — see tools/_bench.py boot profiling).
        """
        if self._baddata is None:
            self._baddata = baddata_info(self.body, ast)

    @property
    def has_baddata(self) -> bool:
        """True when the decompiler halted on undecodable bytes in this body."""
        return self.baddata[0]

    @property
    def baddata_prefix(self) -> int:
        """Executable statements before the first bad-data marker (-1 unknown)."""
        return self.baddata[1]

    @property
    def is_stub(self) -> bool:
        """True only for a body that is *nothing but* bad data.

        Such a function has no executable prefix, so refusing it at the entry
        point loses nothing.  Bodies that do work before the marker used to be
        classified here too; they are :attr:`is_partial` now and run up to the
        point where the bytes stop making sense.
        """
        has, work = self.baddata
        return has and work <= 0

    @property
    def is_partial(self) -> bool:
        """True for "bad-data inside": real code before the marker, gap after."""
        has, work = self.baddata
        return has and work > 0

    @property
    def is_recovered(self) -> bool:
        """True when the whole body is backed by real bytes (no bad-data marker)."""
        return (not self.has_baddata) and self.address is not None and self.address >= 0x8000


def baddata_info(body: str, ast=None) -> Tuple[bool, int]:
    """Classify one body: ``(marker present, executable statements before it)``.

    The marker is found textually (``halt_baddata()`` is unambiguous), but the
    work *before* it has to be counted on the AST: text counting cannot tell a
    declaration (``char cVar1;``) from a statement, and it cannot see a
    ``return`` nested inside an ``if`` (``FUN_CODE_e8f8`` has exactly that and
    is a partial, not a stub).

    ``ast`` lets a caller that parsed this very body already (the loader does)
    hand the tree over instead of paying for a second parse of the same text.
    """
    if "halt_baddata()" not in body:
        return False, 0
    if ast is None:
        try:
            from .cparse import parse_body

            ast = parse_body(body)
        except Exception:                        # noqa: BLE001 - conservative
            return True, -1
    work = _work_before(ast)
    return True, work


def _work_before(ast) -> int:
    """Executable statements before the first ``halt_baddata()`` call (-1 if none)."""
    from .cparse import Expr

    count = 0

    def halt_in(expr) -> bool:
        if expr is None:
            return False
        if isinstance(expr, Expr):
            if expr.kind == "call":
                callee = expr.a
                if getattr(callee, "kind", None) == "var" and callee.a in (
                    "halt_baddata",
                    "__halt",
                ):
                    return True
            for attr in ("a", "b", "c"):
                child = getattr(expr, attr, None)
                if isinstance(child, Expr):
                    if halt_in(child):
                        return True
                elif isinstance(child, (list, tuple)):
                    if any(isinstance(item, Expr) and halt_in(item) for item in child):
                        return True
            return False
        return False

    def scan(stmt) -> bool:
        """Walk in source order; ``True`` means the marker was reached."""
        nonlocal count
        kind = stmt.kind
        if kind in ("decl", "label", "empty"):
            return False                         # declarations are not "work"
        if kind in ("expr", "assign", "return"):
            if halt_in(stmt.expr):
                return True                      # the marker itself: stop here
            count += 1
            return False
        if kind in ("goto", "break", "continue"):
            count += 1
            return False
        if kind == "block":
            for item in stmt.items:
                if scan(item):
                    return True
            return False
        if kind == "if":
            if halt_in(stmt.expr):
                return True
            if stmt.body is not None and scan(stmt.body):
                return True
            return stmt.els is not None and scan(stmt.els)
        if kind in ("while", "do"):
            if halt_in(stmt.expr):
                return True
            return stmt.body is not None and scan(stmt.body)
        if kind == "for":
            for part in (stmt.init, stmt.expr, stmt.step):
                if halt_in(part):
                    return True
            return stmt.body is not None and scan(stmt.body)
        if kind == "switch":
            if halt_in(stmt.expr):
                return True
            if stmt.body is not None and scan(stmt.body):
                return True
            for case in stmt.items:
                if scan(case):
                    return True
            return False
        count += 1
        return False

    if not scan(ast):
        return -1                                # marker only in text, not in AST
    return count


_KNOWN_MANGLED_BIT_PREFIXES = None


def _strip_comments_preserving_lines(text: str) -> str:
    """Remove ``//`` comments but keep the lines they were on."""
    out_lines = []
    for line in text.splitlines():
        out_lines.append(_C_COMMENT.sub("", line))
    return "\n".join(out_lines)


#: следующая «специальная» скобка/кавычка — прыжок на C-скорости вместо
#: покадрового обхода тела функции (тела весят килобайты; бут: 600K итераций)
_SPECIAL_RE = re.compile(r"[{}\"']")


def _find_matching_brace(text: str, open_index: int) -> int:
    """Index of the ``}`` matching the ``{`` at ``open_index``."""
    depth = 0
    i = open_index
    n = len(text)
    search = _SPECIAL_RE.search
    while True:
        m = search(text, i)
        if m is None:
            break
        i = m.start()
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif ch == "'":
            i += 1
            while i < n and text[i] != "'":
                i += 2 if text[i] == "\\" else 1
        elif ch == "{":
            depth += 1
        else:                                     # "}"
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced braces")


@dataclass
class Program:
    """Everything recovered from one dump."""

    globals: List[Global] = field(default_factory=list)
    functions: List[Function] = field(default_factory=list)
    #: ``// WARNING:`` comments that were not attached to a function
    loose_warnings: List[str] = field(default_factory=list)
    source_name: str = ""

    def by_name(self) -> Dict[str, Function]:
        return {f.name: f for f in self.functions}

    def stats(self) -> Dict[str, int]:
        """Totals.

        Every function falls in exactly one bucket:

        ``recovered``  no bad-data marker - the whole body is real bytes;
        ``partials``   real code *before* the first ``halt_baddata()``, gap after;
        ``stubs``      nothing but bad data - nothing to execute.
        """
        recovered = [f for f in self.functions if f.is_recovered]
        stubs = [f for f in self.functions if f.is_stub]
        partials = [f for f in self.functions if f.is_partial]
        return {
            "functions": len(self.functions),
            "recovered": len(recovered),
            "stubs": len(stubs),
            "partials": len(partials),
            "globals": len(self.globals),
            "bit_globals": sum(1 for g in self.globals if g.is_bit),
        }

    def call_targets(self) -> Dict[str, int]:
        """How often each function is called from another function body."""
        counts: Dict[str, int] = {f.name: 0 for f in self.functions}
        for fn in self.functions:
            for name in counts:
                counts[name] += len(re.findall(r"\b" + name + r"\s*\(", fn.body))
            # self-recursion counted above; undo the definition-irrelevant ones
        return counts


def parse_dump(text: str, source_name: str = "") -> Program:
    """Parse a Ghidra pseudo-C dump into a :class:`Program`."""
    program = Program(source_name=source_name)
    code = _strip_comments_preserving_lines(text)
    lines = code.splitlines()
    # Символьные смещения начала каждой строки: O(n) один раз.  Раньше каждая
    # функция считала своё смещение как sum(len(x)+1 for x in lines[:k]) —
    # квадратично: 850K итераций генexpr на дампе (замерено cProfile бута).
    _line_off = [0] * (len(lines) + 1)
    for _k, _ln in enumerate(lines):
        _line_off[_k + 1] = _line_off[_k] + len(_ln) + 1

    # ---- pass 1: global declarations up to the first function signature
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i].rstrip()
        stripped = raw.strip()
        if not stripped:
            i += 1
            continue
        head, _brace_line = _collect_signature(lines, i)
        if head is not None and _SIG_RE.match(head):
            break
        if stripped.startswith("//"):
            program.loose_warnings.append(stripped)
            i += 1
            continue
        # a declaration?
        bm = MANGLED_BIT_RE.match(stripped)
        dm = DECL_RE.match(stripped)
        bm2 = re.match(r"^undefined1?\s+([A-Za-z_]\w*)\.(\d+)\s*;$", stripped)
        if bm:
            program.globals.append(
                Global(name=f"{bm.group(2)}.{bm.group(3)}", type=bm.group(1), raw=stripped,
                       bit_of=(bm.group(1), int(bm.group(3))))
            )
        elif bm2:
            program.globals.append(
                Global(name=f"{bm2.group(1)}.{bm2.group(2)}", type="undefined",
                       raw=stripped, bit_of=(bm2.group(1), int(bm2.group(2))))
            )
        elif dm and dm.group("name") not in ("return",):
            program.globals.append(
                Global(name=dm.group("name"), type=dm.group("type"),
                       stars=dm.group("stars") or "", array=dm.group("array"), raw=stripped)
            )
        elif stripped.startswith("typedef"):
            program.globals.append(Global(name="", type="typedef", raw=stripped))
        else:
            program.loose_warnings.append(stripped)
        i += 1

    # ---- pass 2: function definitions, brace balanced
    #
    # Signatures are sometimes wrapped over several lines by the decompiler and
    # are almost always followed by a blank line before the ``{``, so we join
    # text from the candidate start until the opening brace and then match.
    pending_warnings: List[str] = []
    while i < n:
        stripped = lines[i].strip()
        if stripped.startswith("//"):
            pending_warnings.append(stripped[2:].strip())
            i += 1
            continue
        if not stripped:
            i += 1
            continue

        head, brace_line = _collect_signature(lines, i)
        if head is None:
            pending_warnings.clear()
            i += 1
            continue
        m = _SIG_RE.match(head)
        if not m or m.group("name") in ("if", "while", "for", "switch", "return"):
            pending_warnings.clear()
            i += 1
            continue

        stripped_offset = _line_off[brace_line]
        brace_index = code.index("{", stripped_offset)
        close_index = _find_matching_brace(code, brace_index)
        body = code[brace_index + 1 : close_index]
        flatten = lambda s: " ".join(s.split())
        params = [flatten(p) for p in m.group("params").split(",") if p.strip()]
        fn = Function(
            name=m.group("name"),
            return_type=m.group("ret"),
            params=params,
            body=body,
            index=len(program.functions),
            warnings=list(pending_warnings),
        )
        pending_warnings.clear()
        # Extract the ROM address from names like FUN_CODE_810f and
        # thunk_FUN_CODE_b904 (Ghidra emits ``thunk_`` for tail-jump shims,
        # but the address is still real and must not be lost).
        am = re.search(r"FUN_CODE_([0-9a-fA-F]{4})\b", fn.name)
        if am:
            fn.address = int(am.group(1), 16)
        fn.labels = _collect_labels(body)
        program.functions.append(fn)
        i = code.count("\n", 0, close_index) + 1

    return program


def _collect_signature(lines: List[str], start: int, lookahead: int = 8):
    """Join continuation lines of a signature until the opening brace.

    Returns ``(signature_text, index_of_brace_line)`` or ``(None, -1)``.
    """
    parts: List[str] = []
    for j in range(start, min(start + lookahead, len(lines))):
        candidate = lines[j].strip()
        if candidate == "{":
            if not parts:
                return None, -1
            return " ".join(parts), j
        if candidate.endswith(";") or candidate.startswith("//"):
            return None, -1
        if candidate:
            parts.append(candidate)
    return None, -1


def _collect_labels(body: str) -> List[str]:
    seen: List[str] = []
    for m in re.finditer(r"\b(LAB_CODE_[0-9a-fA-F]+)\b\s*:", body):
        if m.group(1) not in seen:
            seen.append(m.group(1))
    return seen
