"""Execute the recovered AST.

This is a small statement interpreter, not generated Python, for three
reasons:

* recovered code contains ``goto`` into the middle of other functions;
* the decompiler's variable set is dynamic (``uVar7`` may be a byte in one
  function and a pointer in another);
* when execution needs code the dump has no bytes for (addresses below record
  ``0x8000`` - decompiler guesswork), the
  interpreter can raise :class:`~recover.errors.MissingFirmware` with the exact
  address instead of quietly computing nonsense.

Memory access goes through the :class:`~recover.namespace.Machine` proxies, so
the recovered logic reads and writes the same 8051 state that
:mod:`m8051` emulates.

Execution model
---------------
A :class:`_Frame` is one nesting level: a statement list plus a cursor.  The
cursor of the active frame is advanced *before* the statement is dispatched.

**Loops.** ``while``/``for`` test their condition *before* the first
iteration (:meth:`Interpreter._enter_loop`) and again after every completed
body, together with the ``for`` step (:meth:`Interpreter._loop_tail`); ``do``
tests only afterwards.  ``break`` drops the innermost loop *or switch* frame,
``continue`` finishes the innermost loop body so that the same tail logic runs
the step and the condition.

**Labels.** Every label is recorded as ``(statement list, index)`` plus a
parent link for the block it lives in, so ``goto`` can (a) unwind to a frame
that is already on the stack, (b) rebuild the chain of blocks from the
function root when the target block has not been entered yet, or (c) - the
decompiler does emit these - leave the function and continue inside whichever
other dumped function defines the label.  A label no dumped function defines
reports :class:`~recover.errors.MissingFirmware` instead of silently doing
nothing (which would spin for ever).

**Indirect calls.** ``(*(code *)(addr))(args)`` calls the routine *at* the
computed address: the address is dispatched through
:meth:`Interpreter.call_by_address`, and an address no dump defines reports
``MissingFirmware`` rather than being treated as "call 0".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .cparse import Expr, ParseError, Stmt, parse_body
from .errors import MissingFirmware, UnmappedRegister
from .namespace import BitAddress, CodeCell, Machine, RAMCell, SFR, SFR_NAMES, XdataCell
from .runtime import RuntimeHelpers

__all__ = ["Interpreter", "RecoveredFunction", "FunctionLibrary", "Pointer", "Global"]

_POINTER_BASE = 0x10000_0000          # synthetic base for fake pointers
_POINTER_SPAN = 0x10000

#: C macro constants the decompiler uses as free identifiers (``while(true)``).
#: These are language constants, not machine locations: 277 occurrences in the
#: dump, and reading them as variables would be a translation gap, not a
#: firmware gap.
_C_CONSTANTS: Dict[str, int] = {"true": 1, "false": 0}


class Pointer:
    """A stand-in for a C pointer.

    The decompiler turns integers into pointers freely (``(byte *)0x1234``), and
    the recovered code dereferences them with ``*`` and indexes them with
    ``[i]``.  Rather than pretend the model has an address space, a pointer
    knows the space it belongs to and reads/writes through a callback, which
    keeps xdata/SFR/RAM accesses honest.
    """

    __slots__ = ("space", "addr", "reader", "writer", "tag")

    def __init__(self, space: str, addr: int, reader=None, writer=None, tag: str = "") -> None:
        self.space = space
        self.addr = addr & 0xFFFF
        self.reader = reader
        self.writer = writer
        self.tag = tag

    def offset(self, delta: int) -> "Pointer":
        return Pointer(self.space, (self.addr + delta) & 0xFFFF,
                       self.reader, self.writer, self.tag)

    def __int__(self) -> int:
        return self.addr

    def __index__(self) -> int:
        return self.addr

    def __bool__(self) -> bool:
        return True

    def __eq__(self, other) -> bool:                      # type: ignore[override]
        if isinstance(other, Pointer):
            return self.space == other.space and self.addr == other.addr
        return self.addr == (int(other) & 0xFFFF if isinstance(other, int) else other)

    def __hash__(self) -> int:
        return hash((self.space, self.addr))

    def __repr__(self) -> str:
        return f"&{self.space}[{self.addr:#06x}]{'<' + self.tag + '>' if self.tag else ''}"


class _Return(Exception):
    def __init__(self, value: Any) -> None:
        self.value = value


class _Goto(Exception):
    def __init__(self, label: str) -> None:
        self.label = label


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


@dataclass
class _Frame:
    """One nesting level of execution: a statement list plus a cursor."""

    stmts: Sequence[Stmt]
    i: int = 0
    kind: str = "block"
    data: Dict[str, Any] = field(default_factory=dict)


class Interpreter:
    """Runs one recovered function against a :class:`Machine`."""

    def __init__(self, machine: Machine, helpers: RuntimeHelpers) -> None:
        self.machine = machine
        self.helpers = helpers
        self.globals: Dict[str, Global] = {}
        #: symbols the dump declares but never locates (``RXSTAT``); reading one
        #: raises :class:`~recover.errors.UnmappedRegister`
        self.unmapped: Dict[str, str] = {}
        #: set by :class:`FunctionLibrary` so ``goto`` can jump between functions
        self.library: Optional["FunctionLibrary"] = None
        self.max_steps = 2_000_000
        self.steps = 0
        self.call_depth = 0
        self.max_depth = 40
        self.current: Optional[str] = None
        self.trace: Optional[List[str]] = None
        self.trace_limit = 4000

    # ------------------------------------------------------------------ calling
    def call(self, func: "RecoveredFunction", *args) -> Any:
        return func.invoke(self, list(args))

    # ------------------------------------------------------------------ frames
    @staticmethod
    def _fresh_locals(func: "RecoveredFunction", args: Optional[List[Any]] = None) -> Dict[str, Any]:
        """The local environment a function body starts with."""
        args = args or []
        locals_: Dict[str, Any] = {}
        # the decompiler sometimes leaves a parameter undeclared inside the body,
        # so every function starts with a defined value for each of its names
        for name in func.param_names:
            locals_[name] = 0
        for name, _type in func.declarations:
            locals_.setdefault(name, 0)
        # fill in the arguments, tolerating both too few and too many
        for index, name in enumerate(func.param_names):
            locals_[name] = args[index] if index < len(args) else 0
        for index, value in enumerate(args):
            locals_[f"param_{index + 1}"] = value
        return locals_

    def execute_body(self, body: Stmt, func: "RecoveredFunction", args: List[Any]) -> Any:
        locals_ = self._fresh_locals(func, args)
        frames: List[_Frame] = [_Frame(body.items, kind="fn", data={"locals": locals_, "func": func})]
        self.steps = 0
        try:
            return self._run(frames)
        except _Return as done:
            return done.value

    def _locals(self, frames: List[_Frame]) -> Dict[str, Any]:
        return frames[0].data["locals"]

    def _run(self, frames: List[_Frame]) -> Any:
        """Execute statement lists until the outermost frame finishes.

        The cursor of the active frame is advanced **before** the statement is
        dispatched.  That is what makes straight-line code work: if ``_run`` only
        advanced the parent when a child frame popped, every simple statement
        (``x = y;``) would be re-executed for ever.
        """
        while frames:
            self.steps += 1
            if self.steps > self.max_steps:
                raise RuntimeError(
                    f"recovered function {self.current} exceeded {self.max_steps} steps"
                )
            frame = frames[-1]
            if frame.i >= len(frame.stmts):
                # The statement list is finished.  If it was a loop body, the
                # loop has to run its step and re-test its condition - that is
                # decided by _loop_tail on the frame that just finished, not on
                # the frame below it.
                finished = frames.pop()
                self._loop_tail(finished, frames)
                continue

            stmt = frame.stmts[frame.i]
            frame.i += 1
            if self.trace is not None and len(self.trace) < self.trace_limit:
                self.trace.append(f"{self.current}:{stmt.kind}#{stmt.pos}")
            try:
                self._step(stmt, frames)
            except _Goto as jump:
                self._goto(frames, jump.label)
            except _Break:
                self._unwind_break(frames)
            except _Continue:
                self._unwind_continue(frames)
        return 0

    # ------------------------------------------------------------------ goto
    def _goto(self, frames: List[_Frame], label: str) -> None:
        """Continue execution at ``label``.

        Three cases, in order: the label is in a statement list that is already
        on the stack (unwind to it); it is in this function but in a block that
        has not been entered (rebuild the block chain from the root); or it
        belongs to another function entirely (switch execution context - the
        machine's PC just jumps there).
        """
        func = frames[0].data.get("func")
        site = func.labels.get(label) if func is not None else None
        if site is not None:
            if self._rebuild(frames, site, func):
                return
            raise MissingFirmware(
                -1,
                f"goto {label}: the label exists in {getattr(func, 'name', '?')} "
                f"but its statement list cannot be reached",
            )

        target = self._find_label_elsewhere(label, func)
        if target is None:
            key = f"goto_{label}"
            self.machine.missing_calls[key] = self.machine.missing_calls.get(key, 0) + 1
            raise MissingFirmware(
                -1,
                f"goto {label}: no function in the dump defines this label "
                f"(the jump would leave {getattr(func, 'name', 'the function')})",
            )

        target_fn, target_site = target
        root = _Frame(
            target_fn.ast.items,
            kind="fn",
            data={"locals": self._fresh_locals(target_fn), "func": target_fn},
        )
        frames[:] = [root]
        self.current = target_fn.name
        if not self._rebuild(frames, target_site, target_fn):
            raise MissingFirmware(
                -1,
                f"goto {label}: its block in {target_fn.name} cannot be reached",
            )

    def _find_label_elsewhere(
        self, label: str, current: Optional["RecoveredFunction"]
    ) -> Optional[Tuple["RecoveredFunction", Tuple[Sequence[Stmt], int]]]:
        """The one other dumped function that defines ``label``, if unique."""
        if self.library is None:
            return None
        found: List[Tuple["RecoveredFunction", Tuple[Sequence[Stmt], int]]] = []
        for candidate in self.library.functions.values():
            if candidate is current or candidate.is_stub:
                continue
            site = candidate.labels.get(label)
            if site is not None:
                found.append((candidate, site))
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            names = ", ".join(sorted(fn.name for fn, _site in found))
            raise MissingFirmware(
                -1, f"goto {label}: defined by several functions ({names}) - ambiguous"
            )
        return None

    def _rebuild(
        self,
        frames: List[_Frame],
        site: Tuple[Sequence[Stmt], int],
        func: "RecoveredFunction",
    ) -> bool:
        """Transfer execution to ``site``; ``False`` when it is unreachable."""
        stmts, index = site
        # (a) the statement list is already executing - unwind to it
        for depth in range(len(frames) - 1, -1, -1):
            if frames[depth].stmts is stmts:
                del frames[depth + 1:]
                frames[depth].i = index
                return True
        # (b) rebuild the chain of enclosing blocks from the function root
        chain: List[Tuple[Sequence[Stmt], int, Sequence[Stmt]]] = []
        cursor = stmts
        while True:
            info = func.parents.get(id(cursor))
            if info is None:
                break
            parent_list, parent_index = info
            chain.append((parent_list, parent_index, cursor))
            cursor = parent_list
        if cursor is not frames[0].stmts:
            return False
        chain.reverse()
        root = frames[0]
        frames[:] = [root]
        for parent_list, parent_index, child in chain:
            # when the nested block finishes, execution resumes after it
            frames[-1].i = parent_index + 1
            frame = self._resume_frame(parent_list[parent_index], child)
            if child is stmts:
                frame.i = index
            frames.append(frame)
        return True

    @staticmethod
    def _resume_frame(stmt: Stmt, child: Sequence[Stmt]) -> _Frame:
        """The frame runtime pushes for ``stmt``'s body ``child``.

        Used when a goto enters a block the execution has not reached: loops get
        their kind and condition back so :meth:`_loop_tail` keeps driving them,
        conditions are skipped (a goto jumps *into* the body regardless of the
        test), and plain blocks are plain frames.
        """
        if stmt.kind in ("while", "for"):
            return _Frame(child, kind="loop", data={"cond": stmt.expr, "step": stmt.step})
        if stmt.kind == "do":
            return _Frame(child, kind="doloop", data={"cond": stmt.expr, "step": stmt.step})
        if stmt.kind == "switch":
            return _Frame(child, kind="switch")
        return _Frame(child)

    # ---------------------------------------------------------- break/continue
    @staticmethod
    def _unwind_break(frames: List[_Frame]) -> None:
        """``break`` exits the innermost loop **or switch** (C semantics)."""
        for index in range(len(frames) - 1, -1, -1):
            if frames[index].kind in ("loop", "doloop", "switch"):
                del frames[index:]
                return
        # an unmatched break must not hang the machine
        frames.clear()

    @staticmethod
    def _unwind_continue(frames: List[_Frame]) -> None:
        """``continue`` finishes the innermost loop body.

        The cursor is pushed to the end of the body so that the normal
        end-of-list path runs :meth:`_loop_tail` - that is what makes the
        ``for`` step execute, and what re-tests the condition for ``while`` and
        ``do``.
        """
        for index in range(len(frames) - 1, -1, -1):
            if frames[index].kind in ("loop", "doloop"):
                del frames[index + 1:]
                frames[index].i = len(frames[index].stmts)
                return
        frames.clear()

    def _loop_tail(self, finished: _Frame, frames: List[_Frame]) -> None:
        """A statement list just finished; drive the loop it belonged to.

        ``finished`` is the frame that was popped.  When it is a loop body the
        ``for`` step runs first and then the condition decides whether the body
        is re-pushed (with its cursor rewound to 0).
        """
        kind = finished.kind
        if kind == "loop":
            step = finished.data.get("step")
            if step is not None:
                self.eval(step, frames)
            condition = finished.data.get("cond")
            if condition is None or self.truth(self.eval(condition, frames)):
                finished.i = 0
                frames.append(finished)
        elif kind == "doloop":
            condition = finished.data.get("cond")
            if self.truth(self.eval(condition, frames)):
                finished.i = 0
                frames.append(finished)

    # ---------------------------------------------------------------- dispatch
    def _step(self, stmt: Stmt, frames: List[_Frame]) -> bool:
        kind = stmt.kind
        if kind == "empty" or kind == "label":
            return True
        if kind == "block":
            frames.append(_Frame(stmt.items))
            return True
        if kind == "decl":
            locals_ = self._locals(frames)
            for name, _type in stmt.vars:
                locals_.setdefault(name, 0)
            return True
        if kind == "expr":
            self.eval(stmt.expr, frames)
            return True
        if kind == "assign":
            self.assign(stmt.expr, frames)
            return True
        if kind == "return":
            value = self.eval(stmt.expr, frames) if stmt.expr is not None else 0
            raise _Return(value)
        if kind == "goto":
            raise _Goto(stmt.name)
        if kind == "break":
            raise _Break()
        if kind == "continue":
            raise _Continue()
        if kind == "if":
            if self.truth(self.eval(stmt.expr, frames)):
                frames.append(_Frame([stmt.body] if stmt.body.kind != "block" else stmt.body.items))
            elif stmt.els is not None:
                els = stmt.els
                frames.append(_Frame([els] if els.kind != "block" else els.items))
            return True
        if kind == "while":
            self._enter_loop(stmt, frames, check_first=True)
            return True
        if kind == "do":
            self._enter_loop(stmt, frames, check_first=False)
            return True
        if kind == "for":
            if stmt.init is not None:
                self.eval(stmt.init, frames)
            self._enter_loop(stmt, frames, check_first=True)
            return True
        if kind == "switch":
            subject = self.eval(stmt.expr, frames) & 0xFF
            target = None
            for value_expr, body in zip(stmt.init, stmt.items):
                if value_expr is None:
                    continue
                if (self.eval(value_expr, frames) & 0xFF) == subject:
                    target = body
                    break
            if target is None:
                for value_expr, body in zip(stmt.init, stmt.items):
                    if value_expr is None:
                        target = body
                        break
            if target is not None:
                # kind="switch" so that a ``break`` inside a case leaves the
                # switch and not the enclosing loop
                frames.append(
                    _Frame([target] if target.kind != "block" else target.items,
                           kind="switch")
                )
            return True
        raise RuntimeError(f"cannot execute statement kind {kind!r}")

    def _enter_loop(self, stmt: Stmt, frames: List[_Frame], check_first: bool) -> None:
        """Enter a loop body; :meth:`_loop_tail` drives every later iteration.

        ``check_first`` is true for ``while``/``for``: their condition decides
        *before* the first iteration whether the body runs at all (a ``while``
        whose condition is false from the start must run zero times).  ``do``
        starts unconditionally and is tested by the tail.
        """
        body = stmt.body
        body_list = [body] if body.kind != "block" else body.items
        if check_first and stmt.expr is not None:
            if not self.truth(self.eval(stmt.expr, frames)):
                return
        frames.append(_Frame(
            body_list,
            kind="loop" if check_first else "doloop",
            data={"cond": stmt.expr, "step": stmt.step},
        ))

    # -------------------------------------------------------------- evaluation
    def eval(self, expr: Optional[Expr], frames: List[_Frame]) -> Any:
        if expr is None:
            return 0
        kind = expr.kind
        if kind == "const":
            return expr.a
        if kind == "str":
            return expr.a
        if kind == "var":
            return self.lookup(expr.a, frames)
        if kind == "cast":
            value = self.eval(expr.a, frames)
            return self._apply_cast(expr.c, value)
        if kind == "cast_raw":
            return 0
        if kind == "un":
            op = expr.c
            if op == "&":
                # ``&DAT_INTMEM_50`` must yield a *pointer with a space*, not a
                # bare integer: the bodies dereference the result
                # (``pbVar1 = &DAT_INTMEM_50; *pbVar1 = ...``) and an integer
                # would fall back to whatever default the deref picks.
                return self._pointer_of(self.lvalue(expr.a, frames))
            if op == "*":
                return self.deref(self.eval(expr.a, frames))
            value = self.eval(expr.a, frames)
            if op == "-":
                return -int(value) if not isinstance(value, Pointer) else value
            if op == "+":
                return value
            if op == "!":
                return 0 if self.truth(value) else 1
            if op == "~":
                return (~int(value)) & 0xFFFF
            raise RuntimeError(f"unhandled unary {op}")
        if kind == "bin":
            return self._binary(expr, frames)
        if kind == "assign":
            return self.assign(expr, frames)
        if kind == "preinc" or kind == "postinc":
            return self._incdec(expr, frames)
        if kind == "cond":
            if self.truth(self.eval(expr.a, frames)):
                return self.eval(expr.b, frames)
            return self.eval(expr.c, frames)
        if kind == "comma":
            self.eval(expr.a, frames)
            return self.eval(expr.b, frames)
        if kind == "index":
            base = self.eval(expr.a, frames)
            index = int(self.eval(expr.b, frames))
            if isinstance(base, Pointer):
                return self.deref(base.offset(index))
            # No space marker on a bare integer: use the same default as
            # deref() does (xdata), never a different one - the two used to
            # disagree (index -> ram, deref -> xdata), so ``p[i]`` and ``*p``
            # could land in different address spaces.
            return self.deref(Pointer("xdata", int(base) + index))
        if kind == "field":
            base = self.eval(expr.a, frames)
            if isinstance(base, Pointer):
                return self.deref(base)
            return 0
        if kind == "call":
            return self._call(expr, frames)
        raise RuntimeError(f"unhandled expression kind {kind!r}")

    def _binary(self, expr: Expr, frames: List[_Frame]) -> Any:
        op = expr.c
        # short circuit
        if op == "&&":
            return 1 if (self.truth(self.eval(expr.a, frames))
                         and self.truth(self.eval(expr.b, frames))) else 0
        if op == "||":
            return 1 if (self.truth(self.eval(expr.a, frames))
                         or self.truth(self.eval(expr.b, frames))) else 0
        left = self.eval(expr.a, frames)
        right = self.eval(expr.b, frames)
        if op == "+":
            if isinstance(left, Pointer):
                return left.offset(int(right))
            if isinstance(right, Pointer):
                return right.offset(int(left))
            return (int(left) + int(right)) & 0xFFFF
        if op == "-":
            if isinstance(left, Pointer):
                return left.offset(-int(right))
            return (int(left) - int(right)) & 0xFFFF
        a, b = int(left) & 0xFFFF, int(right) & 0xFFFF
        if op == "*":
            return (a * b) & 0xFFFF
        if op == "/":
            return 0 if b == 0 else (a // b) & 0xFFFF
        if op == "%":
            return 0 if b == 0 else (a % b) & 0xFFFF
        if op == "&":
            return a & b
        if op == "|":
            return a | b
        if op == "^":
            return a ^ b
        if op == "<<":
            return (a << (b & 15)) & 0xFFFF
        if op == ">>":
            return (a >> (b & 15)) & 0xFFFF
        if op == "==":
            return 1 if a == b else 0
        if op == "!=":
            return 1 if a != b else 0
        if op == "<":
            return 1 if a < b else 0
        if op == "<=":
            return 1 if a <= b else 0
        if op == ">":
            return 1 if a > b else 0
        if op == ">=":
            return 1 if a >= b else 0
        raise RuntimeError(f"unhandled binary operator {op!r}")

    def _apply_cast(self, cast: str, value: Any) -> Any:
        if cast.endswith("*"):
            if isinstance(value, Pointer):
                return value
            base = cast[:-1].strip()
            # ``(code *)addr`` marks an address in *program* memory: dereferencing
            # it is a MOVC (and calling it is an indirect jump), not a MOVX.
            space = "code" if base == "code" else "xdata"
            return Pointer(space, int(value) & 0xFFFF)
        if isinstance(value, Pointer):
            return value.addr
        text = cast.replace(" ", "")
        if text in ("char", "signedchar", "undefined1", "byte", "unsignedchar", "sbyte", "bool"):
            value = int(value) & 0xFF
            if text in ("char", "signedchar", "sbyte"):
                return value - 256 if value > 127 else value
            return value
        if "int" in text or "word" in text or "long" in text or "short" in text:
            return int(value) & 0xFFFF
        return int(value) & 0xFF

    def _incdec(self, expr: Expr, frames: List[_Frame]) -> int:
        target = expr.a
        value = int(self.eval(target, frames))
        delta = 1 if expr.c == "++" else -1
        new = (value + delta) & 0xFFFF
        self.store(target, new, frames)
        return new if expr.kind == "preinc" else value

    # ------------------------------------------------------------- lvalues
    def lvalue(self, expr: Expr, frames: List[_Frame]) -> Any:
        """Return a settable proxy for ``expr``."""
        if expr.kind == "un" and expr.c == "*":
            return self._deref_target(self.eval(expr.a, frames))
        if expr.kind == "index":
            base = self.eval(expr.a, frames)
            index = int(self.eval(expr.b, frames))
            # same default space as deref()/_deref_target() (xdata); the old
            # "ram" here disagreed with them for a bare integer base
            pointer = base if isinstance(base, Pointer) else Pointer("xdata", int(base))
            return self._deref_target(pointer.offset(index))
        if expr.kind == "var":
            name = expr.a
            locals_ = self._locals(frames)
            if name in locals_:
                return _LocalCell(locals_, name)
            machine = self.machine
            if name in machine.proxy_cache:
                return machine.proxy_cache[name]
            proxy = self._make_proxy(name)
            machine.proxy_cache[name] = proxy
            return proxy
        raise RuntimeError(f"expression {expr.kind!r} is not assignable")

    def _deref_target(self, pointer: Any) -> Any:
        if not isinstance(pointer, Pointer):
            pointer = Pointer("xdata", int(pointer) & 0xFFFF)
        return _MemoryCell(self.machine, pointer.space, pointer.addr, self)

    def _pointer_of(self, cell: Any) -> Pointer:
        """``&x``: the address of a named cell, *with* its address space.

        The dump takes the address of globals only (every ``&`` target is a
        ``DAT_INTMEM_``/``DAT_EXTMEM_``/``BANKn_Rm`` cell), and the bodies then
        dereference the result, so the space has to survive: ``&DAT_INTMEM_50``
        is RAM, ``&DAT_EXTMEM_0c7a`` is external memory, ``&P1`` is an SFR.
        """
        if isinstance(cell, Pointer):
            return cell
        if isinstance(cell, RAMCell):
            return Pointer("ram", cell.addr, tag="&iram")
        if isinstance(cell, XdataCell):
            return Pointer("xdata", cell.addr, tag="&xdata")
        if isinstance(cell, SFR):
            return Pointer("sfr", cell.addr, tag="&sfr")
        if isinstance(cell, CodeCell):
            return Pointer("code", cell.addr, tag="&code")
        if isinstance(cell, BitAddress):
            # a bit has no address of its own; its *container byte* does
            space = "sfr" if cell.byte >= 0x80 else "ram"
            return Pointer(space, cell.byte, tag="&bit")
        if isinstance(cell, _MemoryCell):
            return Pointer(cell.space, cell.addr, tag="&mem")
        if isinstance(cell, _LocalCell):
            raise RuntimeError(
                "cannot take the address of a local frame variable: the "
                "decompiler only ever takes the address of globals"
            )
        raise RuntimeError(f"cannot take the address of {type(cell).__name__}")

    def _proxy_for(self, g: "Global"):
        machine = self.machine
        if g.space == "ram":
            return RAMCell(machine, g.addr)
        if g.space == "xdata":
            return XdataCell(machine, g.addr)
        if g.space == "sfr":
            return SFR(machine, g.addr)
        if g.space == "code":
            return CodeCell(machine, g.addr)
        if g.space == "bit":
            # Global stores the *byte* in ``addr`` (register_globals passes it
            # positionally); ``byte`` was never a field of Global.
            return BitAddress(machine, g.addr, g.bit)
        raise KeyError(g.name)

    def _make_proxy(self, name: str):
        machine = self.machine
        if name in self.globals:
            return self._proxy_for(self.globals[name])
        try:
            return machine.resolve(name)
        except KeyError:
            pass
        # registers R0..R7 of the active bank
        m = re.fullmatch(r"R([0-7])", name)
        if m:
            return RAMCell(machine, ((machine.sfr(0xD0) >> 3) & 3) * 8 + int(m.group(1)))
        m = re.fullmatch(r"BANK([0-3])_R([0-7])", name)
        if m:
            return RAMCell(machine, int(m.group(1)) * 8 + int(m.group(2)))
        # ``NAME_M`` is how a *body* spells the declared bit ``NAME.M``
        # (``FIFLG_4`` <-> ``undefined FIFLG.4;``, ``IP_7`` <-> ``IP.7``,
        # ``P0_0`` <-> ``P0.0``): C identifiers cannot contain a dot, so the
        # decompiler underlines it in expressions.
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9]*)_([0-7])", name)
        if m:
            dotted = f"{m.group(1)}.{m.group(2)}"
            if dotted in self.globals:
                return self._proxy_for(self.globals[dotted])
            head = m.group(1)
            if head in SFR_NAMES:
                return BitAddress(machine, SFR_NAMES[head], int(m.group(2)))
        # ``_N_M`` is the decompiler's name for a *bit*: bit M of internal
        # RAM byte 0x20+N (the 8051 bit address (0x20+N-0x20)*8 + M).
        # Verified against the ROM: 0x8135 is ``JBC 17h`` (byte 0x22 bit 7)
        # exactly where the dump says ``if (_2_7 != '\0')``.
        m = re.fullmatch(r"_([0-9a-fA-F]+)_([0-7])", name)
        if m:
            return BitAddress(machine, 0x20 + int(m.group(1), 16), int(m.group(2)))
        if name in self.unmapped:
            raise UnmappedRegister(name, self.unmapped[name])
        raise KeyError(name)

    def deref(self, pointer: Any) -> int:
        if not isinstance(pointer, Pointer):
            pointer = Pointer("xdata", int(pointer) & 0xFFFF)
        return int(self._deref_target(pointer).value)

    def store(self, target: Expr, value: Any, frames: List[_Frame]) -> Any:
        cell = self.lvalue(target, frames)
        if isinstance(cell, _LocalCell):
            # Locals are the decompiler's registers: they may hold a Pointer
            # (address space included - ``byte *p = (byte *)0x2000;``) and a
            # negative value from a signed cast (``char c = (char)0xff;`` stays
            # -1 until a memory cell truncates it).  Masking here used to
            # destroy both: the pointer collapsed to a bare integer (so ``p[1]``
            # read RAM instead of xdata) and -1 came back as 65535.
            cell.value = value
            return value
        if isinstance(value, Pointer):
            value = value.addr
        masked = int(value)
        if masked >= 0:
            masked &= 0xFFFF          # negatives keep their sign; cells mask &0xFF
        cell.value = masked
        return value

    def assign(self, expr: Expr, frames: List[_Frame]) -> Any:
        op = expr.c
        if op == "=":
            value = self.eval(expr.b, frames)
            return self.store(expr.a, value, frames)
        current = int(self.eval(expr.a, frames))
        value = int(self.eval(expr.b, frames))
        simple = op[:-1]
        if simple == "+":
            result = current + value
        elif simple == "-":
            result = current - value
        elif simple == "*":
            result = current * value
        elif simple == "/":
            result = 0 if value == 0 else current // value
        elif simple == "%":
            result = 0 if value == 0 else current % value
        elif simple == "&":
            result = current & value
        elif simple == "|":
            result = current | value
        elif simple == "^":
            result = current ^ value
        elif simple == "<<":
            result = current << (value & 15)
        elif simple == ">>":
            result = current >> (value & 15)
        else:
            raise RuntimeError(f"unhandled assignment {op!r}")
        return self.store(expr.a, result & 0xFFFF, frames)

    # -------------------------------------------------------------- calls
    def _call(self, expr: Expr, frames: List[_Frame]) -> Any:
        callee = expr.a
        # ``(*(code *)(target))(args)`` - an indirect call: the cast marks the
        # computed integer as a *code* address, so the callee is the address
        # itself (dispatch by address), never a value read from memory.
        if callee.kind == "un" and callee.c == "*":
            target = self.eval(callee.a, frames)
            args = [self.eval(a, frames) for a in expr.b]
            return self.call_by_address(int(target) & 0xFFFF, args)
        name = callee.a if callee.kind == "var" else self.eval(callee, frames)
        args = [self.eval(a, frames) for a in expr.b]
        if isinstance(name, str):
            if name == "sizeof":
                return args[0] if args else 0
            return self.call_by_name(name, args)
        if callable(name):
            return name(*args)
        try:
            address = int(name) & 0xFFFF
        except (TypeError, ValueError):
            raise RuntimeError(f"cannot call {name!r}") from None
        return self.call_by_address(address, args)

    def call_by_address(self, addr: int, args: List[Any]) -> Any:
        """Call the recovered function at ``addr``, or report the gap."""
        addr &= 0xFFFF
        name = self.helpers.by_address.get(addr)
        if name is not None:
            func = self.helpers.get(name)
            if func is not None:
                return func(*args)
        key = f"indirect_0x{addr:04x}"
        self.machine.missing_calls[key] = self.machine.missing_calls.get(key, 0) + 1
        raise MissingFirmware(
            addr,
            "indirect call through a computed address: no dumped function is "
            "defined there",
        )

    def call_by_name(self, name: str, args: List[Any]) -> Any:
        if name in ("halt_baddata", "__halt"):
            # Reached *inside* a partial body: the decompiler hit bytes that
            # were never a valid instruction.  Everything before this point ran
            # on real bytes, so the honest outcome is a firmware gap reported at
            # the address of the function that got here - not the silent 0 the
            # shared helper returns, which would let decompiler fiction run.
            addr = -1
            if self.library is not None:
                current = self.library.functions.get(self.current or "")
                if current is not None and current.address is not None:
                    addr = current.address
            raise MissingFirmware(
                addr,
                f"bad instruction data inside {self.current or 'the recovered code'}: "
                f"the body reaches bytes that were never valid code",
            )
        func = self.helpers.get(name)
        if func is not None:
            return func(*args)
        # The dump calls three routines (FUN_CODE_f80d, _f87d, _feff) that it
        # never defines: the decompiler saw a call but decompiled no function
        # there.  That is a firmware gap with a known address, not an unknown
        # identifier, so it says so.
        m = re.fullmatch(r"(?:thunk_)?FUN_CODE_([0-9a-fA-F]{4})", name)
        if m:
            addr = int(m.group(1), 16)
            self.machine.missing_calls[name] = self.machine.missing_calls.get(name, 0) + 1
            raise MissingFirmware(
                addr,
                f"call to {name}: the dump references this routine but defines "
                f"no function there",
            )
        # ``func_0x1234`` and other addresses outside the dump
        if name.startswith("func_0x"):
            addr = int(name[7:], 16)
            self.machine.missing_calls[name] = self.machine.missing_calls.get(name, 0) + 1
            return 0
        raise KeyError(
            f"recovered code calls '{name}', which is not defined in the dump"
        )

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def truth(value: Any) -> bool:
        if isinstance(value, Pointer):
            return True
        return int(value) != 0

    def lookup(self, name: str, frames: List[_Frame]) -> Any:
        if name in _C_CONSTANTS:
            return _C_CONSTANTS[name]
        locals_ = self._locals(frames)
        if name in locals_:
            return locals_[name]
        machine = self.machine
        if name in machine.proxy_cache:
            return machine.proxy_cache[name]
        try:
            proxy = self._make_proxy(name)
        except KeyError:
            func = self.helpers.get(name)
            if func is not None:
                return func
            raise KeyError(
                f"recovered code reads '{name}', which is neither a known address "
                f"nor a recovered function"
            ) from None
        machine.proxy_cache[name] = proxy
        return proxy


class _LocalCell:
    __slots__ = ("env", "name")

    def __init__(self, env: dict, name: str) -> None:
        self.env = env
        self.name = name

    @property
    def value(self) -> Any:
        return self.env.get(self.name, 0)

    @value.setter
    def value(self, v: Any) -> None:
        self.env[self.name] = v

    def __int__(self) -> int:
        return int(self.value)


class _MemoryCell:
    """A settable view of one byte of machine memory."""

    __slots__ = ("machine", "space", "addr", "interp")

    def __init__(self, machine: Machine, space: str, addr: int, interp: Interpreter) -> None:
        self.machine = machine
        self.space = space
        self.addr = addr & 0xFFFF
        self.interp = interp

    @property
    def value(self) -> int:
        machine = self.machine
        if self.space == "xdata":
            return machine.xdata_read(self.addr)
        if self.space == "sfr":
            return machine.sfr(self.addr)
        if self.space == "code":
            return machine.read_code(self.addr)
        return machine.ram(self.addr)

    @value.setter
    def value(self, v: int) -> None:
        machine = self.machine
        v = int(v) & 0xFF
        if self.space == "xdata":
            machine.xdata_write(self.addr, v)
        elif self.space == "sfr":
            machine.set_sfr(self.addr, v)
        elif self.space == "code":
            raise MissingFirmware(self.addr, "write to code memory")
        else:
            machine.set_ram(self.addr, v)

    def __int__(self) -> int:
        return self.value


# ------------------------------------------------------------------ functions
@dataclass
class Global:
    name: str
    space: str
    addr: int = 0
    bit: int = 0


class RecoveredFunction:
    """A parsed, callable function recovered from the dump.

    Three kinds, matching :class:`recover.parse.Function`:

    ``is_stub``     the body is only bad data - :meth:`invoke` refuses it at the
                    entry point, because there is nothing to execute;
    ``is_partial``  real statements come first and the body hits the
                    ``halt_baddata()`` marker later - it *runs*, and the marker
                    itself raises :class:`MissingFirmware` exactly where the
                    bytes stop making sense (see ``Interpreter.call_by_name``);
    neither         fully recovered: no bad-data marker at all.
    """

    __slots__ = ("name", "address", "ast", "param_names", "declarations", "labels",
                 "parents", "source", "interpreter", "call_count", "is_stub",
                 "is_partial", "baddata_prefix", "truncated")

    def __init__(self, name: str, address: Optional[int], ast: Stmt, param_names: List[str],
                 declarations: List[Tuple[str, str]],
                 labels: Dict[str, Tuple[Sequence[Stmt], int]],
                 parents: Optional[Dict[int, Tuple[Sequence[Stmt], int]]] = None,
                 source: str = "", is_stub: bool = False, truncated: bool = False,
                 is_partial: bool = False, baddata_prefix: int = 0) -> None:
        self.name = name
        self.address = address
        self.ast = ast
        self.param_names = param_names
        self.declarations = declarations
        #: label -> (statement list it lives in, index in that list)
        self.labels = labels
        #: id(statement list) -> (list that contains its statement, index there)
        self.parents = parents or {}
        self.source = source
        self.interpreter: Optional[Interpreter] = None
        self.call_count = 0
        self.is_stub = is_stub
        self.is_partial = is_partial
        #: executable statements before the bad-data marker (0 for stubs)
        self.baddata_prefix = baddata_prefix
        self.truncated = truncated

    def invoke(self, interp: Interpreter, args: List[Any]) -> Any:
        self.call_count += 1
        if interp.call_depth >= interp.max_depth:
            raise RuntimeError(
                f"recovered call depth exceeded at {self.name} "
                f"(mutual recursion or a decompiler-invented call cycle)"
            )
        if self.is_stub:
            raise MissingFirmware(
                self.address or 0,
                f"decompiler stub {self.name} (bad instruction data - the bytes "
                f"here were never a valid function)",
            )
        # a *partial* body runs: everything before the halt_baddata() marker is
        # backed by real bytes, and the marker raises where it is reached.
        interp.call_depth += 1
        previous = interp.current
        interp.current = self.name
        try:
            return interp.execute_body(self.ast, self, args)
        finally:
            interp.current = previous
            interp.call_depth -= 1

    def __repr__(self) -> str:
        return f"<RecoveredFunction {self.name}@0x{self.address:04X}>" if self.address else f"<RecoveredFunction {self.name}>"


class FunctionLibrary:
    """Parse every function of a dump into callable form."""

    def __init__(self, machine: Machine, helpers: RuntimeHelpers) -> None:
        self.machine = machine
        self.helpers = helpers
        self.functions: Dict[str, RecoveredFunction] = {}
        self.failed: Dict[str, str] = {}
        self.globals: Dict[str, Global] = {}
        self.interpreter = Interpreter(machine, helpers)
        self.interpreter.globals = self.globals
        self.interpreter.library = self

    def register_globals(self, declarations) -> None:
        """Turn the dump's global declarations into address-space bindings.

        Names the dump uses (``DAT_INTMEM_3e``, ``DAT_EXTMEM_0c7a``,
        ``DAT_SFR_92``, ``DAT_CODE_8299``, and the mangled bit names ``22.1``)
        already encode their address space, so this is a pure translation with
        no guessing.

        A declaration the dump gives *no* address for (``undefined1 RXSTAT;``,
        ``undefined FIFLG.4;``) is recorded as unmapped: recovered code that
        touches it gets :class:`~recover.errors.UnmappedRegister` - a named,
        honest gap - instead of a generic unknown identifier or an invented
        location.
        """
        for decl in declarations:
            name = getattr(decl, "name", "")
            if not name:
                continue
            raw = getattr(decl, "raw", "") or name
            try:
                if name.startswith("DAT_INTMEM_"):
                    addr = int(name[len("DAT_INTMEM_"):], 16)
                    self.globals[name] = Global(name, "ram", addr)
                    self.machine.proxy_cache[name] = RAMCell(self.machine, addr)
                    continue
                if name.startswith("DAT_EXTMEM_"):
                    addr = int(name[len("DAT_EXTMEM_"):], 16)
                    self.globals[name] = Global(name, "xdata", addr)
                    self.machine.proxy_cache[name] = XdataCell(self.machine, addr)
                    continue
                if name.startswith("DAT_SFR_"):
                    addr = int(name[len("DAT_SFR_"):], 16)
                    self.globals[name] = Global(name, "sfr", addr)
                    self.machine.proxy_cache[name] = SFR(self.machine, addr)
                    continue
                for prefix in ("DAT_CODE_", "SUB_CODE_", "UNK_CODE_", "LAB_CODE_"):
                    if name.startswith(prefix):
                        addr = int(name[len(prefix):], 16)
                        self.globals[name] = Global(name, "code", addr)
                        self.machine.proxy_cache[name] = CodeCell(self.machine, addr)
                        break
                else:
                    if "." in name:
                        self._register_bit(name, raw)
                    else:
                        proxy = self.machine.resolve(name)
                        self.machine.proxy_cache[name] = proxy
                continue
            except (ValueError, KeyError):
                # a prefix whose suffix is not hex, a bit index that is not a
                # number, or a name no address rule covers (``RXSTAT``,
                # ``FIFLG.4``) - fall through to the unmapped bookkeeping below
                pass
            self._mark_unmapped(name, raw)

    def _register_bit(self, name: str, raw: str) -> None:
        """Bind ``BYTE.BIT`` - the declaration form of a bit variable.

        ``undefined 22.1;`` is *bit 1 of RAM byte 0x22*: the declared set is
        exactly ``20.0``..``2f.7`` plus ``F8.6``/``F8.7``, and the bodies spell
        the same bits as ``_2_1`` / ``F8_6`` (see
        ``recover.hal.bit_aliases_from_globals`` for the ROM evidence).  The
        old formula here - ``(0x22 >> 3) + 0x20 == 0x24`` - collapsed the whole
        declared set onto two bytes.
        """
        head, _, bit = name.partition(".")
        index = int(bit)
        if not 0 <= index <= 7:
            raise ValueError(f"bad bit index in {name}")
        try:
            byte = int(head, 16)
        except ValueError:
            # a *named* bit (``P0.0``, ``IP.7``, ``P1.3``)
            if head in SFR_NAMES:
                byte = SFR_NAMES[head]
            else:
                proxy = self.machine.resolve(name)      # raises KeyError if unknown
                byte = proxy.byte
                index = proxy.bit
        if not 0 <= byte <= 0xFF:
            raise ValueError(f"bad byte address in {name}")
        self.globals[name] = Global(name, "bit", byte, index)
        self.machine.proxy_cache[name] = BitAddress(self.machine, byte, index)

    def _mark_unmapped(self, name: str, raw: str) -> None:
        """Remember a declared symbol the dump gives no address for."""
        self.interpreter.unmapped[name] = raw
        if "." in name:
            head, _, bit = name.partition(".")
            # bodies spell ``FIFLG.4`` as ``FIFLG_4``
            self.interpreter.unmapped.setdefault(f"{head}_{bit}", raw)

    def load(self, program) -> None:
        from .cparse import parse_body
        for fn in program.functions:
            try:
                ast = parse_body(fn.body)
            except (ParseError, ValueError, RecursionError) as exc:
                self.failed[fn.name] = f"{type(exc).__name__}: {exc}"
                continue
            declarations, labels, parents = _collect(ast)
            recovered = RecoveredFunction(
                name=fn.name,
                address=fn.address,
                ast=ast,
                param_names=fn.param_names,
                declarations=declarations,
                labels=labels,
                parents=parents,
                source=fn.body,
                is_stub=fn.is_stub,
                is_partial=fn.is_partial,
                baddata_prefix=fn.baddata_prefix,
            )
            recovered.interpreter = self.interpreter
            self.functions[fn.name] = recovered
            self.helpers.register(fn.name, _make_callable(recovered), fn.address)

    def stats(self) -> Dict[str, int]:
        return {
            "loaded": len(self.functions),
            "failed": len(self.failed),
            "stubs": sum(1 for f in self.functions.values() if f.is_stub),
            "partials": sum(1 for f in self.functions.values() if f.is_partial),
            "globals": len(self.globals),
            "unmapped": len(self.interpreter.unmapped),
        }


def _make_callable(recovered: RecoveredFunction):
    def call(*args):
        interp = recovered.interpreter
        return recovered.invoke(interp, list(args))

    call.__name__ = recovered.name
    call.recovered = recovered          # type: ignore[attr-defined]
    return call


def _collect(
    ast: Stmt,
) -> Tuple[List[Tuple[str, str]],
           Dict[str, Tuple[Sequence[Stmt], int]],
           Dict[int, Tuple[Sequence[Stmt], int]]]:
    """Walk the AST collecting declarations, label sites and block parents.

    ``labels`` maps a label to ``(list it lives in, index in that list)`` and
    ``parents`` maps ``id(list)`` to ``(containing list, index of the statement
    that opens it)``.  Together they are exactly what :meth:`Interpreter._rebuild`
    needs to jump into a block that execution has not entered yet - the old
    global statement counter drifted as soon as a label sat inside an ``if`` or
    a loop, which sent ``goto`` to an unrelated statement (or past the end of
    the function, which silently returned).
    """
    declarations: List[Tuple[str, str]] = []
    labels: Dict[str, Tuple[Sequence[Stmt], int]] = {}
    parents: Dict[int, Tuple[Sequence[Stmt], int]] = {}

    def walk(lst: Sequence[Stmt], parent: Optional[Tuple[Sequence[Stmt], int]]) -> None:
        if parent is not None:
            parents[id(lst)] = parent
        for index, node in enumerate(lst):
            if node.kind == "decl":
                declarations.extend(node.vars)
            elif node.kind == "label":
                labels.setdefault(node.name, (lst, index))
            elif node.kind == "block":
                walk(node.items, (lst, index))
            else:
                for child in (node.body, node.els):
                    if child is not None and child.kind == "block":
                        walk(child.items, (lst, index))
                if node.kind == "switch":
                    # case bodies (and the prelude) are statement lists of their
                    # own; at runtime the switch frame is skipped exactly the
                    # same way _resume_frame does
                    for case in node.items:
                        if case.kind == "block":
                            walk(case.items, (lst, index))

    walk(ast.items, None)
    return declarations, labels, parents
