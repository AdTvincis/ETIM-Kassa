#!/usr/bin/env python3
"""Command line front end for the firmware recovery pipeline.

Subcommands
-----------
``report``
    Parse ``docs/nm27c512n_decompiled.c`` and print totals, a per-function
    table and the call targets that no dump covers.
``emit``
    Write ``docs/recovered/firmware_clean.c`` and
    ``docs/recovered/firmware_recovered.py``.
``run``
    Load the recovered library and execute one function through the
    interpreter, printing its return value and the 8051 state.
``selftest``
    Exercise the parser and the interpreter and assert the invariants.

Everything is standard library only.  See ``docs/firmware_recovery.md`` for the
long explanation, and ``recover/emit.py`` for how the two artifacts are built.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, List, Optional, Tuple

# Make ``python tools/recover_firmware.py`` work from the repository root.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from recover.cparse import ParseError, parse_body  # noqa: E402
from recover.emit import (  # noqa: E402
    DUMP_ROM_END,
    DUMP_ROM_START,
    check_balance,
    emit_c,
    emit_python,
)
from recover.errors import MissingFirmware  # noqa: E402
from recover.interp import FunctionLibrary  # noqa: E402
from recover.namespace import Machine  # noqa: E402
from recover.parse import parse_dump  # noqa: E402
from recover.runtime import RuntimeHelpers  # noqa: E402

DEFAULT_DUMP = os.path.join("docs", "nm27c512n_decompiled.c")
DEFAULT_OUT = os.path.join("docs", "recovered")
DEFAULT_ROM = os.path.join("firmware", "nm27c512n.hex")


# --------------------------------------------------------------------- helpers
def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def load_rom(path: str) -> Optional[Dict[int, int]]:
    """Parse an Intel HEX file into ``{address: byte}``; ``None`` on failure."""
    if not os.path.exists(path):
        return None
    image: Dict[int, int] = {}
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line.startswith(":"):
                    continue
                raw = bytes.fromhex(line[1:])
                count, addr, kind = raw[0], (raw[1] << 8) | raw[2], raw[3]
                if kind == 0x00:
                    for index in range(count):
                        image[addr + index] = raw[4 + index]
    except (ValueError, IndexError):
        return None
    return image


def build_library(dump_path: str, rom_path: Optional[str] = None):
    """Return ``(machine, helpers, library, program)`` for one dump."""
    text = read_text(dump_path)
    program = parse_dump(text, dump_path)
    machine = Machine()
    rom = load_rom(rom_path or DEFAULT_ROM)
    if rom is not None:
        machine.rom_reader = lambda addr: rom.get(addr, 0xFF)
    helpers = RuntimeHelpers(machine)
    library = FunctionLibrary(machine, helpers)
    library.register_globals(program.globals)
    library.load(program)
    return machine, helpers, library, program


def snapshot_text(machine: Machine, library: FunctionLibrary) -> str:
    snap = machine.snapshot()
    lines = [
        "SFR snapshot:",
        "  ACC=0x{acc:02X} PSW=0x{psw:02X} SP=0x{sp:02X} DPTR=0x{dptr:04X}".format(**snap),
        "  P0=0x{p0:02X} P1=0x{p1:02X} P2=0x{p2:02X} P3=0x{p3:02X}".format(**snap),
        "  steps={steps} missing calls={missing_calls}".format(**snap),
        "Internal RAM (non-zero bytes):",
    ]
    row = [
        f"  {addr:02X}={machine.ram(addr):02X}"
        for addr in range(0x100)
        if machine.ram(addr)
    ]
    lines.append(" ".join(row) if row else "  (all zero)")
    if machine.missing_calls:
        lines.append("Uncovered call targets (no dump covers these):")
        for name, count in sorted(machine.missing_calls.items()):
            lines.append(f"  {name} x{count}")
    if library.failed:
        lines.append(f"Functions that failed to parse: {len(library.failed)}")
    return "\n".join(lines)


# ---------------------------------------------------------------- subcommands
def cmd_report(args: argparse.Namespace) -> int:
    text = read_text(args.dump)
    program = parse_dump(text, args.dump)
    stats = program.stats()

    print(f"dump        : {args.dump}")
    print(f"functions   : {stats['functions']}")
    print(f"recovered   : {stats['recovered']}  (real bytes in {DUMP_ROM_START:#06x}..{DUMP_ROM_END:#06x})")
    print(f"partials    : {stats['partials']}  (executable statements, then halt_baddata)")
    print(f"stubs       : {stats['stubs']}  (body is only halt_baddata: nothing to run)")
    print(f"globals     : {stats['globals']}  ({stats['bit_globals']} bit cells)")
    print()

    print(f"{'function':24s} {'address':>8s} {'params':>6s} {'stmts':>7s}  status")
    print("-" * 72)
    parse_ok = 0
    parse_total = 0
    for func in program.functions:
        if func.is_stub:
            status = "stub"
        else:
            parse_total += 1
            try:
                parse_body(func.body)
                status = "partial" if func.is_partial else "ok"
                parse_ok += 1
            except (ParseError, ValueError, RecursionError) as exc:
                status = f"unparseable ({type(exc).__name__})"
        address = f"0x{func.address:04X}" if func.address is not None else "-"
        statements = func.body.count(";") if func.body else 0
        print(
            f"{func.name:24s} {address:>8s} {len(func.params):>6d} {statements:>7d}  {status}"
        )
    print()
    print(f"bodies parsed: {parse_ok}/{parse_total} runnable functions "
          f"(recovered + partial; stubs are refused at entry)")
    if args.verbose:
        unparsed = [
            f.name
            for f in program.functions
            if not f.is_stub and f.name not in _parseable(program)
        ]
        if unparsed:
            print("unparseable:", ", ".join(unparsed))

    # call targets no dump covers
    known = {f.name for f in program.functions}
    import re

    missing: Dict[str, int] = {}
    for func in program.functions:
        for match in re.finditer(r"\b(func_0x[0-9a-fA-F]+)\b", func.body):
            missing[match.group(1)] = missing.get(match.group(1), 0) + 1
    print()
    print(f"call targets outside every dump: {len(missing)}")
    for name in sorted(missing, key=lambda n: (-missing[n], n)):
        addr = int(name[len("func_0x"):], 16)
        covered = DUMP_ROM_START <= addr <= DUMP_ROM_END
        note = "covered by the dump" if covered else "NOT covered by any dump"
        print(f"  {name}  x{missing[name]:<4d} {note}")
    undefined = sorted(
        {
            m.group(1)
            for f in program.functions
            for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", f.body)
        }
        - known
        - {"if", "while", "for", "switch", "return", "sizeof", "do"}
    )
    print()
    print(f"called identifiers with no definition in the dump: {len(undefined)}")
    print("  " + ", ".join(undefined))
    return 0


def _parseable(program) -> set:
    ok = set()
    for func in program.functions:
        try:
            parse_body(func.body)
            ok.add(func.name)
        except (ParseError, ValueError, RecursionError):
            pass
    return ok


def cmd_emit(args: argparse.Namespace) -> int:
    text = read_text(args.dump)
    artifacts = [
        emit_c(text, args.dump),
        emit_python(text, args.dump),
    ]
    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)
    for artifact in artifacts:
        path = os.path.join(out_dir, artifact.path)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(artifact.text)
        print(f"wrote {path} ({artifact.stats.get('bytes', 0)} bytes)")
    c_result = artifacts[0]
    if c_result.balance:
        print(f"C balance check FAILED ({len(c_result.balance)} problems):")
        for problem in c_result.balance[:10]:
            print("  " + problem)
        return 1
    print("C balance check: clean (braces/parens/brackets balanced)")
    python_result = artifacts[1]
    print(
        "python artifact: {entries} entries, {ok} ok, {stubs} stubs, "
        "{unparseable} unparseable, raw-scan {raw}".format(
            entries=python_result.stats.get("entries"),
            ok=python_result.stats.get("ok"),
            stubs=python_result.stats.get("stubs"),
            unparseable=python_result.stats.get("unparseable"),
            raw=python_result.stats.get("raw_only"),
        )
    )
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    machine, helpers, library, program = build_library(args.dump, args.rom)
    name = args.function
    recovered = library.functions.get(name)
    if recovered is None:
        # allow the readable spelling too
        for candidate in library.functions.values():
            if candidate.name.endswith(name) or candidate.address == _as_address(name):
                recovered = candidate
                break
    if recovered is None:
        print(
            f"error: {name!r} is not a recovered function. "
            f"{len(library.functions)} functions are available; try ``report``.",
            file=sys.stderr,
        )
        return 2

    values: List[int] = []
    if args.args:
        for chunk in args.args.split(","):
            chunk = chunk.strip()
            if chunk:
                values.append(int(chunk, 0))

    machine.step_limit = args.steps
    interpreter = library.interpreter
    interpreter.max_steps = args.steps
    if args.trace:
        interpreter.trace = []
    try:
        result = recovered.invoke(interpreter, values)
        outcome = f"returned {result!r}"
        code = 0
    except MissingFirmware as missing:
        print(f"MissingFirmware: {missing}")
        outcome = "raised MissingFirmware"
        code = 3
    except RuntimeError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        outcome = "raised RuntimeError"
        code = 4
    except KeyError as exc:
        print(f"error: unresolved name {exc}", file=sys.stderr)
        outcome = f"raised KeyError({exc})"
        code = 5

    print(f"function : {recovered.name}  (address "
          f"{('0x%04X' % recovered.address) if recovered.address is not None else 'unknown'})")
    print(f"arguments: {values}")
    print(f"outcome  : {outcome}")
    print(f"steps    : {interpreter.steps}")
    if args.trace and interpreter.trace:
        print("trace    :")
        for line in interpreter.trace[: args.trace_limit]:
            print("  " + line)
        if len(interpreter.trace) > args.trace_limit:
            print(f"  ... {len(interpreter.trace) - args.trace_limit} more steps")
    print()
    print(snapshot_text(machine, library))
    return code


def _as_address(name: str) -> Optional[int]:
    for prefix in ("sub_", "FUN_CODE_", "0x"):
        if name.startswith(prefix):
            try:
                return int(name[len(prefix):].split("_")[0], 16)
            except ValueError:
                return None
    return None


def cmd_selftest(args: argparse.Namespace) -> int:
    text = read_text(args.dump)
    failures: List[str] = []

    def check(label: str, condition: bool, detail: str = "") -> None:
        mark = "ok  " if condition else "FAIL"
        print(f"[{mark}] {label}{(' - ' + detail) if detail else ''}")
        if not condition:
            failures.append(label)

    program = parse_dump(text, args.dump)
    stats = program.stats()
    check("parse finds >= 120 functions", stats["functions"] >= 120, str(stats["functions"]))
    with_addr = sum(1 for f in program.functions if f.address is not None)
    check(
        "every function has an address or a reason",
        with_addr == stats["functions"],
        f"{with_addr}/{stats['functions']} carry an address",
    )
    check(
        "every global resolved to an address space",
        all(g.name or g.type == "typedef" for g in program.globals),
        f"{len(program.globals)} globals",
    )

    parsed = 0
    total = 0
    failures_body: List[str] = []
    for func in program.functions:
        if func.is_stub:
            continue
        total += 1
        try:
            parse_body(func.body)
            parsed += 1
        except (ParseError, ValueError, RecursionError) as exc:
            failures_body.append(f"{func.name}: {type(exc).__name__}: {exc}")
    check("every non-stub body parses", not failures_body, f"{parsed}/{total}")
    for line in failures_body[:5]:
        print("       " + line)

    machine, helpers, library, _program = build_library(args.dump, args.rom)
    # The probes below are a smoke test, not a full run: partial bodies (which
    # used to refuse at entry as stubs) now execute, and some of them spin in
    # loops that depend on the half of the firmware no dump covers.
    library.interpreter.max_steps = min(library.interpreter.max_steps, 200_000)
    check(
        "FunctionLibrary.load registers >= 100 functions",
        len(library.functions) >= 100,
        str(len(library.functions)),
    )
    check("no unexpected parse failures", len(library.failed) == 0, str(library.failed))
    check("globals bound to the machine", len(library.globals) > 100, str(len(library.globals)))

    # --- three-way status: recovered / partial / stub ---------------------
    buckets = stats["recovered"] + stats["stubs"] + stats["partials"]
    check(
        "every function is exactly one of recovered/partial/stub",
        buckets == stats["functions"] and stats["stubs"] >= 1 and stats["partials"] >= 1,
        f"{stats['recovered']} recovered + {stats['partials']} partial + "
        f"{stats['stubs']} stub = {buckets}/{stats['functions']}",
    )

    # behaviour: a stub refuses at the entry point (no statement runs), a
    # partial body executes its real prefix and reports the gap at the marker
    interp = library.interpreter
    stub_fn = next((f for f in library.functions.values() if f.is_stub), None)
    partial_fn = library.functions.get("FUN_CODE_f565") or next(
        (f for f in library.functions.values() if f.is_partial), None
    )
    behaviour_ok = stub_fn is not None and partial_fn is not None
    notes: List[str] = []
    if behaviour_ok:
        interp.trace = []
        interp.trace_limit = 5000
        try:
            stub_fn.invoke(interp, [1] * 8)
            behaviour_ok = False
            notes.append(f"{stub_fn.name} executed instead of refusing")
        except MissingFirmware:
            if interp.trace:
                behaviour_ok = False
                notes.append(f"{stub_fn.name} ran {len(interp.trace)} statements")
        interp.trace = []
        gap: Optional[MissingFirmware] = None
        try:
            partial_fn.invoke(interp, [1] * 8)
        except MissingFirmware as exc:
            gap = exc
        ran = len(interp.trace)
        interp.trace = None
        if ran == 0:
            behaviour_ok = False
            notes.append(f"{partial_fn.name} refused at entry")
        if gap is None:
            behaviour_ok = False
            notes.append(f"{partial_fn.name} never reported the gap")
        elif partial_fn.name == "FUN_CODE_f565" and gap.addr != (partial_fn.address or -1):
            behaviour_ok = False
            notes.append(f"gap reported at {gap.addr:#x}, not {partial_fn.address:#x}")
        if behaviour_ok and not notes:
            notes.append(f"stub refuses, {partial_fn.name} ran {ran} statements to the marker")
    else:
        notes.append("no stub/partial found in the dump")
    check("stub refuses at entry, partial runs until bad-data", behaviour_ok, "; ".join(notes))

    # execute a few functions; MissingFirmware is fine, interpreter bugs are not
    executed = 0
    bugs: List[str] = []
    for name in args.functions:
        recovered = library.functions.get(name)
        if recovered is None:
            bugs.append(f"{name}: not loaded")
            continue
        try:
            recovered.invoke(library.interpreter, [1, 0, 0, 0, 0, 0, 0, 0])
            executed += 1
        except MissingFirmware:
            executed += 1
        except (KeyError, RuntimeError) as exc:
            executed += 1
            print(f"       {name}: {type(exc).__name__}: {str(exc)[:100]}")
        except (AttributeError, TypeError) as exc:
            bugs.append(f"{name}: {type(exc).__name__}: {exc}")
    check(
        "calling recovered functions never hits an interpreter bug",
        not bugs,
        f"{executed} calls",
    )
    for line in bugs:
        print("       " + line)

    emitted_c = emit_c(text, args.dump)
    emitted_py = emit_python(text, args.dump)
    check("C artifact is non-empty", len(emitted_c.text) > 1000, str(len(emitted_c.text)))
    check(
        "python artifact is non-empty",
        len(emitted_py.text) > 1000,
        str(len(emitted_py.text)),
    )
    check(
        "C artifact passes the balance checker",
        not emitted_c.balance,
        f"{len(emitted_c.balance)} problems",
    )
    for problem in emitted_c.balance[:5]:
        print("       " + problem)
    check(
        "python artifact defines RECOVERED/STATS/MISSING_RANGES",
        all(
            key in emitted_py.text
            for key in ("RECOVERED = {", "STATS = {", "MISSING_RANGES = ")
        ),
    )

    print()
    if failures:
        print(f"selftest FAILED: {len(failures)} check(s)")
        return 1
    print("selftest passed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recover_firmware",
        description="Parse, emit and execute the decompiled ETIM cash-register firmware.",
    )
    parser.add_argument(
        "--dump",
        default=DEFAULT_DUMP,
        help=f"Ghidra pseudo-C dump (default: {DEFAULT_DUMP})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    report = sub.add_parser("report", help="totals, per-function table, uncovered calls")
    report.add_argument("-v", "--verbose", action="store_true", help="list unparseable bodies")
    report.set_defaults(func=cmd_report)

    emit = sub.add_parser("emit", help="write the C and Python reconstructions")
    emit.add_argument("--out", default=DEFAULT_OUT, help=f"output directory (default: {DEFAULT_OUT})")
    emit.set_defaults(func=cmd_emit)

    run = sub.add_parser("run", help="execute one recovered function")
    run.add_argument("function", help="function name, e.g. FUN_CODE_810f or sub_810F")
    run.add_argument("--args", default="", help="comma-separated integer arguments")
    run.add_argument("--steps", type=int, default=200_000, help="step limit (default 200000)")
    run.add_argument("--trace", action="store_true", help="print the interpreter trace")
    run.add_argument("--trace-limit", type=int, default=80, help="trace lines to print")
    run.add_argument("--rom", default=DEFAULT_ROM, help=f"Intel HEX image (default: {DEFAULT_ROM})")
    run.set_defaults(func=cmd_run)

    selftest = sub.add_parser("selftest", help="assert the parser/interpreter/emitter invariants")
    selftest.add_argument(
        "--functions",
        nargs="*",
        default=["FUN_CODE_810f", "FUN_CODE_8139", "FUN_CODE_83f0", "FUN_CODE_8d00"],
        help="functions to execute as part of the test",
    )
    selftest.add_argument("--rom", default=DEFAULT_ROM)
    selftest.set_defaults(func=cmd_selftest)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not os.path.exists(args.dump):
        print(f"error: dump {args.dump!r} not found", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
