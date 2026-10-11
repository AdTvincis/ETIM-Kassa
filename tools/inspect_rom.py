"""Run the cash-register firmware and report what it does.

Examples
--------
    python tools/inspect_rom.py trace --cycles 3000000
    python tools/inspect_rom.py trace --cycles 500000 --watch 0x0000-0x000F
    python tools/inspect_rom.py disasm 0x8000 60
    python tools/inspect_rom.py vectors
    python tools/inspect_rom.py histogram --cycles 5000000
"""

from __future__ import annotations

import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from m8051 import CPU8051, ROM  # noqa: E402
from m8051.bus import HardwareBus  # noqa: E402
from tools.disasm import disassemble_one  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ROM = os.path.join(HERE, "firmware", "nm27c512n.hex")


class TraceBus(HardwareBus):
    """Records every access and reactivates peripherals from the firmware."""

    def __init__(self, watch=()) -> None:
        self.port_writes = collections.Counter()
        self.port_edges = collections.Counter()
        self.ext_writes = collections.Counter()
        self.ext_reads = collections.Counter()
        self.serial = []
        self.events = []
        self.watch = set(watch)
        self._port_state = [0xFF] * 4
        self.tick_cycles = 0
        # a 8255 PPI: control word at ext address 3, ports 0..2
        self.ppi_control = 0
        self.ppi_ports = [0, 0, 0]

    def tick(self, cycles: int) -> None:
        self.tick_cycles += cycles

    def ext_read(self, addr: int, code: bool = False) -> int:
        self.ext_reads[addr] += 1
        if addr < 4:
            if addr == 3:
                return self.ppi_control
            return self.ppi_ports[addr]
        return 0xFF

    def ext_write(self, addr: int, value: int) -> None:
        self.ext_writes[addr] += 1
        if addr < 4:
            if addr == 3:
                self.ppi_control = value
            else:
                self.ppi_ports[addr] = value
            self.events.append((self.tick_cycles, "ppi", addr, value))
        elif addr in self.watch:
            self.events.append((self.tick_cycles, "ext", addr, value))

    def ext_probe(self, addr: int) -> bool:
        return addr < 4

    def port_read(self, port: int) -> int:
        return 0xFF

    def port_write(self, port: int, value: int) -> None:
        self.port_writes[port] += 1
        old = self._port_state[port]
        if old != value:
            self.port_edges[port] += 1
            self.events.append((self.tick_cycles, f"P{port}", old, value))
        self._port_state[port] = value

    def serial_write(self, byte: int) -> None:
        self.serial.append(byte)


def build_rom(path: str) -> ROM:
    rom = ROM(os.path.basename(path)).load_file(path)
    return rom


def cmd_vectors(rom: ROM) -> None:
    print(f"ROM {rom.name}: {len(rom)} bytes, coverage {rom.coverage()}")
    names = ["EXT0", "T0", "EXT1", "T1", "SERIAL", "T2", "PCA", "LVD", "SPI", "UART1"]
    for i, vec in enumerate((0x03, 0x0B, 0x13, 0x1B, 0x23, 0x2B, 0x33, 0x3B, 0x43, 0x4B)):
        target = rom.word(vec - 3) if False else rom.word(vec)
        src = vec - 3
        text, _ = disassemble_one(rom, src)
        print(f"  {src:04X}: {text:<24} -> handler {target:04X}h   {names[i] if i < len(names) else ''}")


def cmd_disasm(rom: ROM, args) -> None:
    from tools.disasm import walk

    start = int(args.start, 0)
    count = args.count
    for i, (pc, text, length) in enumerate(walk(rom, start, start + 0x10000, count)):
        raw = rom.get_slice(pc, length).hex().upper()
        print(f"{pc:04X}  {raw:<9} {text}")


def cmd_trace(rom: ROM, args) -> None:
    bus = TraceBus()
    cpu = CPU8051(rom, bus)
    cpu.run(args.cycles)
    print(f"executed {cpu.op_count} instructions, {cpu.cycles} machine cycles "
          f"({cpu.cycles / 1e6:.3f} s @12MHz), error={cpu.error}")
    print(f"PC={cpu.pc:04X} A={cpu.acc:02X} PSW={cpu.psw:02X} SP={cpu.sp:02X} DPTR={cpu.dptr:04X}")
    print(f"P0={bus._port_state[0]:02X} P1={bus._port_state[1]:02X} "
          f"P2={bus._port_state[2]:02X} P3={bus._port_state[3]:02X}")
    print("--- port writes ---")
    total = 0
    for port in range(4):
        if bus.port_writes[port]:
            total += bus.port_writes[port]
            print(f"  P{port}: {bus.port_writes[port]} writes, {bus.port_edges[port]} edges")
    print(f"  total {total}")
    print("--- external writes (top 25) ---")
    for addr, count in bus.ext_writes.most_common(25):
        print(f"  {addr:04X}h: {count}")
    print("--- external reads (top 25) ---")
    for addr, count in bus.ext_reads.most_common(25):
        print(f"  {addr:04X}h: {count}")
    if bus.serial:
        text = "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in bus.serial[:400])
        print(f"--- serial out ({len(bus.serial)} bytes) ---\n  {text}")
    if args.events:
        print("--- last 60 events ---")
        for ev in bus.events[-60:]:
            print("  ", ev)


def cmd_histogram(rom: ROM, args) -> None:
    bus = TraceBus()
    cpu = CPU8051(rom, bus)
    counts = collections.Counter()
    block = 0x100
    steps = 0
    while cpu.cycles < args.cycles and cpu.error is None:
        counts[cpu.pc & ~(block - 1)] += 1
        cpu.step()
        steps += 1
    print(f"{steps} instructions, {cpu.cycles} cycles, error={cpu.error}")
    for base, count in counts.most_common(30):
        print(f"  {base:04X}-{base + block - 1:04X}: {count}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rom", default=DEFAULT_ROM)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("vectors")
    p = sub.add_parser("disasm")
    p.add_argument("start", nargs="?", default="0x8000")
    p.add_argument("count", nargs="?", type=int, default=60)
    p = sub.add_parser("trace")
    p.add_argument("--cycles", type=int, default=2_000_000)
    p.add_argument("--events", action="store_true")
    p = sub.add_parser("histogram")
    p.add_argument("--cycles", type=int, default=2_000_000)

    args = ap.parse_args()
    rom = build_rom(args.rom)
    if args.cmd == "vectors":
        cmd_vectors(rom)
    elif args.cmd == "disasm":
        cmd_disasm(rom, args)
    elif args.cmd == "trace":
        cmd_trace(rom, args)
    elif args.cmd == "histogram":
        cmd_histogram(rom, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
