# -*- coding: utf-8 -*-
"""Diagnostic: why does nm27c512n.hex (rebased to base 0) go static?

Scratch tool - diagnostics only, no project file is modified.
"""
from __future__ import annotations

import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from m8051.rom import ROM, parse_intel_hex                      # noqa: E402
from m8051.cpu import CPU8051                                    # noqa: E402
from board.cashboard import CashRegisterBoard                    # noqa: E402
from tools.disasm import disassemble, disassemble_one            # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HEX = os.path.join(ROOT, "firmware", "nm27c512n.hex")

SFR = {
    0x88: "TCON", 0x89: "TMOD", 0x8A: "TL0", 0x8C: "TH0",
    0x8B: "TL1", 0x8D: "TH1", 0xA8: "IE", 0xB8: "IP",
    0x98: "SCON", 0xD0: "PSW", 0xE0: "ACC", 0x81: "SP",
    0x82: "DPL", 0x83: "DPH", 0xA0: "P2", 0xB0: "P3", 0x90: "P1",
}


def load_rebased() -> ROM:
    rom = ROM("nm27c512n_rebased")
    for addr, data in parse_intel_hex(open(HEX, encoding="latin-1").read()):
        rom.load_block((addr - 0x8000) & 0xFFFF, data)
    return rom


def sfr_dump(cpu) -> str:
    parts = []
    for a, n in sorted(SFR.items()):
        parts.append(f"{n}={cpu.sfr[a]:02X}")
    return " ".join(parts)


class Probe:
    """Wrap the board's MOVX entry points to count traffic by page."""

    def __init__(self, board):
        self.board = board
        self.rd = collections.Counter()
        self.wr = collections.Counter()
        self.rd_pages = collections.Counter()
        self.wr_pages = collections.Counter()
        self.rd_first = {}
        self.wr_first = {}
        self.hot = []            # (cycle, pc, addr, value) for 0x89/0xA9
        self.cpu = None
        self._rd0 = board.ext_read
        self._wr0 = board.ext_write
        board.ext_read = self._rd
        board.ext_write = self._wr

    def _rd(self, addr, code=False):
        addr &= 0xFFFF
        self.rd[addr] += 1
        self.rd_pages[addr >> 8] += 1
        self.rd_first.setdefault(addr, self.board.cycles)
        return self._rd0(addr, code)

    def _wr(self, addr, value):
        addr &= 0xFFFF
        value &= 0xFF
        self.wr[addr] += 1
        self.wr_pages[addr >> 8] += 1
        self.wr_first.setdefault(addr, self.board.cycles)
        if value in (0x89, 0xA9):              # 8255 mode-set words
            pc = self.cpu.pc if self.cpu is not None else -1
            self.hot.append((self.board.cycles, pc, addr, value))
        return self._wr0(addr, value)


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "boot"

    rom = load_rebased()
    print("mapped bytes:", len(rom._mem),
          "coverage:", rom.coverage(),
          "is_mapped(0x8000):", rom.is_mapped(0x8000))
    print("reset vector bytes:", " ".join(f"{rom.byte(i):02X}" for i in range(6)))

    board = CashRegisterBoard()
    probe = Probe(board)
    cpu = CPU8051(rom, board)
    cpu.pc = 0
    board.attach_cpu(cpu)

    pc_hist = collections.Counter()
    chunk = 50_000
    total = 4_000_000
    n = 0
    samples = []
    while n < total and not cpu.halted:
        cpu.run(chunk)
        n += chunk
        pc_hist[cpu.pc >> 8] += 1
        samples.append((cpu.cycles, cpu.pc, sfr_dump(cpu),
                        repr(board.display.text())))

    print("\n=== after", cpu.cycles, "cycles, ops", cpu.op_count,
          "halted", cpu.halted, "err", cpu.error, "missing", cpu.missing_pc)
    print("PC page histogram:", {f"{k:02X}": v for k, v in
                                 sorted(pc_hist.items())})
    print("\nlast samples (cycle, pc, sfr, display):")
    for s in samples[-6:]:
        print("  %9d %04X  %s  %s" % s)
    print("\nfirst samples:")
    for s in samples[:4]:
        print("  %9d %04X  %s  %s" % s)

    # ---- top PC addresses: need a finer trace -------------------------
    fine = collections.Counter()
    pc0 = cpu.pc
    for _ in range(300_000):
        if cpu.halted:
            break
        fine[cpu.pc] += 1
        cpu.step()
    print("\n=== hot PC addresses in a fresh 300k-instruction window:")
    for pc, c in fine.most_common(15):
        print("  %04X  %8d  %s" % (pc, c, disassemble_one(rom, pc)[0]))

    # ---- where are we stuck ------------------------------------------
    print("\n=== disasm around current PC %04X:" % cpu.pc)
    start = max(0, cpu.pc - 16)
    for addr, txt, size in disassemble(rom, cpu.pc, 16):
        mark = "<<" if addr == cpu.pc else ""
        print("  %04X: %-24s %s %s" % (addr,
                                       rom.get_slice(addr, size).hex(),
                                       txt, mark))

    print("\n=== SFR now:", sfr_dump(cpu))
    print("IE bits: EA=%d EX0=%d ET0=%d EX1=%d ET1=%d ES=%d" % (
        (cpu.sfr[0xA8] >> 7) & 1, (cpu.sfr[0xA8] >> 0) & 1,
        (cpu.sfr[0xA8] >> 1) & 1, (cpu.sfr[0xA8] >> 2) & 1,
        (cpu.sfr[0xA8] >> 3) & 1, (cpu.sfr[0xA8] >> 4) & 1))
    tcon = cpu.sfr[0x88]
    print("TCON: IT0=%d IE0=%d IT1=%d IE1=%d TR0=%d TF0=%d TR1=%d TF1=%d" % (
        tcon & 1, (tcon >> 1) & 1, (tcon >> 2) & 1, (tcon >> 3) & 1,
        (tcon >> 4) & 1, (tcon >> 5) & 1, (tcon >> 6) & 1, (tcon >> 7) & 1))

    print("\n=== display:", repr(board.display.text()))
    print("cells:", ["%02X" % board.display.cell_segments(i)
                     for i in range(board.display.columns)])
    print("grid:", board.display.grid)

    print("\n=== MOVX writes by page:",
          {f"{k:02X}": v for k, v in sorted(probe.wr_pages.items())})
    print("=== MOVX reads by page:",
          {f"{k:02X}": v for k, v in sorted(probe.rd_pages.items())})
    print("top written addrs:")
    for a, c in probe.wr.most_common(12):
        print("   %04X x%d first@cyc %d" % (a, c, probe.wr_first[a]))
    print("top read addrs:")
    for a, c in probe.rd.most_common(12):
        print("   %04X x%d first@cyc %d" % (a, c, probe.rd_first[a]))

    if mode == "trace":
        # Fresh run with instruction tracing: catch the moment PC first
        # reaches 0x1F60 and show how it got there.
        print("\n=== TRACE to first arrival at 1F60 ===")
        cpu.reset()
        board.reset()
        cpu.pc = 0
        cpu.trace = []
        cpu.trace_limit = 5_000_000
        while not cpu.halted and cpu.pc != 0x1F60:
            cpu.step()
            if cpu.trace is None:
                break
        tr = cpu.trace or []
        print("arrival at pc=%04X after %d cycles, trace len %d"
              % (cpu.pc, cpu.cycles, len(tr)))
        show = tr[-70:]
        for pc, op, acc, psw, sp, cyc in show:
            txt, size = disassemble_one(rom, pc)
            print("  cyc=%-8d pc=%04X op=%02X A=%02X PSW=%02X SP=%02X %s"
                  % (cyc, pc, op, acc, psw, sp, txt))
        # then observe: does it stay?
        cpu.trace = None
        start = cpu.cycles
        while cpu.cycles - start < 300_000 and not cpu.halted:
            cpu.step()
        print("after 300k more cycles: pc=%04X halted=%s" % (cpu.pc, cpu.halted))
        print("bits 0x20..0x27 (RAM):", " ".join(
            "%02X" % board.ram.get(0x20 + i, 0xFF) for i in range(8)))
        # bit-addressable RAM read through cpu.ram
        print("cpu.ram[20..2F]:", " ".join("%02X" % cpu.ram[0x20 + i]
                                           for i in range(0x10)))
        print("cpu.ram[40..5F]:", " ".join("%02X" % cpu.ram[0x40 + i]
                                           for i in range(0x20)))
        print("stack 60..66:", " ".join("%02X" % cpu.ram[0x60 + i]
                                        for i in range(7)))
        print("IE=%02X TCON=%02X" % (cpu.sfr[0xA8], cpu.sfr[0x88]))

    if mode == "fail":
        # Run until the self-test error entry 0x1F32, logging every MOVX
        # with the executing PC so we can see the failing compare.
        import collections as _c
        print("\n=== RUN TO SELF-TEST FAIL ENTRY 1F32 ===")
        cpu.reset()
        board.reset()
        cpu.pc = 0
        log = _c.deque(maxlen=400)
        r0, w0 = board.ext_read, board.ext_write

        def wr(addr, value):
            log.append(("W", cpu.pc, addr & 0xFFFF, value & 0xFF))
            return w0(addr, value)

        def rd(addr, code=False):
            v = r0(addr, code)
            log.append(("R", cpu.pc, addr & 0xFFFF, v))
            return v

        board.ext_read, board.ext_write = rd, wr
        try:
            while not cpu.halted and cpu.pc != 0x1F32 and cpu.cycles < 8_000_000:
                cpu.run(10_000)
        finally:
            board.ext_read, board.ext_write = r0, w0
        print("stopped pc=%04X halted=%s err=%s cycles=%d"
              % (cpu.pc, cpu.halted, cpu.error, cpu.cycles))
        print("--- last 80 MOVX ops (kind, PC, addr, value) ---")
        for row in list(log)[-80:]:
            print("   %s pc=%04X addr=%04X val=%02X" % row)
        # self-test registers at failure
        psw = cpu.sfr[0xD0]
        bank = (psw >> 3) & 3
        regs = [cpu.ram[bank * 8 + i] for i in range(8)]
        print("bank%d R0..R7 =" % bank, " ".join("%02X" % r for r in regs))
        print("A=%02X B=%02X DPTR=%04X PSW=%02X (C=%d) SP=%02X"
              % (cpu.sfr[0xE0], cpu.sfr[0xF0],
                 (cpu.sfr[0x83] << 8) | cpu.sfr[0x82], psw, (psw >> 7) & 1,
                 cpu.sfr[0x81]))
        print("IE=%02X TCON=%02X PPI=%s"
              % (cpu.sfr[0xA8], cpu.sfr[0x88], board.ppi.describe()))
        print("disp:", repr(board.display.text()))
        print("digitRAM50..5F:", " ".join("%02X" % cpu.ram[0x50 + i]
                                          for i in range(0x10)))
        # disassemble around failure arrival for context
        print("--- disasm around pc ---")
        for addr, txt, size in disassemble(rom, max(0, cpu.pc - 8), 12):
            print("   %04X: %-16s %s" % (addr, rom.get_slice(addr, size).hex(),
                                         txt))

    if mode == "keys":
        print("\n=== pressing keys ===")
        disp0 = board.display.text()
        for key in ("5", "СУММА", "ВВОД", "СБРОС"):
            board.keyboard.press(key)
            for _ in range(40):
                if cpu.halted:
                    break
                cpu.run(20_000)
            board.keyboard.release(key)
            for _ in range(20):
                if cpu.halted:
                    break
                cpu.run(20_000)
            print(" after %-8s disp=%r pc=%04X halted=%s rd0x91xx=%d "
                  "rd0x0Cxx=%d" % (
                      key, board.display.text(), cpu.pc, cpu.halted,
                      sum(v for a, v in probe.rd.items() if a >> 8 == 0x91),
                      sum(v for a, v in probe.rd.items()
                          if 0x0C80 <= a <= 0x0C9F)))
        print("disp0 was", repr(disp0))


if __name__ == "__main__":
    main()
