"""A small MCS-51 disassembler.

Used both for debugging the emulator and for reverse-engineering the cash
register firmware.  It covers the complete opcode map including the AT89C55
extended SFRs.
"""

from __future__ import annotations

from typing import Iterator, List, Optional, Tuple

__all__ = ["disassemble_one", "disassemble"]

_R = [f"R{i}" for i in range(8)]
_ALU_OP = {
    0x20: "ADD", 0x21: "ADD", 0x22: "ADD", 0x23: "ADD", 0x24: "ADD", 0x25: "ADD", 0x26: "ADD", 0x27: "ADD",
}
_AJMP_BIT = (0x01, 0x21, 0x41, 0x61, 0x81, 0xA1, 0xC1, 0xE1)
_ACALL_BIT = (0x11, 0x31, 0x51, 0x71, 0x91, 0xB1, 0xD1, 0xF1)

SFR_NAMES = {
    0x80: "P0", 0x81: "SP", 0x82: "DPL", 0x83: "DPH", 0x87: "PCON",
    0x88: "TCON", 0x89: "TMOD", 0x8A: "TL0", 0x8B: "TL1", 0x8C: "TH0", 0x8D: "TH1",
    0x90: "P1", 0x98: "SCON", 0x99: "SBUF", 0xA0: "P2", 0xA8: "IE", 0xB0: "P3",
    0xB8: "IP", 0xC8: "T2CON", 0xCA: "RCAP2L", 0xCB: "RCAP2H", 0xCC: "TL2", 0xCD: "TH2",
    0xD0: "PSW", 0xD8: "CCON", 0xD9: "CMOD", 0xDA: "CCAPM0", 0xDB: "CCAPM1",
    0xDC: "CCAPM2", 0xDD: "CCAPM3", 0xDE: "CCAPM4",
    0xE0: "ACC", 0xE9: "CL", 0xEA: "CCAP0L", 0xEB: "CCAP1L", 0xEC: "CCAP2L",
    0xED: "CCAP3L", 0xEE: "CCAP4L", 0xF0: "B", 0xF9: "CH",
    0xFA: "CCAP0H", 0xFB: "CCAP1H", 0xFC: "CCAP2H", 0xFD: "CCAP3H", 0xFE: "CCAP4H",
    0xA6: "WDTRST", 0xA7: "WDTPRG", 0x9A: "AUXR", 0x9B: "AUXR1",
}

BIT_NAMES = {
    # PSW
    0xD7: "CY", 0xD6: "AC", 0xD5: "F0", 0xD4: "RS1", 0xD3: "RS0", 0xD2: "OV", 0xD0: "P",
    # TCON
    0x8F: "TF1", 0x8E: "TR1", 0x8D: "TF0", 0x8C: "TR0", 0x8B: "IE1", 0x8A: "IT1",
    0x89: "IE0", 0x88: "IT0",
    # IE
    0xAF: "EA", 0xAE: "ET2", 0xAD: "ES", 0xAC: "ET1", 0xAB: "EX1", 0xAA: "ET0", 0xA9: "EX0",
    # SCON
    0x9F: "SM0", 0x9E: "SM1", 0x9D: "SM2", 0x9C: "REN", 0x9B: "TB8", 0x9A: "RB8", 0x99: "TI", 0x98: "RI",
    # IP
    0xBF: "PS", 0xBC: "PT1", 0xBB: "PX1", 0xBA: "PT0", 0xB9: "PX0",
}


def _dir(addr: int) -> str:
    if addr < 0x80:
        return f"{addr:02X}h"
    return SFR_NAMES.get(addr, f"{addr:02X}h")


def _bit(addr: int) -> str:
    if addr in BIT_NAMES:
        return BIT_NAMES[addr]
    if addr < 0x80:
        # 8051 bit addresses 0x00..0x7F map onto internal RAM bytes 0x20..0x2F:
        # bit address = (byte - 0x20) * 8 + n, i.e. byte = 0x20 + (addr >> 3).
        byte = 0x20 + (addr >> 3)
        return f"{byte:02X}h.{addr & 7}"
    base = addr & 0xF8
    return f"{SFR_NAMES.get(base, f'{base:02X}h')}.{addr & 7}"


def _imm(data: int) -> str:
    return f"#{data:02X}h"


def _rel(byte: int, addr_after: int) -> str:
    target = (addr_after + (byte - 256 if byte > 127 else byte)) & 0xFFFF
    return f"{target:04X}h"


def _bit_bits(addr: int) -> str:
    if addr < 0x80:
        return f"{addr:02X}h"
    return SFR_NAMES.get(addr, f"{addr:02X}h")


def disassemble_one(code, pc: int) -> Tuple[str, int]:
    """Return ``(text, length)`` for the instruction at ``pc``."""
    op = code[pc] & 0xFF
    b1 = code[(pc + 1) & 0xFFFF] & 0xFF
    b2 = code[(pc + 2) & 0xFFFF] & 0xFF

    if op == 0x00:
        return "NOP", 1
    if op == 0x02:
        return f"LJMP   {b1 << 8 | b2:04X}h", 3
    if op == 0x12:
        return f"LCALL  {b1 << 8 | b2:04X}h", 3
    if op == 0x22:
        return "RET", 1
    if op == 0x32:
        return "RETI", 1
    if op in _AJMP_BIT:
        target = ((pc + 2) & 0xF800) | ((op >> 5) << 8) | b1
        return f"AJMP   {target:04X}h", 2
    if op in _ACALL_BIT:
        target = ((pc + 2) & 0xF800) | ((op >> 5) << 8) | b1
        return f"ACALL  {target:04X}h", 2
    if op == 0x80:
        return f"SJMP   {_rel(b1, pc + 2)}", 2
    if op == 0x73:
        # JMP @A+DPTR - the only opcode of the MCS-51 table that used to fall
        # through to "DB" here (and was equally missing in m8051/cpu.py).
        return "JMP    @A+DPTR", 1
    if op == 0x03:
        return "RR     A", 1
    if op == 0x13:
        return "RRC    A", 1
    if op == 0x23:
        return "RL     A", 1
    if op == 0x33:
        return "RLC    A", 1
    if op == 0x04:
        return "INC    A", 1
    if op == 0x05:
        return f"INC    {_dir(b1)}", 2
    if op in (0x06, 0x07):
        return f"INC    @R{op & 1}", 1
    if 0x08 <= op <= 0x0F:
        return f"INC    {_R[op & 7]}", 1
    if op == 0x14:
        return "DEC    A", 1
    if op == 0x15:
        return f"DEC    {_dir(b1)}", 2
    if op in (0x16, 0x17):
        return f"DEC    @R{op & 1}", 1
    if 0x18 <= op <= 0x1F:
        return f"DEC    {_R[op & 7]}", 1
    if op == 0x24:
        return f"ADD    A,{_imm(b1)}", 2
    if op == 0x25:
        return f"ADD    A,{_dir(b1)}", 2
    if op in (0x26, 0x27):
        return f"ADD    A,@R{op & 1}", 1
    if 0x28 <= op <= 0x2F:
        return f"ADD    A,{_R[op & 7]}", 1
    if op == 0x34:
        return f"ADDC   A,{_imm(b1)}", 2
    if op == 0x35:
        return f"ADDC   A,{_dir(b1)}", 2
    if op in (0x36, 0x37):
        return f"ADDC   A,@R{op & 1}", 1
    if 0x38 <= op <= 0x3F:
        return f"ADDC   A,{_R[op & 7]}", 1
    if op == 0x44:
        return f"ORL    A,{_imm(b1)}", 2
    if op == 0x45:
        return f"ORL    A,{_dir(b1)}", 2
    if op in (0x46, 0x47):
        return f"ORL    A,@R{op & 1}", 1
    if 0x48 <= op <= 0x4F:
        return f"ORL    A,{_R[op & 7]}", 1
    if op == 0x42:
        return f"ORL    {_dir(b1)},A", 2
    if op == 0x43:
        return f"ORL    {_dir(b1)},{_imm(b2)}", 3
    if op == 0x54:
        return f"ANL    A,{_imm(b1)}", 2
    if op == 0x55:
        return f"ANL    A,{_dir(b1)}", 2
    if op in (0x56, 0x57):
        return f"ANL    A,@R{op & 1}", 1
    if 0x58 <= op <= 0x5F:
        return f"ANL    A,{_R[op & 7]}", 1
    if op == 0x52:
        return f"ANL    {_dir(b1)},A", 2
    if op == 0x53:
        return f"ANL    {_dir(b1)},{_imm(b2)}", 3
    if op == 0x64:
        return f"XRL    A,{_imm(b1)}", 2
    if op == 0x65:
        return f"XRL    A,{_dir(b1)}", 2
    if op in (0x66, 0x67):
        return f"XRL    A,@R{op & 1}", 1
    if 0x68 <= op <= 0x6F:
        return f"XRL    A,{_R[op & 7]}", 1
    if op == 0x62:
        return f"XRL    {_dir(b1)},A", 2
    if op == 0x63:
        return f"XRL    {_dir(b1)},{_imm(b2)}", 3
    if op == 0x74:
        return f"MOV    A,{_imm(b1)}", 2
    if op == 0x75:
        return f"MOV    {_dir(b1)},{_imm(b2)}", 3
    if op in (0x76, 0x77):
        return f"MOV    @R{op & 1},{_imm(b1)}", 2
    if 0x78 <= op <= 0x7F:
        return f"MOV    {_R[op & 7]},{_imm(b1)}", 2
    if op == 0x85:
        return f"MOV    {_dir(b2)},{_dir(b1)}", 3
    if op in (0x86, 0x87):
        return f"MOV    {_dir(b1)},@R{op & 1}", 2
    if 0x88 <= op <= 0x8F:
        return f"MOV    {_dir(b1)},{_R[op & 7]}", 2
    if op == 0x90:
        # The '#' is not decoration: tools/asm51.py only matches an
        # immediate operand in the IMM kind, so dropping it made
        # "MOV DPTR,1234h" impossible to assemble back (round-trip break).
        return f"MOV    DPTR,{_imm(b1 << 8 | b2)}", 3
    if op == 0x93:
        return "MOVC   A,@A+DPTR", 1
    if op == 0x83:
        return "MOVC   A,@A+PC", 1
    if op in (0x96, 0x97):
        return f"SUBB   A,@R{op & 1}", 1
    if 0x98 <= op <= 0x9F:
        return f"SUBB   A,{_R[op & 7]}", 1
    if op == 0x94:
        return f"SUBB   A,{_imm(b1)}", 2
    if op == 0x95:
        return f"SUBB   A,{_dir(b1)}", 2
    if op == 0xA3:
        return "INC    DPTR", 1
    if op == 0xA4:
        return "MUL    AB", 1
    if op == 0x84:
        return "DIV    AB", 1
    if op == 0xA5:
        return "DB     0A5h   ; reserved", 1
    if op in (0xA6, 0xA7):
        return f"MOV    @R{op & 1},{_dir(b1)}", 2
    if 0xA8 <= op <= 0xAF:
        return f"MOV    {_R[op & 7]},{_dir(b1)}", 2
    if op == 0xC0:
        return f"PUSH   {_dir(b1)}", 2
    if op == 0xD0:
        return f"POP    {_dir(b1)}", 2
    if op == 0xC4:
        return "SWAP   A", 1
    if op == 0xC5:
        return f"XCH    A,{_dir(b1)}", 2
    if op in (0xC6, 0xC7):
        return f"XCH    A,@R{op & 1}", 1
    if 0xC8 <= op <= 0xCF:
        return f"XCH    A,{_R[op & 7]}", 1
    if op == 0xD4:
        return "DA     A", 1
    if op in (0xD6, 0xD7):
        return f"XCHD   A,@R{op & 1}", 1
    if op == 0xE0:
        return "MOVX   A,@DPTR", 1
    if op == 0xF0:
        return "MOVX   @DPTR,A", 1
    if op in (0xE2, 0xE3):
        return f"MOVX   A,@R{op & 1}", 1
    if op in (0xF2, 0xF3):
        return f"MOVX   @R{op & 1},A", 1
    if op == 0xE4:
        return "CLR    A", 1
    if op == 0xF4:
        return "CPL    A", 1
    if op in (0xE6, 0xE7):
        return f"MOV    A,@R{op & 1}", 1
    if op in (0xF6, 0xF7):
        return f"MOV    @R{op & 1},A", 1
    if 0xE8 <= op <= 0xEF:
        return f"MOV    A,{_R[op & 7]}", 1
    if 0xF8 <= op <= 0xFF:
        return f"MOV    {_R[op & 7]},A", 1
    if op == 0xE5:
        return f"MOV    A,{_dir(b1)}", 2
    if op == 0xF5:
        return f"MOV    {_dir(b1)},A", 2
    # bit / branch group
    if op == 0xC2:
        return f"CLR    {_bit(b1)}", 2
    if op == 0xD2:
        return f"SETB   {_bit(b1)}", 2
    if op == 0xB2:
        return f"CPL    {_bit(b1)}", 2
    if op == 0xC3:
        return "CLR    C", 1
    if op == 0xD3:
        return "SETB   C", 1
    if op == 0xB3:
        return "CPL    C", 1
    if op == 0x72:
        return f"ORL    C,{_bit(b1)}", 2
    if op == 0xA0:
        return f"ORL    C,/{_bit(b1)}", 2
    if op == 0x82:
        return f"ANL    C,{_bit(b1)}", 2
    if op == 0xB0:
        return f"ANL    C,/{_bit(b1)}", 2
    if op == 0xA2:
        return f"MOV    C,{_bit(b1)}", 2
    if op == 0x92:
        return f"MOV    {_bit(b1)},C", 2
    if op == 0x10:
        return f"JBC    {_bit(b1)},{_rel(b2, pc + 3)}", 3
    if op == 0x20:
        return f"JB     {_bit(b1)},{_rel(b2, pc + 3)}", 3
    if op == 0x30:
        return f"JNB    {_bit(b1)},{_rel(b2, pc + 3)}", 3
    if op == 0x40:
        return f"JC     {_rel(b1, pc + 2)}", 2
    if op == 0x50:
        return f"JNC    {_rel(b1, pc + 2)}", 2
    if op == 0x60:
        return f"JZ     {_rel(b1, pc + 2)}", 2
    if op == 0x70:
        return f"JNZ    {_rel(b1, pc + 2)}", 2
    if op == 0xB4:
        return f"CJNE   A,{_imm(b1)},{_rel(b2, pc + 3)}", 3
    if op == 0xB5:
        return f"CJNE   A,{_dir(b1)},{_rel(b2, pc + 3)}", 3
    if op in (0xB6, 0xB7):
        return f"CJNE   @R{op & 1},{_imm(b1)},{_rel(b2, pc + 3)}", 3
    if 0xB8 <= op <= 0xBF:
        return f"CJNE   {_R[op & 7]},{_imm(b1)},{_rel(b2, pc + 3)}", 3
    if op == 0xD5:
        return f"DJNZ   {_dir(b1)},{_rel(b2, pc + 3)}", 3
    if 0xD8 <= op <= 0xDF:
        return f"DJNZ   {_R[op & 7]},{_rel(b1, pc + 2)}", 2
    return f"DB     0{op:02X}h", 1


def disassemble(code, start: int, count: int, base: int = 0) -> List[Tuple[int, str, int]]:
    """Disassemble ``count`` instructions from ``start``.

    Returns a list of ``(address, text, length)``.
    """
    out = []
    pc = start
    for _ in range(count):
        text, length = disassemble_one(code, pc)
        out.append((pc, text, length))
        pc = (pc + length) & 0xFFFF
    return out


def walk(code, start: int, stop: int, limit: int = 100000) -> Iterator[Tuple[int, str, int]]:
    """Linear sweep between two addresses."""
    pc = start
    produced = 0
    while pc < stop and produced < limit:
        text, length = disassemble_one(code, pc)
        yield pc, text, length
        pc += length
        produced += 1
