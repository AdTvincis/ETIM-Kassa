"""Intel 8255 (KR580VV55) programmable peripheral interface.

The emulation is deliberately *honest* rather than a register bank with a mode
byte: the control word is decoded into group A / group B mode and direction
bits, ports keep separate output latches and input pins (quasi-bidirectional
behaviour), and the mode 1/2 handshake bits (/OBF, /ACK, /IBF, /STB, /INTR)
are modelled as real flags that a device on the other side can drive.

References
----------
* control word (D7 = 1)::

      D7 1
      D6 D5  group A mode   00 = 0, 01 = 1, 1x = 2
      D4     port A          1 = input, 0 = output
      D3     port C upper    1 = input, 0 = output (mode 0)
      D2     group B mode    0 = 0, 1 = 1
      D1     port B          1 = input, 0 = output
      D0     port C lower    1 = input, 0 = output (mode 0)

* bit set/reset word (D7 = 0): D3..D1 select a PC bit, D0 = 1 set / 0 reset.
* after RESET all ports are inputs and the control register reads 0x9B-ish;
  we model "all input, mode 0", which is what firmware-writing code expects.

Nothing here knows about cash registers; :mod:`board.cashboard` wires it up.
"""

from __future__ import annotations

from typing import Callable, List, Optional

__all__ = [
    "PPI8255",
    "MODE_0",
    "MODE_1",
    "MODE_2",
    "PORT_A",
    "PORT_B",
    "PORT_C",
    "CTRL",
]

PORT_A, PORT_B, PORT_C, CTRL = 0, 1, 2, 3
MODE_0, MODE_1, MODE_2 = 0, 1, 2

# PC bit roles in the mode 1 / mode 2 handshakes (active low unless noted).
PC0_INTR_B = 0x01
PC1_OBF_B = 0x02
PC2_STB_B_ACK_B = 0x04
PC3_INTR_A = 0x08
PC4_STB_A = 0x10
PC5_IBF_A = 0x20
PC6_ACK_A = 0x40
PC7_OBF_A = 0x80


class PPI8255:
    """A single 8255.  Register addresses are handled by the board."""

    def __init__(self, name: str = "ppi") -> None:
        self.name = name
        self.reset()

    # ------------------------------------------------------------------ reset
    def reset(self) -> None:
        # Reset: every port is an input in mode 0, latches float high.
        self.mode_a = MODE_0
        self.mode_b = MODE_0
        self.control = 0x9B          # mode-set word: all ports input
        self._mode_set = True
        self.latch: List[int] = [0xFF, 0xFF, 0xFF]
        self.pins: List[int] = [0xFF, 0xFF, 0xFF]
        self.ddr: List[int] = [0xFF, 0xFF, 0xFF]      # 1 = input
        # handshake flags (True = asserted HIGH on the pin; /OBF etc. are
        # stored as their *electrical* level, so idle = 1)
        self.obf_a = 1
        self.ack_a = 1
        self.ibf_a = 0
        self.stb_a = 1
        self.intr_a = 0
        self.obf_b = 1
        self.ack_b = 1
        self.ibf_b = 0
        self.stb_b = 1
        self.intr_b = 0
        self.inte_a = 0              # interrupt enable (PC4/PC2 in mode 1)
        self.inte_b = 0
        self.last_write: Optional[int] = None
        self.write_count = 0
        self.read_count = 0
        # Callbacks the board can hook (byte handed over in mode 1/2 etc.)
        self.on_output: Optional[Callable[[int, int], None]] = None

    # ------------------------------------------------------------- directions
    def _decode_control(self, value: int) -> None:
        self.control = value
        self._mode_set = bool(value & 0x80)
        self.mode_a = (value >> 5) & 0x03
        self.mode_b = (value >> 2) & 0x01

        ddr_a = 0xFF if (value & 0x10) else 0x00
        ddr_b = 0xFF if (value & 0x02) else 0x00

        if self.mode_a == MODE_0:
            ddr_c = (0xFF if (value & 0x08) else 0x00) | (0xFF if (value & 0x01) else 0x00)
        elif self.mode_a == MODE_1:
            if value & 0x10:                     # port A input (strobed)
                ddr_c = PC4_STB_A | PC5_IBF_A | PC3_INTR_A
                ddr_c |= (0xFF if (value & 0x08) else 0x00) & (PC6_ACK_A | PC7_OBF_A)
            else:                                # port A output (strobed)
                ddr_c = PC6_ACK_A | PC7_OBF_A | PC3_INTR_A
                ddr_c |= (0xFF if (value & 0x08) else 0x00) & (PC4_STB_A | PC5_IBF_A)
        else:                                    # mode 2, port A bidirectional
            ddr_c = PC7_OBF_A | PC6_ACK_A | PC5_IBF_A | PC4_STB_A | PC3_INTR_A
        if self.mode_b == MODE_1:
            ddr_c |= PC0_INTR_B | PC1_OBF_B | PC2_STB_B_ACK_B
        else:
            ddr_c |= (0xFF if (value & 0x01) else 0x00) & 0x0F
        self.ddr = [ddr_a, ddr_b, ddr_c]

        # a fresh mode word clears the handshake outputs
        self.obf_a = 1
        self.obf_b = 1
        self.intr_a = 0
        self.intr_b = 0
        self.ibf_a = 0
        self.ibf_b = 0
        # ...and returns the INTE flip-flops to 0: after (re)programming the
        # chip the firmware must re-arm group A/B interrupts with a BSR word
        # (PC4 / PC2) before an INTR line can fire again.
        self.inte_a = 0
        self.inte_b = 0

    def write_control(self, value: int) -> None:
        value &= 0xFF
        if value & 0x80:
            self._decode_control(value)
            return
        # bit set/reset: only meaningful for port C output bits
        self.control = value
        self._mode_set = True
        bit = (value >> 1) & 0x07
        mask = 1 << bit
        if value & 0x01:
            self.latch[PORT_C] |= mask
        else:
            self.latch[PORT_C] &= ~mask & 0xFF
        # In modes 1/2 PC4 (group A) and PC2 (group B) are not port C pins
        # but the interrupt-enable flip-flops: BSR set/reset arms INTR.
        if bit == 4 and self.mode_a in (MODE_1, MODE_2):
            self.inte_a = 1 if (value & 0x01) else 0
        if bit == 2 and self.mode_b == MODE_1:
            self.inte_b = 1 if (value & 0x01) else 0

    def read_control(self) -> int:
        # Reading the control register returns the last mode word with the
        # mode-set flag; genuine 8255 silicon returns 0x9B-style status.
        return (self.control & 0x7F) | 0x80

    # ------------------------------------------------------------------ ports
    def set_pins(self, port: int, value: int) -> None:
        """Levels driven onto the port by the outside world."""
        self.pins[port] = value & 0xFF

    def latch_value(self, port: int) -> int:
        return self.latch[port]

    def read(self, port: int) -> int:
        self.read_count += 1
        if port == CTRL:
            return self.read_control()
        if port == PORT_C and (self.mode_a in (MODE_1, MODE_2) or self.mode_b == MODE_1):
            return self._read_status_c()
        mask = self.ddr[port]
        # input bits come from the pins, output bits from the latch
        return ((self.pins[port] & mask) | (self.latch[port] & ~mask)) & 0xFF

    def write(self, port: int, value: int) -> None:
        value &= 0xFF
        if port == CTRL:
            self.write_control(value)
            return
        self.write_count += 1
        self.last_write = value
        if port == PORT_C:
            # output bits take the value; input bits stay released (high)
            out = ~self.ddr[PORT_C] & 0xFF
            self.latch[PORT_C] = ((value & out) | (self.latch[PORT_C] & ~out)) & 0xFF
            self._bsr_side_effects(value)
            if self.on_output:
                self.on_output(PORT_C, value)
            return
        # Keep 1s in bits that are inputs: that is what makes a written latch
        # readable back through the weak pull-up.
        self.latch[port] = ((value & ~self.ddr[port]) | (self.latch[port] & self.ddr[port])) & 0xFF
        if port == PORT_A:
            if self.mode_a == MODE_1 and not (self.ddr[PORT_A] & 0xFF):
                self.obf_a = 0                      # data available
                self.intr_a = self.inte_a
            elif self.mode_a == MODE_2:
                self.obf_a = 0
                self.intr_a = self.inte_a
        elif port == PORT_B:
            if self.mode_b == MODE_1:
                self.obf_b = 0
                self.intr_b = self.inte_b
        if self.on_output:
            self.on_output(port, value)

    def _bsr_side_effects(self, value: int) -> None:
        """PC as a handshake line: /STB, /ACK or INTE, depending on mode."""
        for bit in range(8):
            level = (value >> bit) & 1
            if self.mode_a == MODE_1 and not (self.ddr[PORT_A] & 0xFF):
                # output mode: PC6 = /ACK (input), PC7 = /OBF (output)
                if bit == 6 and level == 0:         # /ACK asserted
                    self.ack_a = 0
                    self.obf_a = 1
                    self.intr_a = 1
                elif bit == 6 and level == 1:
                    self.ack_a = 1
            if self.mode_b == MODE_1 and not (self.ddr[PORT_B] & 0xFF):
                if bit == 2 and level == 0:
                    self.ack_b = 0
                    self.obf_b = 1
                    self.intr_b = 1
                elif bit == 2 and level == 1:
                    self.ack_b = 1

    # -------------------------------------------------------------- handshake
    def _read_status_c(self) -> int:
        """Port C read in mode 1/2 is the status byte, not the latch.

        Group A mode 1 exposes the interrupt-enable flip-flop at PC4, so the
        firmware can read back what its BSR word armed; mode 2 shows the whole
        bidirectional handshake (PC7..PC3: /OBF /ACK IBF /STB INTR).
        """
        if self.mode_a == MODE_2:
            return ((self.obf_a & 1) << 7) | ((self.ack_a & 1) << 6) \
                | ((self.ibf_a & 1) << 5) | ((self.stb_a & 1) << 4) \
                | ((self.intr_a & 1) << 3)
        if self.mode_a == MODE_1:
            if not (self.ddr[PORT_A] & 0xFF):        # port A output
                return ((self.obf_a & 1) << 7) | ((self.ack_a & 1) << 6) \
                    | ((self.inte_a & 1) << 4) | ((self.intr_a & 1) << 3)
            return ((self.stb_a & 1) << 4) | ((self.ibf_a & 1) << 5) | ((self.intr_a & 1) << 3)
        if self.mode_b == MODE_1:
            return ((self.obf_b & 1) << 1) | ((self.ack_b & 1) << 2) | ((self.intr_b & 1) << 0)
        return self.latch[PORT_C]

    def notify_ack(self, port: int = PORT_A) -> None:
        """The external device pulsed /ACK: latch is free again."""
        if port == PORT_A:
            self.ack_a = 0
            self.obf_a = 1
            self.intr_a = 1
        else:
            self.ack_b = 0
            self.obf_b = 1
            self.intr_b = 1

    def notify_stb(self, port: int = PORT_A, value: int = 0) -> None:
        """The external device pulsed /STB and placed ``value`` on the pins."""
        self.set_pins(port, value)
        if port == PORT_A:
            self.stb_a = 0
            self.ibf_a = 1
            self.intr_a = 1
        else:
            self.stb_b = 0
            self.ibf_b = 1
            self.intr_b = 1

    def clear_intr(self, port: int = PORT_A) -> None:
        if port == PORT_A:
            self.intr_a = 0
        else:
            self.intr_b = 0

    def interrupt(self) -> bool:
        """True when a group A or group B INTR line is asserted."""
        return bool(self.intr_a or self.intr_b)

    # ------------------------------------------------------------ diagnostics
    def describe(self) -> str:
        return (f"8255 {self.name}: ctrl=0x{self.control:02X} "
                f"A={'in' if self.ddr[0] else 'out'} "
                f"B={'in' if self.ddr[1] else 'out'} "
                f"C=0x{self.ddr[2]:02X}")

    def __repr__(self) -> str:      # pragma: no cover - debugging aid
        return (f"PPI8255(mode_a={self.mode_a}, mode_b={self.mode_b}, "
                f"ctrl=0x{self.control:02X}, latch={self.latch})")
