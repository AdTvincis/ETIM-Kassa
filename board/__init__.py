"""Emulated hardware of the AO "ETIM" cash register (AT89C55VD + 27C512).

Public entry point: :class:`board.cashboard.CashRegisterBoard`.
"""

from __future__ import annotations

from board.cashboard import WIRING, CashRegisterBoard
from board.display import Display
from board.keyboard import Keyboard
from board.ppi8255 import PPI8255
from board.printer import ReceiptPrinter

__all__ = [
    "CashRegisterBoard",
    "WIRING",
    "Display",
    "Keyboard",
    "PPI8255",
    "ReceiptPrinter",
]
